/* asset_splits.c -- reassemble Unity's chunked SerializedFiles on the console.
 *
 * Unity splits large SerializedFiles into 1 MB parts named "<name>.split0",
 * "<name>.split1", ... and relies on an engine-side VFS ("AndroidSplitFile" is a
 * literal in libunity) to stitch them back at read time. That path is bound up
 * with reading assets out of a real APK through the Java AssetManager, which is
 * not how this port serves data -- we hand the engine plain files on the SD
 * card. So we join them ourselves, once, at boot.
 *
 * Nothing below is hardcoded to any file list -- any "<name>.splitN" chain
 * found in assets/bin/Data is joined. (AotA's own extraction shows no
 * .splitN parts; the pass then simply finds nothing and returns.) check_data()
 * in main.c reports a missing stem that still has a .split0 beside it as
 * "not assembled" rather than "missing", precisely
 * because of this.
 *
 * Unlike that reference port, this title is NOT an Android App Bundle and has no
 * Play Asset Delivery pack: assets/ comes out of a single APK in one piece, so
 * there is nothing for the user to merge. The splits are Unity's own file
 * chunking, present in the base APK.
 *
 * Safety properties:
 *   - Idempotent. Subsequent boots find the joined file, verify its size, and
 *     do nothing. Cost is one readdir.
 *   - Never publishes a truncated file. Output goes to "<name>.part", which is
 *     only renamed into place after the byte count matches the sum of the parts
 *     AND (when the result is a recognisable SerializedFile) the size the file's
 *     own header declares.
 *   - Only deletes the .splitN parts after that verification passes, so an
 *     interrupted run leaves the inputs intact and simply retries next boot. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>

#include "config.h"   /* DATA_ROOT */
#include "util.h"     /* debugPrintf */
#include "error.h"    /* startup_status_update */

#define DATA_SUBDIR "assets/bin/Data"
#define STEM_MAX    256     /* longest "<name>" we track (excl. the .splitN)    */
#define MAX_PARTS   4096    /* parts per chain (1 MB each -> 4 GB ceiling)      */
#define COPY_BUF    (128 * 1024)
#define PATHMAX     1024

static uint8_t g_copy_buf[COPY_BUF];

/* Return the stem length if `fn` looks like "<stem>.split<digits>", else 0. */
static size_t split_stem_len(const char *fn, long *idx_out) {
    const char *p = NULL, *q = fn;
    while ((q = strstr(q, ".split")) != NULL) { p = q; q += 6; }
    if (!p) return 0;
    const char *d = p + 6;
    if (!*d) return 0;
    for (const char *c = d; *c; c++)
        if (!isdigit((unsigned char)*c)) return 0;
    *idx_out = strtol(d, NULL, 10);
    return (size_t)(p - fn);
}

static long file_size_of(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    return (long)st.st_size;
}

/* Unity SerializedFile: if this parses as version >= 22, return the file size
 * the header declares; otherwise -1 (not a SerializedFile, or too old to check).
 * Layout is big-endian: u32 legacy fields, u32 version at +8, then for v22+ a
 * u32 metadata_size at +20 and a u64 file_size at +24. */
static long declared_serialized_size(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t h[32];
    size_t n = fread(h, 1, sizeof h, f);
    fclose(f);
    if (n < sizeof h) return -1;

    uint32_t ver = ((uint32_t)h[8] << 24) | ((uint32_t)h[9] << 16) |
                   ((uint32_t)h[10] << 8) | (uint32_t)h[11];
    if (ver < 22 || ver > 64) return -1;

    uint64_t fsz = 0;
    for (int i = 24; i < 32; i++) fsz = (fsz << 8) | h[i];
    if (fsz == 0 || fsz > (uint64_t)1 << 40) return -1;
    return (long)fsz;
}

/* Build "<dir>/<stem><suffix>"; returns 0 if it would not fit. */
static int mkpath(char *out, const char *dir, const char *stem, const char *suffix) {
    size_t dl = strlen(dir), sl = strlen(stem), xl = strlen(suffix);
    if (dl + 1 + sl + xl + 1 > PATHMAX) return 0;
    memcpy(out, dir, dl);
    out[dl] = '/';
    memcpy(out + dl + 1, stem, sl);
    memcpy(out + dl + 1 + sl, suffix, xl);
    out[dl + 1 + sl + xl] = '\0';
    return 1;
}

static int mkpart(char *out, const char *dir, const char *stem, int idx) {
    char suffix[24];
    snprintf(suffix, sizeof suffix, ".split%d", idx);
    return mkpath(out, dir, stem, suffix);
}

/* Join one chain. Returns 1 if the file is present and correct afterwards. */
static int join_one(const char *dir, const char *stem) {
    char target[PATHMAX], part[PATHMAX], tmp[PATHMAX];
    if (!mkpath(target, dir, stem, "")) {
        debugPrintf("[split] %s: path too long\n", stem);
        return 0;
    }

    /* Walk the chain from 0 and total it up. */
    int  nparts = 0;
    long total = 0;
    for (; nparts < MAX_PARTS; nparts++) {
        if (!mkpart(part, dir, stem, nparts)) break;
        long sz = file_size_of(part);
        if (sz < 0) break;
        total += sz;
    }

    long have = file_size_of(target);

    if (nparts == 0) {
        /* No parts left: either already joined, or nothing to do. */
        return have >= 0;
    }

    /* Already joined on a previous boot but the parts survived (interrupted
     * cleanup). Verify, then finish the cleanup. */
    if (have == total) {
        for (int i = 0; i < nparts; i++)
            if (mkpart(part, dir, stem, i)) unlink(part);
        debugPrintf("[split] %s already joined (%ld bytes); removed %d leftover part(s)\n",
                    stem, total, nparts);
        return 1;
    }

    if (have >= 0 && have != total)
        debugPrintf("[split] %s exists at %ld bytes but parts total %ld -- rebuilding\n",
                    stem, have, total);

    if (!mkpath(tmp, dir, stem, ".part")) {
        debugPrintf("[split] %s: path too long\n", stem);
        return 0;
    }
    unlink(tmp);

    FILE *out = fopen(tmp, "wb");
    if (!out) {
        debugPrintf("[split] %s: cannot create %s (SD full or read-only?)\n", stem, tmp);
        return 0;
    }

    long written = 0;
    int  ok = 1;
    for (int i = 0; i < nparts && ok; i++) {
        if (!mkpart(part, dir, stem, i)) { ok = 0; break; }
        FILE *in = fopen(part, "rb");
        if (!in) { ok = 0; break; }
        for (;;) {
            size_t got = fread(g_copy_buf, 1, sizeof g_copy_buf, in);
            if (got == 0) break;
            if (fwrite(g_copy_buf, 1, got, out) != got) { ok = 0; break; }
            written += (long)got;
        }
        fclose(in);
    }
    if (fclose(out) != 0) ok = 0;

    if (!ok || written != total) {
        debugPrintf("[split] %s: JOIN FAILED (wrote %ld of %ld) -- parts left intact\n",
                    stem, written, total);
        unlink(tmp);
        return 0;
    }

    /* The file's own header is a second opinion on whether the chain was
     * complete and in the right order. */
    long declared = declared_serialized_size(tmp);
    if (declared > 0 && declared != written) {
        debugPrintf("[split] %s: header declares %ld bytes but joined %ld -- "
                    "chain incomplete or out of order; parts left intact\n",
                    stem, declared, written);
        unlink(tmp);
        return 0;
    }

    unlink(target);
    if (rename(tmp, target) != 0) {
        debugPrintf("[split] %s: rename failed; parts left intact\n", stem);
        unlink(tmp);
        return 0;
    }

    for (int i = 0; i < nparts; i++)
        if (mkpart(part, dir, stem, i)) unlink(part);

    debugPrintf("[split] joined %-32s %d parts -> %ld bytes%s\n",
                stem, nparts, written,
                declared > 0 ? " (header size matches)" : "");
    return 1;
}

/* Scan assets/bin/Data for "<name>.splitN" families and join each one.
 * Returns the number of chains joined this boot (0 is the normal steady state).
 * Safe to call every boot; call it before anything opens the data. */
int nx_join_asset_splits(void) {
    const char *dir = game_path(DATA_SUBDIR);

    DIR *d = opendir(dir);
    if (!d) {
        debugPrintf("[split] cannot open %s -- assets not installed?\n", dir);
        return 0;
    }

    /* The chain list grows on the heap. It used to be a fixed char[16][256] on
     * the stack, which was ample for Deus Ex GO's TWO chains but silently
     * dropped the rest here: The Room Three 1.18.1 ships 166 chains / 674 parts
     * (573 MB). Anything past the cap stayed as .splitN parts, so the engine
     * would later ask for e.g. bin/Data/level78 and find nothing.
     *
     * A bigger constant would just move the cliff, and 166 * 256 B is also more
     * stack than a Switch thread wants to spend. Grow instead -- there is no
     * cap now, and the failure mode is a clean OOM rather than missing assets. */
    char (*stems)[STEM_MAX] = NULL;
    int  nstems = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        long idx;
        size_t sl = split_stem_len(de->d_name, &idx);
        if (!sl || sl >= STEM_MAX) continue;
        char stem[STEM_MAX];
        memcpy(stem, de->d_name, sl);
        stem[sl] = '\0';
        int seen = 0;
        for (int i = 0; i < nstems; i++)
            if (!strcmp(stems[i], stem)) { seen = 1; break; }
        if (seen) continue;
        if (nstems == cap) {
            int ncap = cap ? cap * 2 : 32;
            void *grown = realloc(stems, (size_t)ncap * STEM_MAX);
            if (!grown) {
                debugPrintf("[split] out of memory tracking chains at %d; "
                            "joining what we have\n", nstems);
                break;
            }
            stems = grown;
            cap = ncap;
        }
        strcpy(stems[nstems++], stem);
    }
    closedir(d);

    if (nstems == 0) { free(stems); return 0; }

    debugPrintf("[split] %d chunked file(s) to join; this happens once\n", nstems);
    int joined = 0;
    for (int i = 0; i < nstems; i++) {
        if (join_one(dir, stems[i])) joined++;
        /* 166 chains is a long silent stretch on the first boot -- keep the
         * on-screen status moving so it does not look hung. */
        if ((i & 7) == 0 || i == nstems - 1) {
            char status[96];
            snprintf(status, sizeof status,
                     "Joining chunked assets\n\n  %d / %d", i + 1, nstems);
            startup_status_update(status);
        }
    }

    if (joined != nstems)
        debugPrintf("[split] WARNING: %d of %d chains could not be joined\n",
                    nstems - joined, nstems);
    free(stems);
    return joined;
}
