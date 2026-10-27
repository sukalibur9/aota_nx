/* gpu_arena.c -- heap wrappers: a dedicated GPU arena, plus a free() guard.
 *
 * THIS FILE IS LOAD-BEARING. It is not diagnostics.
 *
 * libdrm_nouveau backs EVERY GPU buffer with memalign(0x1000, size) before
 * nvMapCreate/nvAddressSpaceMap. Those allocations are large (up to ~22MB),
 * page-aligned, and churned constantly, so serving them from newlib's general
 * heap shreds it: once fragmented, a 21MB CONTIGUOUS page-aligned run cannot be
 * placed even with a gigabyte free in aggregate. memalign then returns NULL ->
 * nouveau_bo_new fails -> texStorage reports GL_OUT_OF_MEMORY -> incomplete FBO
 * -> BLACK SCREEN.
 *
 * So we reserve one big contiguous region ONCE at first use, before the heap has
 * been churned, and hand GPU buffers out of it with a page bitmap. They can
 * never fragment newlib and newlib can never fragment them. Anything that is not
 * a large page-aligned request falls straight through to newlib.
 *
 * The Makefile's -Wl,--wrap flags are what route allocations here, including
 * mesa's own internal ones. THE WRAP LIST AND THE FUNCTIONS BELOW MUST AGREE:
 * a --wrap with no __wrap_ function is an undefined-reference link error from
 * libEGL.a, and a __wrap_ function with no --wrap is silently dead code. If you
 * add or remove one, do both.
 *
 * Carried over from the reference port essentially unchanged -- this is engine-
 * and driver-level behaviour, not title-specific. The canary machinery it also
 * contained is left in but DISABLED (see CANARY_ENABLE): it was built to hunt a
 * corruption that turned out to be a nouveau_mm_allocate bug, since fixed, and
 * its +8-byte tail sat directly in the GPU allocation path. Re-arm it only if a
 * real heap corruption shows up.
 *
 * MIT.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>      /* memset (canary calloc) */
#include <malloc.h>      /* malloc_usable_size (free quarantine) */
#include <stdio.h>       /* snprintf (quarantine report) */
#include <math.h>
#include <switch.h>      /* Mutex/Thread/svcSleepThread (canary sweeper) */
#include "so_util.h"
#include "config.h"
#include "util.h"        /* debugPrintf */


/* ---- heap-corruption guard (save-load asset processing) --------------------
 * A crash on UnityMain inside _free_r showed free() handed 0x3d636c1c3d1fcf53 --
 * packed float RGBA data, not a heap pointer. An object's pointer field had been
 * overwritten by asset/texture float data (a buffer overrun during save load),
 * and freeing that garbage faulted. We can't yet localize the overrun, but we can
 * keep it from being fatal: with -Wl,--wrap,free in the Makefile, EVERY free()
 * call routes here first -- libunity/il2cpp frees (via the &free import table
 * entry, which --wrap redirects to __wrap_free) AND mesa's own internal frees.
 * A real malloc() result is 8-byte aligned and inside the 39-bit user address
 * space; a smashed pointer is neither, so we skip it (leaking the block) and log
 * instead of crashing in _free_r. Fast integer checks only -- no syscall on the
 * hot path, which matters because asset load frees heavily. If a subtler
 * corruption (aligned + in-range but non-heap) ever slips through, add an
 * svcQueryMemory readability tier here. */
extern void __real_free(void *p);
extern int oc_ptr_is_oc(void *addr);   /* libc_shim.c: OC reserve window test (build #157) */

/* ---- heap overrun hunter (canaries) ----------------------------------------
 * The free-guard above proved a heap buffer overrun exists (pointer fields
 * smashed with float RGBA during asset processing); it has now graduated to
 * smashing mesa's GL buffer bookkeeping -> the recurring glBufferData faults
 * at round/garbage destinations. Catch the overrunner: every allocation gets
 * an 8-byte tail canary (size+8 alloc, XOR-keyed to the pointer) tracked in a
 * lossy side table; a sweeper thread checks live canaries every 2s and
 * __wrap_free checks at free. On a smash we log the block size and the first
 * 32 bytes written PAST the block -- the content names the writer.
 * The side table is alignment-neutral (no headers), so memalign semantics are
 * preserved; collisions just evict tracking (lossy is fine for hunting). */
extern void *__real_malloc(size_t sz);
extern void *__real_memalign(size_t al, size_t sz);
extern void *__real_calloc(size_t n, size_t s);
extern void *__real_realloc(void *p, size_t sz);

#define CAN_TAB_BITS 16
#define CAN_TAB_N    (1u << CAN_TAB_BITS)
#define CAN_KEY      0xC0DEC0DE5EED5EEDULL
typedef struct { uintptr_t p; size_t sz; uintptr_t caller; } CanEnt;
static CanEnt g_can[CAN_TAB_N];
static Mutex  g_can_lk;
static int    g_can_sweeper = 0;

static inline unsigned can_slot(uintptr_t a) {
  return (unsigned)((a >> 4) * 0x9E3779B97F4A7C15ULL >> (64 - CAN_TAB_BITS));
}
static inline void can_write(void *p, size_t sz) {
  *(uint64_t *)((uint8_t *)p + sz) = CAN_KEY ^ (uintptr_t)p;
}
static inline int can_ok(uintptr_t p, size_t sz) {
  return *(volatile uint64_t *)(p + sz) == (CAN_KEY ^ p);
}
static void can_report(uintptr_t p, size_t sz, const char *when) {
  const uint8_t *o = (const uint8_t *)(p + sz);
  debugPrintf("[canary] SMASH %s: block %p size %u; overrun bytes: "
              "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x "
              "%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
              when, (void *)p, (unsigned)sz,
              o[0],o[1],o[2],o[3], o[4],o[5],o[6],o[7],
              o[8],o[9],o[10],o[11], o[12],o[13],o[14],o[15],
              o[16],o[17],o[18],o[19], o[20],o[21],o[22],o[23],
              o[24],o[25],o[26],o[27], o[28],o[29],o[30],o[31]);
  /* floats too -- the historic smash was float RGBA */
  const float *f = (const float *)(p + sz);
  debugPrintf("[canary]   as floats: %g %g %g %g\n", f[0], f[1], f[2], f[3]);
}
/* Build #159: name the writer. A canary overrun runs FORWARD: the writer
 * writes past the end of ITS block into the NEXT block's tail canary, so
 * the writer is the live tracked block with the greatest address below
 * the victim. The table is lossy (hash eviction), so the neighbor found
 * here is the nearest TRACKED block below -- a strong lead, not proof.
 * Call with g_can_lk held; the SMASH line itself is left byte-identical
 * so existing log greps keep working. */
static void can_report_neighbor(uintptr_t victim, uintptr_t vcaller) {
  uintptr_t bp = 0; size_t bsz = 0; uintptr_t bcaller = 0;
  for (unsigned i = 0; i < CAN_TAB_N; i++) {
    uintptr_t p = g_can[i].p;
    if (p && p < victim && p > bp) { bp = p; bsz = g_can[i].sz; bcaller = g_can[i].caller; }
  }
  debugPrintf("[canary] SMASH-NEIGHBOR: victim %p caller %p | prev %p size %u caller %p\n",
              (void *)victim, (void *)vcaller, (void *)bp, (unsigned)bsz, (void *)bcaller);
}
static void can_sweeper_thread(void *arg) {
  (void)arg;
  for (;;) {
    svcSleepThread(2000000000ULL);   /* 2s */
    mutexLock(&g_can_lk);
    for (unsigned i = 0; i < CAN_TAB_N; i++) {
      if (g_can[i].p && !can_ok(g_can[i].p, g_can[i].sz)) {
        can_report(g_can[i].p, g_can[i].sz, "LIVE-SWEEP");
        can_report_neighbor(g_can[i].p, g_can[i].caller);
        g_can[i].p = 0;              /* report once */
      }
    }
    mutexUnlock(&g_can_lk);
  }
}
static void can_track(void *p, size_t sz, uintptr_t caller) {
  if (!p) return;
  can_write(p, sz);
  mutexLock(&g_can_lk);
  if (!g_can_sweeper) {
    g_can_sweeper = 1;
    static Thread t;
    if (R_SUCCEEDED(threadCreate(&t, can_sweeper_thread, NULL, NULL, 0x4000, 0x3B, -2)))
      threadStart(&t);
  }
  unsigned s = can_slot((uintptr_t)p);
  g_can[s].p = (uintptr_t)p; g_can[s].sz = sz; g_can[s].caller = caller;   /* lossy: eviction ok */
  mutexUnlock(&g_can_lk);
}
static void can_untrack_check(uintptr_t a) {
  mutexLock(&g_can_lk);
  unsigned s = can_slot(a);
  if (g_can[s].p == a) {
    if (!can_ok(a, g_can[s].sz)) { can_report(a, g_can[s].sz, "AT-FREE"); can_report_neighbor(a, g_can[s].caller); }
    g_can[s].p = 0;
  }
  mutexUnlock(&g_can_lk);
}

/* ---- free quarantine (use-after-free hunter/neutralizer) --------------------
 * Canaries stayed silent while pointer slots keep getting hit with packed float
 * data (this run: dst hi32 = a float bit pattern; regs full of packed float
 * pairs; historic smash was float RGBA). Tail canaries can't see writes INSIDE
 * a block -- the signature of a STALE POINTER writing into memory that was
 * freed and reallocated (to mesa's GL bookkeeping, lately). Quarantine frees:
 * hold recently freed blocks (poisoned, unreusable) in a ring; verify the
 * poison when a block finally leaves quarantine and log any write-after-free
 * with offset + content. While armed, the stale writer scribbles into
 * quarantined memory instead of someone's live allocation -- so this is a
 * mitigation as well as a detector. Bounded: <=1MB blocks, <=4096 entries,
 * <=64MB held. */
#define QUAR_N        4096
#define QUAR_MAX_SZ   (1u << 20)
#define QUAR_CAP      (64u << 20)
#define QUAR_POISON   0xDE
typedef struct { void *p; uint32_t sz; } QuarEnt;
static QuarEnt g_quar[QUAR_N];
static unsigned g_quar_head, g_quar_tail;   /* ring: head=oldest, tail=next-in */
static size_t   g_quar_bytes;
__attribute__((unused)) static void quar_check_free(QuarEnt e) {   /* no locks held */
  const uint8_t *b = (const uint8_t *)e.p;
  for (uint32_t i = 0; i < e.sz; i++) {
    if (b[i] != QUAR_POISON) {
      uint32_t end = i + 32 > e.sz ? e.sz : i + 32;
      char line[3 * 36 + 4]; int n = 0;
      for (uint32_t k = i; k < end && n < (int)sizeof(line) - 4; k++)
        n += snprintf(line + n, sizeof(line) - n, " %02x", b[k]);
      debugPrintf("[quar] WRITE-AFTER-FREE: block %p size %u, first hit at +0x%x:%s\n",
                  e.p, e.sz, i, line);
      const float *f = (const float *)(b + (i & ~3u));
      debugPrintf("[quar]   as floats: %g %g %g %g\n", f[0], f[1], f[2], f[3]);
      break;   /* report once per block */
    }
  }
  __real_free(e.p);
}
__attribute__((unused)) static void quar_add(void *p, size_t sz) {
  memset(p, QUAR_POISON, sz);
  QuarEnt out[8]; int no = 0; int direct = 0;
  mutexLock(&g_can_lk);
  while (g_quar_bytes + sz > QUAR_CAP ||
         (g_quar_tail + 1) % QUAR_N == g_quar_head) {
    if (no >= 8) { direct = 1; break; }        /* couldn't make room: free p directly */
    QuarEnt e = g_quar[g_quar_head];
    g_quar[g_quar_head].p = NULL;
    g_quar_head = (g_quar_head + 1) % QUAR_N;
    if (e.p) { g_quar_bytes -= e.sz; out[no++] = e; }
  }
  if (!direct) {
    g_quar[g_quar_tail].p = p; g_quar[g_quar_tail].sz = (uint32_t)sz;
    g_quar_tail = (g_quar_tail + 1) % QUAR_N;
    g_quar_bytes += sz;
  }
  mutexUnlock(&g_can_lk);
  for (int i = 0; i < no; i++) quar_check_free(out[i]);   /* outside the lock */
  if (direct) __real_free(p);
}

/* CANARIES DISABLED. They were built to hunt the heap corruption that turned out
 * to be mesa's nouveau_mm_allocate bug (PORTING 7), which is fixed properly now.
 * Keeping them is actively risky here: libdrm_nouveau's nouveau_bo_new allocates
 * every GPU buffer with memalign(0x1000, size), so the +8 byte tail and the side
 * table sat directly in the GPU allocation path. Pass straight through; set
 * CANARY_ENABLE to 1 to re-arm for a future corruption hunt.
 *
 * Build #153 (2026-10-25): RE-ARMED for a targeted hunt. Tests #151/#152
 * proved the full-RAM NULL-guard works but full RAM then dies deterministically
 * in newlib _int_free (aota_nx+0x92d4c0, same chunk-header value
 * 0x1000000f0000003e every run) and sphaira dies in a tiny accessor reading
 * [x0+0x50] with x0=1 -- both consistent with a heap overrun corrupting a
 * chunk/object before the crash. The canary's 2s sweeper (LIVE-SWEEP) and the
 * free-time check (AT-FREE) report the smashed block's size and the first 32
 * overrun bytes, which names the writer. KNOWN TRADE-OFFS of this build,
 * accepted for one diagnostic run: (a) __wrap_memalign bypasses the dedicated
 * GPU arena (all page-aligned buffers go through newlib again, so the
 * fragmentation/OOM behaviour differs from #150); (b) the [mem145] census and
 * [gpu]/[mem150] FAIL reporting are fed only by the #else branches, so with
 * canaries on those numbers go blind/stale -- IGNORE [mem150] tick numbers in
 * this build, the signal is [canary] SMASH lines; (c) every allocation grows
 * 8 bytes, shifting heap layout (the deterministic chunk value may move).
 * This is a DIAGNOSTIC build: do not keep canaries on for gameplay.
 *
 * Build #154 (2026-10-25): REVERTED to 0. The canary answered its question
 * (test #153: zero SMASH lines -- no classic malloc overrun before the
 * frame-0 accessor fault), so the arena and the [mem145] census are restored
 * for the dispatch-logging hunt.
 *
 * Build #155 (2026-10-25): RE-ENABLED to 1. The accessor fault is fixed
 * by the guard trampoline (the deleted mov, not corruption), so execution
 * should now reliably reach the asset phase where the deterministic chunk
 * corruption (0x1000000f0000003e) lives -- and the #153 canary never
 * watched that phase (it died at the accessor first). This run watches it:
 * a SMASH before the chunk crash proves a malloc overrun and names the
 * writer; a chunk crash with no SMASH points to a wild write or an
 * unwrapped free. Trade-offs from #153 apply again (arena bypassed,
 * [mem145] census blind while canaries are on). */
#define CANARY_ENABLE 1
void *__wrap_malloc(size_t sz) {
#if CANARY_ENABLE
  void *p = __real_malloc(sz + 8); can_track(p, sz, (uintptr_t)__builtin_return_address(0)); return p;
#else
  return __real_malloc(sz);
#endif
}
/* GPU-allocation accounting. libdrm_nouveau's nouveau_bo_new() backs EVERY GPU
 * buffer with memalign(0x1000, size) before nvMapCreate/nvAddressSpaceMap, so
 * page-aligned memaligns are a faithful proxy for GPU memory demand. texStorage is
 * failing with GL_OUT_OF_MEMORY while newlib has GBs free, so we need to know which
 * of nouveau_bo_new's three steps fails. If memalign itself returns NULL, it is CPU
 * memory after all; if it always succeeds, the failure is downstream in
 * nvMapCreate (handle limit) or nvAddressSpaceMap (GPU address space), neither of
 * which we can fix from here -- but knowing the live total tells us the budget. */
static size_t g_gpu_live, g_gpu_peak; static unsigned long g_gpu_n, g_gpu_freed;

/* ---- dedicated GPU arena --------------------------------------------------
 * libdrm_nouveau backs every GPU buffer with memalign(0x1000, size). Those are
 * large (up to ~22 MB), page-aligned, and churned constantly, so serving them
 * from newlib's general heap shreds it: once fragmented, a 21 MB CONTIGUOUS
 * page-aligned run cannot be placed even with a gigabyte free in aggregate, and
 * memalign returns NULL -> nouveau_bo_new fails -> texStorage GL_OUT_OF_MEMORY ->
 * incomplete FBO -> black screen. Reserve one big contiguous region ONCE at first
 * use (before the heap is churned) and hand GPU buffers out of it with a simple
 * page bitmap, so they can never fragment newlib and newlib can never fragment
 * them. Falls back to plain memalign if the arena is full or unavailable. */
#define GPUA_PAGE   0x1000u
/* Contiguous GPU region.
 *
 * The old note here said "observed 927 MB live and still failing at 1024 MB, so
 * the game wants ~1 GB+ of GPU buffers". THAT MEASUREMENT WAS CONTAMINATED: the
 * OC commit-pool was itself a memalign(0x1000, 896 MB), which matches this
 * wrapper's GPU signature, so the pool was being served OUT OF THIS ARENA and
 * counted as GPU buffers. Shrinking the pool by 384 MB dropped reported arena
 * usage by exactly 384 MB, which is what gave it away.
 *
 * With the pool moved to __real_memalign (main.c), real GPU buffer usage is
 * about 135 MB -- at 720p in the menus and at 1080p alike. 1152 MB is therefore
 * enormous headroom at either resolution, and the resolution-aware bump this
 * briefly carried was funded by a number that was not real. One size again.
 *
 * Kept generous rather than trimmed to fit: the arena exists to guarantee
 * CONTIGUOUS page-aligned runs, and the failure it prevents is fragmentation,
 * not total bytes. With the pool gone it costs newlib 384 MB less than before.
 *
 * Self-limiting: gpua_init() shrinks the request by 64 MB until memalign
 * succeeds, so the reserved size is whatever fits, and it is logged. */
/* [gpu142] 1152 -> 1024 MB. Hardware (tests #138/#141) shows THIS game
 * parks ~1140 MB in the arena during the Addressables load -- 8x the
 * reference port's 135 MB the 1152 figure was sized from -- and the arena
 * stays pinned at max from early load to title. The binding constraint at
 * the #141 OOM was the OTHER side: newlib/mmap requests (52 MB) failing
 * while ~700 MB of BOs already lived in newlib via fallbacks. The arena is
 * carved from the same fixed 2962 MB title heap, so 128 MB moves from the
 * (full) arena to the (starving) general heap. Fallbacks already work --
 * #138 reached title with 80 of them -- they just need room. */
#define GPUA_BYTES  ((size_t)1024 * 1024 * 1024)
#define GPUA_MIN    (64u * 1024)                   /* below this, use newlib */
static uint8_t  *gpua_base;
static size_t    gpua_pages;
static uint8_t  *gpua_used;      /* 1 byte/page: in use */
static uint32_t *gpua_runlen;    /* run length recorded at the first page */
static size_t   *gpua_runsz;     /* [gpu142] requested size at the first page */
static size_t    gpua_hint;
static Mutex     gpua_lock;
static int       gpua_state;     /* 0=untried 1=ready -1=disabled */
static size_t    gpua_live_pages, gpua_peak_pages;
static unsigned long g_gpua_fallbacks;   /* arena full/unavailable -> newlib */
static size_t    gpua_hist_n[8], gpua_hist_b[8];   /* <64K,128K,256K,1M,4M,8M,16M,+ */

/* NOTE: never call debugPrintf while holding gpua_lock. Logging writes to the SD
 * card and can allocate internally, which re-enters __wrap_memalign -> gpua_alloc
 * -> mutexLock(gpua_lock); libnx mutexes are NOT recursive, so that self-deadlocks
 * the calling thread (observed as "clock thread driving Update (main stalled)").
 * Record the outcome under the lock, report it after releasing. */
static void gpua_init(void) {
  if (gpua_state) return;
  size_t got_mb = 0, want_mb = 0; int report = 0;
  mutexLock(&gpua_lock);
  if (!gpua_state) {
    const size_t target = GPUA_BYTES;
    size_t want = target;
    uint8_t *b = NULL;
    while (want >= (size_t)128 * 1024 * 1024) {     /* shrink until it fits */
      b = (uint8_t *)__real_memalign(GPUA_PAGE, want);
      if (b) break;
      want -= (size_t)64 * 1024 * 1024;
    }
    if (b) {
      gpua_pages  = want / GPUA_PAGE;
      gpua_used   = (uint8_t *)__real_calloc(gpua_pages, 1);
      gpua_runlen = (uint32_t *)__real_calloc(gpua_pages, sizeof(uint32_t));
      gpua_runsz  = (size_t *)__real_calloc(gpua_pages, sizeof(size_t));
      if (gpua_used && gpua_runlen && gpua_runsz) {
        gpua_base = b; gpua_hint = 0; gpua_state = 1;
        got_mb = want >> 20; report = 1;
        want_mb = target >> 20;
      } else {
        __real_free(gpua_used); __real_free(gpua_runlen); __real_free(gpua_runsz); __real_free(b);
        gpua_used = NULL; gpua_runlen = NULL; gpua_runsz = NULL;
        gpua_state = -1; report = 2;
      }
    } else {
      gpua_state = -1; report = 3;
    }
  }
  mutexUnlock(&gpua_lock);
  if (report == 1)
    debugPrintf("[gpua] GPU arena reserved: %u MB contiguous (asked %u MB)%s\n",
                (unsigned)got_mb, (unsigned)want_mb,
                got_mb < want_mb ? "  <-- SHORT: heap could not spare the rest" : "");
  else if (report == 2) debugPrintf("[gpua] GPU arena DISABLED (bitmap alloc failed)\n");
  else if (report == 3) debugPrintf("[gpua] GPU arena DISABLED (no contiguous region)\n");
}

/* Periodic health line for the render loop (called from the swap diagnostic).
 * The arena is sized from the reference port's numbers, not this game's, so the
 * question worth answering on hardware is whether 1152 MB is wildly over- or
 * under-provisioned -- and, more urgently for a black screen, whether GPU
 * buffers are falling back to newlib because the arena filled. A fallback here
 * is the documented path to nouveau_bo_new failing -> texStorage OOM -> nothing
 * renders. */
void gpua_report(void) {
  debugPrintf("[gpua] arena %u/%u MB (peak %u MB) | bo live %u MB peak %u MB | "
              "fallbacks %lu\n",
              (unsigned)((gpua_live_pages * GPUA_PAGE) >> 20),
              (unsigned)((gpua_pages     * GPUA_PAGE) >> 20),
              (unsigned)((gpua_peak_pages * GPUA_PAGE) >> 20),
              (unsigned)(g_gpu_live >> 20), (unsigned)(g_gpu_peak >> 20),
              g_gpua_fallbacks);
}

static void *gpua_alloc(size_t sz) {
  gpua_init();
  if (gpua_state != 1) return NULL;
  size_t need = (sz + GPUA_PAGE - 1) / GPUA_PAGE;
  if (!need || need > gpua_pages) return NULL;
  void *out = NULL;
  mutexLock(&gpua_lock);
  for (int pass = 0; pass < 2 && !out; pass++) {     /* hint first, then wrap */
    size_t i = pass ? 0 : gpua_hint;
    size_t end = pass ? gpua_hint : gpua_pages;
    while (i + need <= end) {
      size_t run = 0;
      while (run < need && !gpua_used[i + run]) run++;
      if (run == need) {
        for (size_t k = 0; k < need; k++) gpua_used[i + k] = 1;
        gpua_runlen[i] = (uint32_t)need;
        gpua_runsz[i] = sz;
        gpua_hint = i + need; if (gpua_hint >= gpua_pages) gpua_hint = 0;
        gpua_live_pages += need;
        if (gpua_live_pages > gpua_peak_pages) gpua_peak_pages = gpua_live_pages;
        { unsigned b = 0; size_t t = sz >> 16;      /* bucket by size */
          while (t && b < 7) { t >>= 1; b++; }
          gpua_hist_n[b]++; gpua_hist_b[b] += sz; }
        out = gpua_base + i * GPUA_PAGE;
        break;
      }
      i += run + 1;                                  /* skip past the blocker */
    }
  }
  mutexUnlock(&gpua_lock);
  return out;
}

static int gpua_owns(const void *p) {
  return gpua_state == 1 && (const uint8_t *)p >= gpua_base &&
         (const uint8_t *)p < gpua_base + gpua_pages * GPUA_PAGE;
}

static size_t gpua_free(void *p) {
  size_t i = (size_t)(((uint8_t *)p - gpua_base) / GPUA_PAGE);
  mutexLock(&gpua_lock);
  uint32_t n = (i < gpua_pages) ? gpua_runlen[i] : 0;
  size_t rsz = 0;
  if (n) {
    rsz = gpua_runsz[i];
    for (uint32_t k = 0; k < n; k++) gpua_used[i + k] = 0;
    gpua_runlen[i] = 0;
    gpua_runsz[i] = 0;
    if (gpua_live_pages >= n) gpua_live_pages -= n; else gpua_live_pages = 0;
    if (i < gpua_hint) gpua_hint = i;
  }
  mutexUnlock(&gpua_lock);
  return rsz;
}

/* ---- [mem145] big-allocation caller census --------------------------------
 * Tests #141-#144 keep dying the same way in sphaira mode: during the
 * Addressables load, page-aligned requests of 32-65 MB fail in BOTH the
 * arena and newlib while reported live sits ~1.7 GB of the 2962 MB pool.
 * Two blind arena diets (1152 -> 1024) did not close it, because nobody
 * knows WHO holds the memory, nor whether the arena's free space is one
 * run or confetti. This census answers both, once, at the first hard
 * failure:
 *   - every page-aligned allocation >= 4 MB is tagged with its caller
 *     (the return address out of __wrap_memalign) in a lossy side table
 *     (the canary table's pattern, minus the canaries);
 *   - per-caller aggregates: count, live bytes, peak bytes, largest single;
 *   - at the first "[gpu] memalign FAILED", a dump prints the victim's
 *     caller, the arena's free-run histogram (fragmentation shape), the
 *     top callers by live bytes, and the eight largest live blocks.
 * Caller VAs resolve to module+offset against the [mod] virtbase lines in
 * the same debug.log (proven: futex caller 0xff6f7257c = libunity+0x127a57c).
 * Diagnostic only: no routing, sizing or accounting behaviour changes. */
#define MEM145_MIN     ((size_t)4 * 1024 * 1024)
#define MEM145_CALLERS 32
#define MEM145_TAB_BITS 13
#define MEM145_TAB_N   (1u << MEM145_TAB_BITS)
typedef struct { uintptr_t caller; unsigned long n; size_t live, peak, max1; } M145Caller;
typedef struct { uintptr_t p; size_t sz; uintptr_t caller; } M145Ent;
static M145Caller g_m145_callers[MEM145_CALLERS];
static M145Ent    g_m145_tab[MEM145_TAB_N];
static Mutex      g_m145_lk;

static unsigned m145_hash(uintptr_t a) {
  return (unsigned)((a >> 12) * 0x9E3779B97F4A7C15ULL >> (64 - MEM145_TAB_BITS));
}
static int m145_caller_idx(uintptr_t caller) {   /* g_m145_lk held */
  int empty = -1;
  for (int i = 0; i < MEM145_CALLERS; i++) {
    if (g_m145_callers[i].caller == caller) return i;
    if (!g_m145_callers[i].caller && empty < 0) empty = i;
  }
  if (empty >= 0) g_m145_callers[empty].caller = caller;
  return empty;
}
static void m145_track(void *p, size_t sz, uintptr_t caller) {
  if (!p || sz < MEM145_MIN) return;
  mutexLock(&g_m145_lk);
  const int ci = m145_caller_idx(caller);
  if (ci >= 0) {
    M145Caller *c = &g_m145_callers[ci];
    c->n++; c->live += sz;
    if (c->live > c->peak) c->peak = c->live;
    if (sz > c->max1) c->max1 = sz;
  }
  const unsigned s = m145_hash((uintptr_t)p);
  for (int k = 0; k < 8; k++) {
    const unsigned j = (s + (unsigned)k) & (MEM145_TAB_N - 1);
    if (!g_m145_tab[j].p || g_m145_tab[j].p == (uintptr_t)p) {
      g_m145_tab[j].p = (uintptr_t)p; g_m145_tab[j].sz = sz;
      g_m145_tab[j].caller = caller;
      break;
    }
  }
  mutexUnlock(&g_m145_lk);
}
static void m145_untrack(void *p) {
  mutexLock(&g_m145_lk);
  const unsigned s = m145_hash((uintptr_t)p);
  for (int k = 0; k < 8; k++) {
    const unsigned j = (s + (unsigned)k) & (MEM145_TAB_N - 1);
    if (g_m145_tab[j].p == (uintptr_t)p) {
      const int ci = m145_caller_idx(g_m145_tab[j].caller);
      if (ci >= 0) {
        M145Caller *c = &g_m145_callers[ci];
        if (c->live >= g_m145_tab[j].sz) c->live -= g_m145_tab[j].sz;
        else c->live = 0;
      }
      g_m145_tab[j].p = 0; g_m145_tab[j].sz = 0; g_m145_tab[j].caller = 0;
      break;
    }
    if (!g_m145_tab[j].p) break;   /* empty slot: it was never tracked */
  }
  mutexUnlock(&g_m145_lk);
}
static void m145_dump(uintptr_t victim_caller, size_t victim_sz) {
  /* Gather under the locks, print after releasing them (this file's rule:
   * never debugPrintf while holding gpua_lock; same discipline for ours). */
  size_t free_pages = 0, largest_run = 0;
  unsigned run_hist[5] = {0, 0, 0, 0, 0};   /* runs of <1M, 1-4M, 4-16M, 16-64M, >=64M */
  if (gpua_state == 1 && gpua_used) {
    mutexLock(&gpua_lock);
    size_t run = 0;
    for (size_t i = 0; i <= gpua_pages; i++) {
      const int used = (i < gpua_pages) ? gpua_used[i] : 1;   /* sentinel flush */
      if (!used) { run++; free_pages++; continue; }
      if (run) {
        const size_t bytes = run * GPUA_PAGE;
        if (run > largest_run) largest_run = run;
        run_hist[bytes < ((size_t)1 << 20) ? 0 : bytes < ((size_t)4 << 20) ? 1 :
                 bytes < ((size_t)16 << 20) ? 2 : bytes < ((size_t)64 << 20) ? 3 : 4]++;
        run = 0;
      }
    }
    mutexUnlock(&gpua_lock);
  }
  M145Caller callers[MEM145_CALLERS];
  M145Ent top[8]; int ntop = 0;
  mutexLock(&g_m145_lk);
  memcpy(callers, g_m145_callers, sizeof callers);
  for (int i = 0; i < MEM145_TAB_N; i++) {
    if (!g_m145_tab[i].p) continue;
    if (ntop < 8) { top[ntop++] = g_m145_tab[i]; continue; }
    int minj = 0;
    for (int j = 1; j < 8; j++) if (top[j].sz < top[minj].sz) minj = j;
    if (g_m145_tab[i].sz > top[minj].sz) top[minj] = g_m145_tab[i];
  }
  mutexUnlock(&g_m145_lk);
  for (int i = 1; i < ntop; i++) {           /* insertion sort, largest first */
    const M145Ent e = top[i]; int j = i - 1;
    while (j >= 0 && top[j].sz < e.sz) { top[j + 1] = top[j]; j--; }
    top[j + 1] = e;
  }

  debugPrintf("[mem145] FIRST memalign FAILURE: request %u KB caller=%p | arena live %u/%u MB, bo live %u MB peak %u MB\n",
              (unsigned)(victim_sz >> 10), (void *)victim_caller,
              (unsigned)((gpua_live_pages * GPUA_PAGE) >> 20),
              (unsigned)((gpua_pages * GPUA_PAGE) >> 20),
              (unsigned)(g_gpu_live >> 20), (unsigned)(g_gpu_peak >> 20));
  debugPrintf("[mem145] arena free: %u MB total, largest run %u MB | runs <1M=%u 1-4M=%u 4-16M=%u 16-64M=%u >=64M=%u\n",
              (unsigned)((free_pages * GPUA_PAGE) >> 20),
              (unsigned)((largest_run * GPUA_PAGE) >> 20),
              run_hist[0], run_hist[1], run_hist[2], run_hist[3], run_hist[4]);
  for (int printed = 0; printed < 8; printed++) {
    int best = -1;
    for (int i = 0; i < MEM145_CALLERS; i++)
      if (callers[i].caller && (best < 0 || callers[i].live > callers[best].live)) best = i;
    if (best < 0 || !callers[best].live) break;
    debugPrintf("[mem145] caller %p: n=%lu live=%u MB peak=%u MB max1=%u MB\n",
                (void *)callers[best].caller, callers[best].n,
                (unsigned)(callers[best].live >> 20),
                (unsigned)(callers[best].peak >> 20),
                (unsigned)(callers[best].max1 >> 20));
    callers[best].live = 0; callers[best].caller = 0;   /* consumed */
  }
  for (int i = 0; i < ntop; i++)
    debugPrintf("[mem145] block %p size=%u MB caller=%p\n",
                (void *)top[i].p, (unsigned)(top[i].sz >> 20),
                (void *)top[i].caller);
}
/* ---- [mem150] cliff quantification --------------------------------------
 * Tests #149 (three runs) all died the same way with different crash sites:
 * arena 988/1024 MB, bo live ~1.7 GB, arena free 35 MB with largest run
 * 5 MB, then memalign failures (32-102 MB) -> unchecked NULL -> NULL-store
 * (run 1: worker memcpy dst=NULL; run 2: game-code store after explicit
 * 52 MB failures) or wild jump (run 3: Instruction Abort). The [mem145]
 * census fires once, at the first failure, and [gpu] memalign FAILED stops
 * after 3 -- so the cliff's SHAPE is invisible: how fast headroom burns,
 * which sizes fail in what order, and how far the peak demand sits above
 * capacity. [mem150] closes that gap, diagnostic only:
 *   - mem150_tick(): called every 5s from the [jni137] ticker thread
 *     (which keeps running while nativeRender stalls during loading),
 *     one line: arena live/free/largest-run, bo live/peak, top caller by
 *     live bytes + its largest single block, newlib used/free (mallinfo --
 *     the fallback heap's headroom, which decides whether a failed arena
 *     allocation survives via newlib or dies outright).
 *   - mem150_fail(): one compact line for EVERY hard memalign failure
 *     past the first 3 (capped at 20 -- failures cascade, the log must not
 *     drown), same snapshot. The full [mem145] census still fires once.
 * Gathering follows m145_dump's discipline: locks held only while copying
 * counters, never across debugPrintf. */
typedef struct {
  unsigned arena_live_mb, arena_tot_mb, arena_free_mb, largest_mb;
  unsigned bo_live_mb, bo_peak_mb;
  uintptr_t top_caller; unsigned long top_n;
  size_t top_live, top_max1;
  unsigned nl_used_mb, nl_free_mb;
} M150Snap;
static void mem150_gather(M150Snap *s) {
  memset(s, 0, sizeof *s);
  s->arena_tot_mb = (unsigned)((gpua_pages * GPUA_PAGE) >> 20);
  s->arena_live_mb = (unsigned)((gpua_live_pages * GPUA_PAGE) >> 20);
  if (gpua_state == 1 && gpua_used) {
    mutexLock(&gpua_lock);
    size_t run = 0, free_pages = 0, largest_run = 0;
    for (size_t i = 0; i <= gpua_pages; i++) {
      const int used = (i < gpua_pages) ? gpua_used[i] : 1;   /* sentinel */
      if (!used) { run++; free_pages++; continue; }
      if (run) {
        if (run > largest_run) largest_run = run;
        run = 0;
      }
    }
    mutexUnlock(&gpua_lock);
    s->arena_free_mb = (unsigned)((free_pages * GPUA_PAGE) >> 20);
    s->largest_mb = (unsigned)((largest_run * GPUA_PAGE) >> 20);
  }
  s->bo_live_mb = (unsigned)(g_gpu_live >> 20);
  s->bo_peak_mb = (unsigned)(g_gpu_peak >> 20);
  mutexLock(&g_m145_lk);
  for (int i = 0; i < MEM145_CALLERS; i++)
    if (g_m145_callers[i].caller && g_m145_callers[i].live > s->top_live) {
      s->top_caller = g_m145_callers[i].caller; s->top_n = g_m145_callers[i].n;
      s->top_live = g_m145_callers[i].live; s->top_max1 = g_m145_callers[i].max1;
    }
  mutexUnlock(&g_m145_lk);
  struct mallinfo mi = mallinfo();
  s->nl_used_mb = (unsigned)((unsigned)mi.uordblks >> 20);
  s->nl_free_mb = (unsigned)((unsigned)mi.fordblks >> 20);
}
void mem150_tick(void) {
  static unsigned n = 0;
  M150Snap s; mem150_gather(&s);
  debugPrintf("[mem150] 5s #%u | arena %u/%u MB free %u MB largest %u MB | bo live %u MB peak %u MB | top caller %p n=%lu live %u MB max1 %u MB | newlib used %u MB free %u MB\n",
              ++n, s.arena_live_mb, s.arena_tot_mb, s.arena_free_mb, s.largest_mb,
              s.bo_live_mb, s.bo_peak_mb, (void *)s.top_caller, s.top_n,
              (unsigned)(s.top_live >> 20), (unsigned)(s.top_max1 >> 20),
              s.nl_used_mb, s.nl_free_mb);
}
void mem150_fail(uintptr_t caller, size_t sz, unsigned n) {
  M150Snap s; mem150_gather(&s);
  debugPrintf("[mem150] FAIL #%u size=%u KB caller=%p | arena %u/%u MB free %u MB largest %u MB | bo live %u MB peak %u MB | newlib used %u MB free %u MB\n",
              n, (unsigned)(sz >> 10), (void *)caller,
              s.arena_live_mb, s.arena_tot_mb, s.arena_free_mb, s.largest_mb,
              s.bo_live_mb, s.bo_peak_mb, s.nl_used_mb, s.nl_free_mb);
}

void *__wrap_memalign(size_t al, size_t sz) {
#if CANARY_ENABLE
  void *p = __real_memalign(al ? al : 8, sz + 8); can_track(p, sz, (uintptr_t)__builtin_return_address(0)); return p;
#else
  const uintptr_t ra = (uintptr_t)__builtin_return_address(0);   /* [mem145] */
  void *p = NULL;
  if (al >= 0x1000 && sz >= GPUA_MIN) {
    p = gpua_alloc(sz);   /* dedicated GPU arena */
    if (!p) {
      /* Report the FIRST few immediately. The counter is otherwise only printed
       * by the periodic swap diagnostic, so a run that dies between reports
       * shows "fallbacks 0" and looks healthy -- which is exactly how the 1080p
       * crash hid: the last report said 0, and the failing allocation came
       * after it. A fallback is the documented road to nouveau_bo_new failing,
       * so it should never be inferred from a stale counter. */
      if (g_gpua_fallbacks < 5)
        debugPrintf("[gpua] FALLBACK #%lu: arena could not place %u KB "
                    "(live %u/%u MB) caller=%p -- newlib next\n",
                    g_gpua_fallbacks + 1, (unsigned)(sz >> 10),
                    (unsigned)((gpua_live_pages * GPUA_PAGE) >> 20),
                    (unsigned)((gpua_pages * GPUA_PAGE) >> 20), (void *)ra);
      /* [gpu142] The size histogram has been collected since day one but
       * its print was disabled. The first two fallbacks are the moment
       * the arena's real diet matters -- dump it there. */
      if (g_gpua_fallbacks < 2) {
        static const char *lbl[8] = {"<64K","<128K","<256K","<512K","<1M","<2M","<4M",">=4M"};
        for (unsigned b = 0; b < 8; b++)
          if (gpua_hist_n[b])
            debugPrintf("[gpu142] arena hist %-6s n=%u total=%u MB\n", lbl[b],
                        (unsigned)gpua_hist_n[b], (unsigned)(gpua_hist_b[b] >> 20));
      }
      g_gpua_fallbacks++;
    }
  }
  if (!p) p = __real_memalign(al ? al : 8, sz);
  if (al >= 0x1000) {                       /* nouveau_bo_new signature */
    if (!p) {
      static unsigned nf;
      const unsigned this_nf = nf++;   /* [mem150] count every failure */
      if (this_nf < 3) {
        debugPrintf("[gpu] memalign FAILED size=%u KB (live=%u MB peak=%u MB n=%lu) caller=%p\n",
                    (unsigned)(sz >> 10), (unsigned)(g_gpu_live >> 20),
                    (unsigned)(g_gpu_peak >> 20), g_gpu_n, (void *)ra);
      }
      if (this_nf == 0) m145_dump(ra, sz);   /* [mem145] one full census */
      else if (this_nf < 20) mem150_fail(ra, sz, this_nf + 1);
    } else {
      g_gpu_live += sz; g_gpu_n++;
      if (g_gpu_live > g_gpu_peak) g_gpu_peak = g_gpu_live;
      m145_track(p, sz, ra);                 /* [mem145] no-op below 4 MB */
      if (0)
        debugPrintf("[gpu] bo allocs=%lu freed=%lu LIVE=%u MB | arena %u/%u MB peak %u MB\n",
                    g_gpu_n, g_gpu_freed, (unsigned)(g_gpu_live >> 20),
                    (unsigned)((gpua_live_pages * GPUA_PAGE) >> 20),
                    (unsigned)((gpua_pages * GPUA_PAGE) >> 20),
                    (unsigned)((gpua_peak_pages * GPUA_PAGE) >> 20));
      { static unsigned hist_shown; if (0) {
        static const char *lbl[8] = {"<64K","<128K","<256K","<512K","<1M","<2M","<4M",">=4M"};
        for (unsigned b = 0; b < 8; b++)
          if (gpua_hist_n[b])
            debugPrintf("[gpu]   %-6s n=%u total=%u MB\n", lbl[b],
                        (unsigned)gpua_hist_n[b], (unsigned)(gpua_hist_b[b] >> 20)); } }
    }
  }
  return p;
#endif
}
void *__wrap_calloc(size_t n, size_t s) {
#if CANARY_ENABLE
  if (s && n > (SIZE_MAX - 8) / s) return NULL;
  size_t sz = n * s;
  void *p = __real_malloc(sz + 8);
  if (p) { memset(p, 0, sz); can_track(p, sz, (uintptr_t)__builtin_return_address(0)); }
  return p;
#else
  return __real_calloc(n, s);
#endif
}
void *__wrap_realloc(void *p, size_t sz) {
#if CANARY_ENABLE
  if (p) can_untrack_check((uintptr_t)p);
  void *q = __real_realloc(p, sz + 8); can_track(q, sz, (uintptr_t)__builtin_return_address(0)); return q;
#else
  /* An arena block is NOT a newlib block: handing it to realloc would corrupt the
   * heap. Copy out to a real allocation and release the arena slot. */
  if (p && gpua_owns(p)) {
    size_t old_pages = 0;
    { size_t i = (size_t)(((uint8_t *)p - gpua_base) / GPUA_PAGE);
      if (i < gpua_pages) old_pages = gpua_runlen[i]; }
    size_t oldsz = old_pages * GPUA_PAGE;
    void *q = __real_malloc(sz);
    if (q) memcpy(q, p, sz < oldsz ? sz : oldsz);
    m145_untrack(p);   /* [mem145] this path bypasses __wrap_free */
    gpua_free(p);
    return q;
  }
  return __real_realloc(p, sz);
#endif
}

/* ---- copy-destination guard (the glBufferData killer, final line of defense) --
 * Every crash in this arc is a memmove/memcpy into a poisoned destination with
 * the same shape: low 32 bits ~0, high bits junk, or beyond the 39-bit user AS.
 * The producer (mesa transfer-map path; one reachable uninitialized-tx return
 * exists when staging mm_allocate fails) is still being pinned down. Until
 * then: validate copy destinations. An insane dst is logged WITH THE CALLER
 * ADDRESS (names the exact site) and the copy is SKIPPED -- a stale/garbage GL
 * buffer renders wrong at worst, instead of killing the process. Sane copies
 * pass straight through to newlib (tail-called, near-zero overhead). */
extern void *__real_memmove(void *dst, const void *src, size_t n);
extern void *__real_memcpy(void *dst, const void *src, size_t n);
static int copy_dst_insane(uintptr_t d, size_t n) {
  /* DISABLED now that mesa's nouveau_mm_allocate bug is fixed. This was a
   * crash-era net that SKIPS a memcpy it judges insane -- and one of its
   * rules (low-32 == 0) matches legitimate 4GB-aligned addresses such as our
   * own mmap arena base (0x7200000000). A silently skipped copy = missing
   * geometry//texture data, i.e. exactly a black screen. Keep the plumbing,
   * fail-open. */
  return 0;
  if (!n) return 0;
  if (d == 0) return 1;
  if (d >= 0x8000000000ULL) return 1;                 /* past 39-bit user AS */
  if ((d & 0xFFFFFFFFULL) == 0 && d != 0) return 1;   /* {lo32=0} poison shape */
  if ((d >> 32) == 0xdedededeULL) return 1;           /* our 0xDE free-poison in the ptr */
  if ((d & 0xFFFFFFFF00000000ULL) &&
      (d & 0xFFFFFFFFULL) == 0x1181a8d8ULL) return 1; /* observed mangled-high family */
  /* any 0xDE byte in the top half is quarantine poison bleed */
  if ((((d >> 32) & 0xFF) == 0xDE) && (((d >> 40) & 0xFF) == 0xDE)) return 1;
  return 0;
}
static void copy_report(const char *fn, void *dst, const void *src, size_t n) {
  static unsigned cnt = 0;
  if (cnt < 32 || (cnt & 0xFF) == 0)
    debugPrintf("[copyguard] SKIP %s(dst=%p, src=%p, n=%u) caller=%p\n",
                fn, dst, src, (unsigned)n, __builtin_return_address(0));
  cnt++;
}
void *__wrap_memmove(void *dst, const void *src, size_t n) {
  if (copy_dst_insane((uintptr_t)dst, n)) { copy_report("memmove", dst, src, n); return dst; }
  return __real_memmove(dst, src, n);
}
void *__wrap_memcpy(void *dst, const void *src, size_t n) {
  if (copy_dst_insane((uintptr_t)dst, n)) { copy_report("memcpy", dst, src, n); return dst; }
  return __real_memcpy(dst, src, n);
}

void __wrap_free(void *p) {
  uintptr_t a = (uintptr_t)p;
  if (a == 0) return;                         /* free(NULL): no-op */
  if ((a & 7) != 0 || a >= 0x8000000000ULL) { /* misaligned or past user AS */
    static unsigned n = 0;
    if (n++ < 128)
      debugPrintf("[heap] SKIP free(%p): corrupted pointer (asset-load smash) -- leaking\n", p);
    return;
  }
  /* Build #157/#158: managed-mmap pointers must never reach newlib's
   * chunk walk. Tests #156/#157 died freeing a managed-mmap pointer
   * (region+0x10 -- OC window in #156, heap-backed mmap_arena in #157
   * after "OC window full"): the walk reads the region's asset bytes
   * at chunk+8 as a "size" (0x1000000f0000003e) and faults on the wild
   * next chunk. oc_ptr_is_oc now covers both regions. Log (first 128,
   * with the free caller) and LEAK the block -- leaking one managed
   * pointer per occurrence keeps the game alive past frame 0 and names
   * every managed free; proper managed-free routing follows once the
   * callers are known. NOTE: __wrap_realloc is NOT guarded yet -- a
   * managed pointer through realloc would hit the same walk. */
  if (oc_ptr_is_oc(p)) {
    static unsigned oc_n = 0;
    if (oc_n++ < 128)
      debugPrintf("[ocfree] managed-mmap free(%p) caller %p -- leaking, NOT feeding newlib\n",
                  p, (void *)__builtin_return_address(0));
    return;
  }
#if CANARY_ENABLE
  can_untrack_check(a);
#endif
  if (gpua_owns(p)) {
    /* [gpu142] __wrap_memalign added the requested size to g_gpu_live for
     * arena allocations too, but this branch never subtracted it back --
     * "bo live" was cumulative for arena-served blocks and only ever
     * decreased for newlib ones, which is how test #141 could report
     * live=1871 MB against a 1152 MB arena. Subtract symmetrically. */
    size_t rsz = gpua_free(p);
    if (rsz <= g_gpu_live) g_gpu_live -= rsz; else g_gpu_live = 0;
    g_gpu_freed++;
    m145_untrack(p);   /* [mem145] */
    return;
  }
  if ((a & 0xFFF) == 0) {          /* page-aligned => almost certainly a nouveau bo */
    size_t us = malloc_usable_size(p);
    if (us <= g_gpu_live) g_gpu_live -= us; else g_gpu_live = 0;
    g_gpu_freed++;
    m145_untrack(p);   /* [mem145] */
  }
  /* Free quarantine DISABLED: it held up to 64MB of freed blocks hostage, which
   * starves mesa's GART slab allocations (nouveau bo memory comes from newlib).
   * It existed to prove the use-after-free, which is now fixed properly in
   * mesa (nouveau_mm_allocate slab-failure handling). Set QUAR_ENABLE to 1 to
   * re-arm it for future memory-corruption hunts. */
#define QUAR_ENABLE 0
#if QUAR_ENABLE
  size_t us = malloc_usable_size(p);
  if (us && us <= QUAR_MAX_SZ) { quar_add(p, us); return; }   /* hold + poison */
#endif
  /* Build #161: chunk-guard. Tests #159-retest/#160 died INSIDE newlib's
   * free() itself -- full RAM on a chunk-walk load (aota_nx+0x92CCD8),
   * sphaira on a free-list unlink store (aota_nx+0x92B0D8) -- both
   * operating on chunks whose headers the heap corruption had already
   * poisoned (asset bytes / float patterns as "sizes"). Every other
   * routing above has run (NULL, misaligned, [ocfree], canary, gpu
   * arena), so p MUST be a newlib chunk here: its head sits at p-8
   * and its size (head & ~7) must be 16-aligned, >= 32, and sane.
   * A poisoned header fails that test -- log it and LEAK instead of
   * feeding newlib a corrupted chunk (same philosophy as [ocfree]).
   * PARTIAL guard, stated honestly: it catches poisoned SIZE fields,
   * not a corrupted fd/bk in a NEIGHBOR chunk, so a run can still
   * die in free() -- but then the log shows which frees were clean.
   * NOTE: __wrap_realloc is still NOT guarded. */
  {
    size_t head = *(size_t *)((char *)p - 8);
    size_t csz = head & ~(size_t)7;
    if (csz < 32 || (csz & 15) != 0 || csz > (size_t)0x40000000) {
      static unsigned cg_n = 0;
      if (cg_n++ < 128)
        debugPrintf("[chunk161] POISONED free(%p) caller %p head 0x%zx size 0x%zx -- leaking, NOT feeding newlib\n",
                    p, (void *)__builtin_return_address(0), head, csz);
      return;
    }
  }
  /* Build #162: chain-guard. Retest #161 #4 proved #161's guard cannot
   * fire on the observed early deaths: full RAM died at aota_nx+0x92CD58
   * (ldr x5,[x5,#8] inside newlib free) reading the size of the
   * chunk-after-next -- the freed chunk's own size was VALID, but the
   * NEXT chunk's size field was poisoned, so the walk computed a wild
   * chunk-after-next pointer and faulted. #161 only validates the freed
   * chunk's own size, so it passed cleanly and the walk died anyway.
   * This block walks up to 4 links ahead and validates each next
   * chunk's size with the same test (16-aligned, >= 32, <= 1GB) BEFORE
   * advancing: a size is only used to compute the next pointer after
   * it passed, so the walk itself can never dereference a wild
   * pointer -- the first poisoned link leaks instead of feeding newlib.
   * Depth 4 covers the observed poison-at-link-1 with margin, and
   * keeps the top-chunk false-positive window (a legit huge top size
   * within 4 links of the heap end) small; a leak there is benign.
   * Build #163 fix: test #162 fired 135 times (7 full RAM, 128 capped
   * sphaira) but EVERY firing was size 0x0, at links 2/4 only, from
   * wrapper startup onward -- the walk crossing a region boundary
   * newlib itself never crosses (top chunk / mmap chunks), reading
   * zero-filled memory past the boundary. A real chunk's size is
   * >= 32, so 0 can only come from unwritten memory there; newlib
   * stops before it (the game never hung on these frees), so the
   * guard now treats size 0 as CHAIN END: stop walking and pass the
   * free to newlib, silently. The poison test below still catches
   * the real family (huge / misaligned / float-asset sizes). */
  {
    uintptr_t ch = (uintptr_t)p - 0x10;   /* chunk base: size field at p-8 */
    size_t sz = *(size_t *)(ch + 8) & ~(size_t)7;   /* own size, #161-validated */
    for (int link = 1; link <= 4; link++) {
      uintptr_t nxt = ch + sz;
      size_t nsz = *(size_t *)(nxt + 8) & ~(size_t)7;
      if (nsz == 0) break;   /* #163: chain end (boundary), not poison */
      if (nsz < 32 || (nsz & 15) != 0 || nsz > (size_t)0x40000000) {
        static unsigned ch_n = 0;
        if (ch_n++ < 128)
          debugPrintf("[chain162] POISONED link %d free(%p) caller %p next %p size 0x%zx -- leaking, NOT feeding newlib\n",
                      link, p, (void *)__builtin_return_address(0), (void *)nxt, nsz);
        return;
      }
      ch = nxt; sz = nsz;
    }
  }
  __real_free(p);
}
