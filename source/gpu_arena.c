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
#include <unistd.h>      /* sbrk (chain-guard heap bound, #164) */
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
extern so_module unity_mod;   /* main.c: libunity load bases (#172) */
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
  /* Build #172: leak EVERY free from the late-variant cleanup callers
   * (libunity return-address offsets 0xC44E14 / 0xC44D00 -- the last
   * managed free before the fullram NULL-deref at libunity+0xC505E8,
   * 13 sightings). CORRECTION to the original proposal: the OC cleanup
   * free is ALREADY leaked by the [ocfree] branch below, so merely
   * leaking it again would be a no-op. This check sits BEFORE [ocfree]
   * so it also catches cleanup frees of NON-OC pointers, which today
   * flow to the chunk/chain/bin guards and then to newlib. If the
   * crash disappears, a cleanup free was the trigger; if it persists
   * with [free172] firing, cleanup frees are exonerated entirely.
   * Caller offset = return address - libunity virtbase (same
   * convention as the [ocfree] caller values); the range check keeps
   * non-libunity callers (mesa/driver frees through the same wrapper)
   * from ever matching by arithmetic coincidence. */
  {
    uintptr_t vb = (uintptr_t)unity_mod.load_virtbase;
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    if (vb && ra >= vb && ra < vb + (uintptr_t)unity_mod.load_size) {
      uintptr_t off = ra - vb;
      if (off == 0xC44E14 || off == 0xC44D00) {
        static unsigned f172_n = 0;
        if (f172_n++ < 128)
          debugPrintf("[free172] cleanup free(%p) caller offset 0x%lx -- leaking, NOT feeding newlib\n",
                      p, (unsigned long)off);
        return;
      }
    }
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
   * the real family (huge / misaligned / float-asset sizes).
   * Build #164 bound: test #163 proved even non-zero firings are
   * boundary artifacts -- the SAME 4 startup frees at the SAME log
   * lines and low-bit pointers read 0x0 in #162 but asset/binary
   * values in #163, so those chain positions are not allocator
   * headers at all; the walk had left the heap. The walk only goes
   * forward (sizes >= 32), so a single upper bound suffices: stop
   * (pass, silently) when the next pointer reaches the current
   * break sbrk(0). sbrk(0) just returns the cached break, so the
   * per-free cost is one call; on error it returns (void*)-1 and
   * the bound disables itself, degrading exactly to #163. This does
   * not cover mmap chunks below the break (same as #163, no
   * regression) -- only the heap-top crossing that #162/#163 hit. */
  {
    uintptr_t ch = (uintptr_t)p - 0x10;   /* chunk base: size field at p-8 */
    size_t sz = *(size_t *)(ch + 8) & ~(size_t)7;   /* own size, #161-validated */
    uintptr_t heap_hi = (uintptr_t)sbrk(0);   /* #164: current break */
    for (int link = 1; link <= 4; link++) {
      uintptr_t nxt = ch + sz;
      if (nxt >= heap_hi) break;   /* #164: left the heap -- chain end, pass */
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
  /* Build #165: bin-list guard (Option A). Test #164-first died in
   * newlib free's sorted bin insertion (aota_nx+0x92CF34, ldr x3,[x1,#8])
   * reading the size of a chunk reached via a corrupted bin fd link
   * (far 0x3e88e0003f1ed008 = two floats, the same float-pattern writer
   * family as the SMASH overruns). The chain-guard cannot catch this:
   * it validates chunk sizes along the chunk chain, not the bin lists
   * (fd at chunk+0x10, bk at chunk+0x18) that newlib walks during
   * insertion. This block replicates newlib's bin computation for the
   * freed chunk's OWN size (decoded from the #164 NRO's free():
   * small <= 0x1FF: (size>>3)+1; large: (size>>6)+0x39 for
   * 0x200..0x9FF, then by size>>9: <=0x14 -> +0x5C, <=0x54 ->
   * (size>>12)+0x6F, <=0x154 -> (size>>15)+0x78, <=0x554 ->
   * (size>>18)+0x7D, else 0x7F0; bin_ptr = mstate + ((idx & 0x1F)<<4)),
   * then walks that bin's fd chain (bounded 1024 steps, heap-bounded
   * by sbrk(0)): a link that is NULL/tiny, misaligned, past the break,
   * cyclic (bound exceeded), or whose chunk size is insane is genuine
   * corruption -- a bin fd never legitimately points there -- so log
   * and LEAK instead of feeding newlib.
   * mstate derivation: newlib's free() loads it with `adrp x7; ldr
   * x7,[x7,#off]` near its start. The guard finds that pair by
   * scanning __real_free's code at runtime (no hardcoded addresses,
   * robust to layout shifts); if the pair is not found the guard
   * disables itself and behaviour is exactly #164. The result is
   * cached (same value for every thread; a racy first write of the
   * same value is benign).
   * PARTIAL guard, stated honestly: newlib walks the bin of the
   * COALESCED size (after merging with free neighbours), which this
   * block does not replicate -- it walks the own-size bin. A bad link
   * found in ANY real bin is a true positive (never a false positive
   * from wrong-bin selection), so the gap is coverage, not correctness.
   * Non-coalescing frees (the common case) are fully covered.
   * Residual risk: a corrupted link that is 16-aligned, in-range, and
   * points at an unmapped hole inside the heap range would fault the
   * guard's own read -- the same fault newlib would hit, just
   * relocated; the observed family (misaligned / huge / NULL links)
   * is caught by the checks before any dereference. */
  {
    static uintptr_t bin_ms = 0;
    static int bin_tried = 0;
    if (!bin_tried) {
      bin_tried = 1;
      uintptr_t fn = (uintptr_t)&__real_free;
      for (uintptr_t pc = fn; pc < fn + 0x400; pc += 4) {
        uint32_t op0 = *(volatile uint32_t *)pc;
        uint32_t op1 = *(volatile uint32_t *)(pc + 4);
        if ((op0 & 0x9F00001Fu) != 0x90000007u) continue;   /* adrp x7 */
        if ((op1 & 0xFFC00000u) != 0xF9400000u) continue;   /* ldr x?,[x?,#..] */
        if ((op1 & 0x1Fu) != 7u || ((op1 >> 5) & 0x1Fu) != 7u) continue; /* x7,[x7] */
        int32_t immlo = (int32_t)((op0 >> 29) & 3u);
        int32_t immhi = (int32_t)((op0 >> 5) & 0x7FFFFu);
        int32_t imm = (immhi << 2) | immlo;
        if (imm & 0x100000) imm -= 0x200000;   /* sign-extend 21 bits */
        uintptr_t slot = (pc & ~(uintptr_t)0xFFF) + ((uintptr_t)imm << 12)
                       + (uintptr_t)(((op1 >> 10) & 0xFFFu) * 8u);
        bin_ms = *(uintptr_t *)slot;
        break;
      }
    }
    if (bin_ms != 0) {
      size_t bsz = *(size_t *)((char *)p - 8) & ~(size_t)7;  /* #161-validated */
      unsigned long idx;
      if (bsz <= 0x1FF) idx = (bsz >> 3) + 1;
      else if (bsz <= 0x9FF) idx = (bsz >> 6) + 0x39;
      else {
        unsigned long s9 = bsz >> 9;
        if (s9 <= 0x14) idx = s9 + 0x5C;
        else if (s9 <= 0x54) idx = (bsz >> 12) + 0x6F;
        else if (s9 <= 0x154) idx = (bsz >> 15) + 0x78;
        else if (s9 <= 0x554) idx = (bsz >> 18) + 0x7D;
        else idx = 0x7F0;
      }
      uintptr_t bin = bin_ms + ((idx & 0x1F) << 4);
      uintptr_t head = *(uintptr_t *)bin;
      uintptr_t marker = bin - 16;
      if (head != marker) {
        uintptr_t heap_hi = (uintptr_t)sbrk(0);
        uintptr_t cur = head;
        int bad = 0;
        for (int step = 0; step <= 1024; step++) {
          if (cur == marker) break;
          if (cur < 0x10000 || (cur & 15) != 0 || cur >= heap_hi) { bad = 1; break; }
          size_t csz2 = *(size_t *)(cur + 8) & ~(size_t)7;
          if (csz2 < 32 || (csz2 & 15) != 0 || csz2 > (size_t)0x40000000) { bad = 1; break; }
          if (step == 1024) { bad = 1; break; }   /* cycle / overlong bin */
          cur = *(uintptr_t *)(cur + 0x10);
        }
        if (bad) {
          static unsigned bn_n = 0;
          if (bn_n++ < 128)
            debugPrintf("[bin165] POISONED bin %lu free(%p) caller %p link %p -- leaking, NOT feeding newlib\n",
                        idx, p, (void *)__builtin_return_address(0), (void *)cur);
          return;
        }
      }
    }
  }
  __real_free(p);
}

/* ---- build #175: .text pattern scanner (shift-proof site lookup) --------
 * #173 failed because its site offset was hardcoded from an older NRO:
 * adding wrapper code shifts ALL mesa code, so hardcoded mesa offsets go
 * stale. Mesa .text bytes themselves are shift-invariant (mesa code shifts
 * uniformly when wrapper code grows, so intra-mesa distances -- and
 * therefore bl immediates -- never change). So #175+ locates patch sites
 * by exact byte patterns verified UNIQUE in the #174 NRO, and decodes
 * bl/adrp targets from the found instructions instead of trusting
 * constants. The #174 constants remain as fallback; the verify-first
 * stock-word check still guards every patch.
 * --------------------------------------------------------------------------- */
static const uint8_t PAT_REF_SITE[] = {
  0xa0, 0x0a, 0x40, 0xf9, 0xe1, 0x03, 0x19, 0xaa,
  0xe2, 0x2b, 0x00, 0xf9, 0xc4, 0x1d, 0x07, 0x94 }; /* ldr/mov/str/bl, bl at +12 */
static const uint8_t PAT_WALK_SITE[] = {
  0x23, 0x03, 0x00, 0x54, 0x61, 0x82, 0x00, 0x91,
  0x21, 0x00, 0x14, 0x8b, 0xab, 0x0f, 0x00, 0x94,
  0xf5, 0x03, 0x00, 0xaa, 0xc0, 0x02, 0x00, 0xb4 }; /* b.lo/add/add/bl/mov/cbz, bl at +12 */
static const uint8_t PAT_WALK_PROLOGUE[] = {
  0xfd, 0x7b, 0xb9, 0xa9, 0x23, 0x5c, 0x00, 0x91,
  0xfd, 0x03, 0x00, 0x91, 0xf3, 0x0b, 0x00, 0xf9,
  0xf3, 0x03, 0x00, 0xaa }; /* slab fn entry, 5 instrs */

/* Scan the wrapper's own .text (resolved via svcQueryMemory on a local
 * function, same as ref173_arm) for an exact pattern. Returns the
 * runtime address of the match, or 0. */
static uintptr_t text_scan(const uint8_t *pat, size_t len) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&text_scan)) || !mi.size)
    return 0;
  const uint8_t *t = (const uint8_t *)mi.addr;
  if (mi.size < len) return 0;
  for (size_t i = 0; i + len <= mi.size; i++)
    if (memcmp(t + i, pat, len) == 0) return mi.addr + i;
  return 0;
}

/* Decode an AArch64 bl's absolute target from its address + word. */
static int64_t bl_target(uintptr_t bl_addr, uint32_t w) {
  int64_t imm = (int64_t)(w & 0x3FFFFFFu);
  if (imm & 0x2000000) imm -= 0x4000000;
  return (int64_t)bl_addr + 4 * imm;
}

/* ---------------------------------------------------------------------------
 * Build #173 -- mesa refcount guard (sphaira crash, test #172).
 * Build #174 -- OFFSET CORRECTION ONLY: test #173 proved the #172 offsets
 * were stale (wrapper code growth shifted all mesa code +0x1D0 in the #173
 * NRO). SITE_OFF/REF_OFF now track the #173 layout; the stock bl word is
 * unchanged (both ends shifted equally) and the guard code is byte-identical,
 * so #174's layout equals #173's and these offsets cannot move again.
 *
 * Test #172's sphaira fault: mesa's bitmap-slot allocator (NRO+0x2fd520)
 * loaded a BO pointer from [slot+0x10] and branched to the reference-assign
 * helper (NRO+0x4c4d50), whose first ldxr (at obj+0x50) faulted on the
 * garbage value 0x004310d7fec43450. The slot struct itself was VALID
 * (count/bitmap fields read fine, a free bit was found) -- only its
 * +0x10 BO-pointer field is garbage, and the value exceeds Switch's
 * 39-bit user address space, so it is definitively not a real pointer
 * (not a stale-but-valid BO). The helper already skips NULL (cbz);
 * only NONZERO garbage faults.
 *
 * This guard does NOT patch the helper itself: it retargets the ONE
 * verified call site -- the allocator's `bl #0x4c4d50` at NRO+0x2fd640
 * (stock word 0x94071DC4, verified against the #173 NRO bytes) -- to
 * ref173_guard below. The guard validates the BO pointer against the
 * user-AS top (same 0x8000000000 bound the heap guards use): out-of-range
 * pointers are logged ([ref173], capped) and SKIPPED, so the caller's
 * new object keeps a NULL BO field instead of crashing; NULL and
 * in-range pointers call through to the real helper unchanged (NULL
 * still clears the field, exactly as the helper does today).
 *
 * The wrapper's own .text base is resolved the same way diag.c does it
 * (svcQueryMemory on a local function). The patch is verify-first: if
 * the stock word does not match, or the alias write fails, nothing is
 * changed and the build behaves exactly like #172 (original crash).
 * The patch runs single-threaded in main() before init_array, so no
 * thread can execute the site mid-patch. If the guard fires and the
 * game proceeds, this fault is survivable; if it faults elsewhere,
 * the next wall is the new data. Other call sites of the same helper
 * are NOT guarded -- a later crash at the same PC with a different
 * caller backtrace means the garbage reached another site.
 * --------------------------------------------------------------------------- */
#define REF173_SITE_OFF    0x2fd640u   /* allocator's bl to the ref helper */
#define REF173_REF_OFF     0x4c4d50u   /* the ref-assign helper itself */
#define REF173_STOCK_BL    0x94071DC4u /* bl #0x4c4d50 from 0x2fd640 */
#define REF173_USER_AS_TOP 0x8000000000ULL

typedef void (*ref173_fn_t)(void *obj, void *aux);
static ref173_fn_t ref173_real = NULL;
static unsigned ref173_n = 0;

void ref173_guard(void *obj, void *aux) {
  if ((uintptr_t)obj >= REF173_USER_AS_TOP) {
    if (ref173_n++ < 128)
      debugPrintf("[ref173] skip garbage BO %p aux %p ret %p (n=%u)\n",
                  obj, aux, __builtin_return_address(0), ref173_n);
    return;
  }
  if (ref173_real) ref173_real(obj, aux);
}

void ref173_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&ref173_arm)) || !mi.size) {
    debugPrintf("[ref173] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  /* Build #175: locate the site by pattern-scan (see scanner section
   * above); fall back to the #174 constants. Verify-first below still
   * protects against a bad site either way. */
  uintptr_t site_off = 0, real_off = 0;
  uintptr_t found = text_scan(PAT_REF_SITE, sizeof PAT_REF_SITE);
  if (found) {
    site_off = (found + 12) - base;
    real_off = (uintptr_t)bl_target(found + 12, *(volatile uint32_t *)(found + 12)) - base;
    debugPrintf("[ref173] scan: site NRO+0x%x real NRO+0x%x\n", site_off, real_off);
  } else {
    debugPrintf("[ref173] scan MISS, falling back to #174 constants\n");
    site_off = REF173_SITE_OFF; real_off = REF173_REF_OFF;
  }
  volatile uint32_t *site = (volatile uint32_t *)(base + site_off);
  uint32_t stock = *site;
  if (stock != REF173_STOCK_BL) {
    debugPrintf("[ref173] site word mismatch (got %08x, want %08x), patch skipped\n",
                stock, REF173_STOCK_BL);
    return;
  }
  ref173_real = (ref173_fn_t)(base + real_off);
  int64_t diff = (int64_t)(uintptr_t)&ref173_guard - (int64_t)(base + site_off);
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[ref173] guard out of bl range (diff %lld), patch skipped\n",
                (long long)diff);
    ref173_real = NULL;
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)site, &nw, sizeof nw) != 0) {
    debugPrintf("[ref173] so_patch_code FAILED, patch skipped\n");
    ref173_real = NULL;
    return;
  }
  debugPrintf("[ref173] armed: site NRO+0x%x -> guard %p (real refcount %p)\n",
              site_off, (void *)&ref173_guard, (void *)ref173_real);
}

/* ---- build #175: slab free-list pre-validation guard --------------------
 * TEST #174's new sphaira wall: the slab/size-class freelist allocator
 * (fn at #174 NRO+0x92cf80, global descriptor from slot NRO+0x140fa50,
 * bitmap of non-empty classes at [desc+8], per-class CIRCULAR doubly-
 * linked free lists: node +8 = size tag with low-2-bit flags, +0x10 =
 * prev, +0x18 = next) faulted walking a list whose node next pointer
 * was overwritten with float data (0.0f/-1.0f). The guard retargets
 * the ONE observed call site -- the allocation wrapper's `bl` to the
 * slab fn (pattern PAT_WALK_SITE, #174 site NRO+0x9290d4, stock word
 * 0x94000FAB) -- to walk175_guard below. The guard pre-validates ALL
 * free lists (bitmap-gated per-class lists + the [desc+0x20] head list)
 * in C with a bounded node budget, range checks, and an
 * svcQueryMemory check before EVERY dereference, so a garbage pointer
 * can never fault the guard itself. On corruption it logs ([walk175],
 * capped) and returns NULL -- the wrapper NULL-handles (its cbz path)
 * -- instead of faulting. On truncation (budget out, i.e. lists too
 * large to fully validate) it CALLS THROUGH with a per-list log
 * (build #176: NULLing on truncation aborted healthy runs). Clean
 * lists call through unchanged. Build #177: validation is SAMPLED
 * (1 in WALK175_SAMPLE_EVERY calls) -- test #176-long proved
 * every-call validation drowned IL2CPP init in QueryMemory calls
 * (main thread sampled inside the guard's QueryMemory loop across
 * 15 min); corruption persists across calls, so a sampled call still
 * catches it. Other call sites of the slab fn are NOT guarded. The
 * guard runs under the same locks as the call it replaces (it IS the
 * call, retargeted), and the patch runs single-threaded in main()
 * before init_array.
 * --------------------------------------------------------------------------- */
#define WALK175_SITE_OFF_FALLBACK 0x9290d4u
#define WALK175_FN_OFF_FALLBACK   0x92cf80u
#define WALK175_STOCK_BL          0x94000FABU
#define WALK175_AS_TOP            0x8000000000ULL
#define WALK175_MAX_TOTAL         16384  /* build #176: was 2048; #175 truncated twice on healthy lists */
#define WALK175_LOG_CAP           32
#define WALK175_SAMPLE_EVERY      32  /* build #177: validate 1 in 32 calls */

typedef void *(*walk175_fn_t)(void *ctx, uintptr_t size);
static walk175_fn_t walk175_real = NULL;
static uintptr_t walk175_base = 0;
static uintptr_t walk175_slot_off = 0;   /* 0 = unknown -> guard passes through */
static unsigned walk175_n = 0;           /* corruption/truncation events (log capped) */
static unsigned walk175_trunc_n = 0;
static unsigned walk175_calls = 0;     /* build #177: sampling counter (lock-free, see guard) */

static void walk175_log_bad(uintptr_t cur, uintptr_t nxt, uintptr_t head) {
  if (walk175_n < WALK175_LOG_CAP)
    debugPrintf("[walk175] corrupt list node %p next %p head %p (n=%u)\n",
                (void *)cur, (void *)nxt, (void *)head, walk175_n + 1);
}

/* Validate one circular list: first node -> ... -> head. Returns 1 clean,
 * 0 corrupt, -1 truncated (budget out -- NOT corruption). Never
 * dereferences an unvalidated pointer: every node is svcQueryMemory'd
 * first, and the +0x18 read is bounds-checked against that query. */
static int walk175_list_ok(uintptr_t first, uintptr_t head, unsigned *budget,
                           unsigned *nodes_out, int cls) {
  uintptr_t cur = first;
  int started = 0;  /* build #176: cycle detection -- see below */
  while (cur != head) {
    /* A list that returns to its first node without reaching the head
     * sentinel is a detached cycle (corrupt), NOT a budget truncation:
     * without this, a cycle just burns the budget and looks like trunc. */
    if (started && cur == first) {
      if (walk175_n < WALK175_LOG_CAP)
        debugPrintf("[walk175] corrupt list CYCLE back to first %p head %p class %d\n",
                    (void *)first, (void *)head, cls);
      return 0;
    }
    started = 1;
    if (!*budget) return -1;
    (*budget)--;
    if (nodes_out) (*nodes_out)++;
    if (!cur || cur >= WALK175_AS_TOP) { walk175_log_bad(cur, 0, head); return 0; }
    MemoryInfo mi; u32 pi;
    if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)cur)) ||
        mi.addr > cur || cur + 0x18 >= mi.addr + mi.size) {
      walk175_log_bad(cur, 0, head); return 0;
    }
    uintptr_t nxt = *(volatile uintptr_t *)(cur + 0x18);
    if (!nxt || nxt >= WALK175_AS_TOP) { walk175_log_bad(cur, nxt, head); return 0; }
    cur = nxt;
  }
  return 1;
}

void *walk175_guard(void *ctx, uintptr_t size) {
  if (walk175_real && walk175_slot_off && walk175_base) {
    uintptr_t desc = *(volatile uintptr_t *)(walk175_base + walk175_slot_off);
    if (desc) {
      MemoryInfo mi; u32 pi;
      int desc_ok = R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)desc)) &&
                    mi.addr <= desc && desc + 0x400 <= mi.addr + mi.size;
      if (!desc_ok) {
        if (walk175_n < WALK175_LOG_CAP)
          debugPrintf("[walk175] corrupt descriptor %p, returning NULL (n=%u)\n",
                      (void *)desc, walk175_n + 1);
        walk175_n++;
        return NULL;
      }
      /* Build #177: SAMPLED validation. Test #176-long proved
       * every-call validation drowned IL2CPP init in QueryMemory
       * calls (main thread sampled inside the guard's QueryMemory
       * loop across 15 min, from one IL2CPP init allocation loop).
       * Corruption persists across calls, so a sampled call still
       * catches it; unsampled calls go straight through at full
       * speed. The counter is deliberately lock-free: a torn
       * increment only shifts which calls are sampled, and taking
       * a lock inside the allocator guard could deadlock. */
      if ((++walk175_calls % WALK175_SAMPLE_EVERY) != 0)
        return walk175_real(ctx, size);
      unsigned budget = WALK175_MAX_TOTAL;
      int bad = 0, trunc = 0;
      int trunc_class = -1;  /* build #176: -1 = head list, else class index */
      uintptr_t trunc_head = 0;
      unsigned trunc_nodes = 0;
      /* (a) head list: [desc+0x20], sentinel desc+0x10. */
      uintptr_t h = *(volatile uintptr_t *)(desc + 0x20);
      if (h != desc + 0x10) {
        unsigned nn = 0;
        int r = walk175_list_ok(h, desc + 0x10, &budget, &nn, -1);
        if (r == 0) bad = 1;
        else if (r < 0) { trunc = 1; trunc_class = -1; trunc_head = desc + 0x10; trunc_nodes = nn; }
      }
      /* (b) per-class lists, bitmap-gated: bit (i>>2) of [desc+8]. */
      if (!bad) {
        uint64_t bm = *(volatile uint64_t *)(desc + 8);
        for (int i = 0; i <= 62 && !bad && !trunc; i++) {
          if (!((bm >> (i >> 2)) & 1)) continue;
          uintptr_t el = desc + (uintptr_t)i * 16;
          if (el + 0x18 >= mi.addr + mi.size) continue;
          uintptr_t first = *(volatile uintptr_t *)(el + 0x18);
          if (first == el) continue; /* empty */
          unsigned nn = 0;
          int r = walk175_list_ok(first, el, &budget, &nn, i);
          if (r == 0) bad = 1;
          else if (r < 0) { trunc = 1; trunc_class = i; trunc_head = el; trunc_nodes = nn; }
        }
      }
      if (bad) {
        /* TRUE corruption only: NULL beats a fault. */
        walk175_n++;
        return NULL;
      }
      if (trunc) {
        /* Build #176 (regression fix): truncation is NOT corruption.
         * A healthy huge list must not be NULLed -- call through and
         * log which list ran out of budget, so the next log shows
         * whether 16384 is finally enough. */
        if (walk175_trunc_n++ < 4)
          debugPrintf("[walk175] truncated (budget) class %d head %p nodes %u, CALLING THROUGH\n",
                      trunc_class, (void *)trunc_head, trunc_nodes);
        /* fall through to walk175_real below */
      }
    }
    /* desc == 0: pre-init. The real allocator inits first, then walks
     * fresh (empty) lists -- nothing to validate yet. Fall through. */
  }
  if (walk175_real) return walk175_real(ctx, size);
  return NULL;
}

void walk175_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&walk175_arm)) || !mi.size) {
    debugPrintf("[walk175] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  walk175_base = base;
  uintptr_t site_off = 0, fn_off = 0;
  uintptr_t found = text_scan(PAT_WALK_SITE, sizeof PAT_WALK_SITE);
  if (found) {
    site_off = (found + 12) - base;
    uintptr_t tgt = (uintptr_t)bl_target(found + 12, *(volatile uint32_t *)(found + 12));
    fn_off = tgt - base;
    if (memcmp((const void *)tgt, PAT_WALK_PROLOGUE, sizeof PAT_WALK_PROLOGUE) != 0) {
      debugPrintf("[walk175] scan target prologue MISMATCH at NRO+0x%x, falling back\n", fn_off);
      found = 0;
    } else {
      debugPrintf("[walk175] scan: site NRO+0x%x fn NRO+0x%x\n", site_off, fn_off);
    }
  }
  if (!found) {
    debugPrintf("[walk175] scan MISS, falling back to #174 constants\n");
    site_off = WALK175_SITE_OFF_FALLBACK; fn_off = WALK175_FN_OFF_FALLBACK;
  }
  /* Decode the descriptor slot from the slab fn's adrp+ldr (+0x34/+0x38).
   * adrp: (w & 0x9F000000) == 0x90000000; ldr x8,[x8,#off]: 64-bit
   * unsigned-offset ldr with Rt == Rn == 8. */
  uintptr_t fn = base + fn_off;
  uint32_t aw = *(volatile uint32_t *)(fn + 0x34);
  uint32_t lw = *(volatile uint32_t *)(fn + 0x38);
  if ((aw & 0x9F000000u) == 0x90000000u && (lw & 0xFFC00000u) == 0xF9400000u &&
      (lw & 0x1Fu) == 8 && ((lw >> 5) & 0x1Fu) == 8) {
    int64_t imm = (int64_t)((((aw >> 5) & 0x7FFFFu) << 2) | ((aw >> 29) & 0x3u));
    if (imm & 0x200000) imm -= 0x400000;
    uintptr_t page = (fn + 0x34) & ~(uintptr_t)0xFFF;
    uintptr_t slot = page + (uintptr_t)(imm << 12) + (((lw >> 10) & 0xFFFu) << 3);
    walk175_slot_off = slot - base;
    debugPrintf("[walk175] desc slot NRO+0x%x\n", walk175_slot_off);
  } else {
    debugPrintf("[walk175] desc slot decode FAILED (aw %08x lw %08x), guard passes through\n",
                aw, lw);
    walk175_slot_off = 0;
  }
  volatile uint32_t *site = (volatile uint32_t *)(base + site_off);
  uint32_t stock = *site;
  if (stock != WALK175_STOCK_BL) {
    debugPrintf("[walk175] site word mismatch (got %08x, want %08x), patch skipped\n",
                stock, WALK175_STOCK_BL);
    return;
  }
  walk175_real = (walk175_fn_t)(base + fn_off);
  int64_t diff = (int64_t)(uintptr_t)&walk175_guard - (int64_t)(base + site_off);
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[walk175] guard out of bl range (diff %lld), patch skipped\n",
                (long long)diff);
    walk175_real = NULL;
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)site, &nw, sizeof nw) != 0) {
    debugPrintf("[walk175] so_patch_code FAILED, patch skipped\n");
    walk175_real = NULL;
    return;
  }
  debugPrintf("[walk175] armed: site NRO+0x%x -> guard %p (real slab %p, desc slot NRO+0x%x)\n",
              site_off, (void *)&walk175_guard, (void *)walk175_real, walk175_slot_off);
}

/* ---------------------------------------------------------------------------
 * Build #178 -- slab FREE-path double-free guard (test #177's cycle hunt).
 *
 * Test #177 caught a REAL detached cycle in a slab free list, then faulted
 * 6 lines later in a mesa consumer (NRO+0x91ebb8) that dereferences its
 * arg1+0xb0 with no NULL check -- most plausibly the walk175 guard's
 * corrupt->NULL return propagated unchecked. Returning NULL on corruption
 * is therefore itself a crash vector, so #178 does NOT change the alloc
 * guard's corrupt handling. Instead it attacks the cycle's most likely
 * writer: a DOUBLE-FREE. A clean cycle back to FIRST is what inserting
 * the same block twice produces (mesa's free does not check); a float
 * overwrite (#174) breaks links with garbage, it does not make a clean
 * pointer cycle.
 *
 * Mesa is PREBUILT here (mesa-switch SDK, libvulkan.a -- see build.yml),
 * so this guard is binary patching like walk175/ref173, not a source
 * edit. The slab free fn (entry NRO+0x92f880 in #177: cbz x1 NULL-check,
 * prologue, mutex lock, coalescing free that unlinks + re-inserts the
 * merged block) is called from 37 bl sites -- too many to retarget one
 * by one -- so #178 patches the fn ENTRY itself: its first word (the
 * cbz) becomes `b free178_guard`, covering ALL callers with one patch.
 * The guard replicates the entry cbz (NULL free is a no-op, returning
 * ctx exactly as the real fn does), then walks the free lists looking
 * for the block being freed. If the block is ALREADY in a list, this
 * is a double-free: log it ([free178], capped, with block, class, and
 * the mesa caller return address so the culprit call site can be
 * decoded offline) and SKIP the real free -- the block stays freed
 * exactly once, so the cycle is never created. Skipping is safe by
 * construction: a block re-allocated between two frees is NOT in any
 * list (alloc removed it), so a legitimate free is never skipped; only
 * a proven duplicate is. If the walk goes bad (wild pointer, budget
 * out) the guard does NOT skip -- it logs and calls through, because
 * an unproven duplicate must not leak a legitimate free.
 *
 * The walk is deliberately SYSCALL-FREE (range + alignment + node bound
 * only, no QueryMemory per node): the #176 validation storm was the
 * syscalls, not the pointer chasing, and frees may become frequent
 * later -- one QueryMemory per free (for the descriptor only) is
 * affordable, per-node syscalls are not. Residual risk: a corrupt
 * list pointer that is in-range and aligned but unmapped could fault
 * the guard itself; that fault's [xd] shows guard code (identifiable),
 * and the list was already corrupt -- the game was doomed anyway.
 * The free fn's entry pattern (24 bytes: cbz + prologue, no bl) is
 * verified UNIQUE in the #177 NRO; the #177 entry offset remains as
 * fallback with the verify-first stock-word check. The descriptor slot
 * is decoded from the free fn's own adrp+ldr (+0x20/+0x24, x7), so
 * this guard is self-contained and does not depend on walk175_arm's
 * ordering. The real free is entered at entry+4 (the prologue) with
 * the original (ctx, ptr) -- the guard's early NULL return covers the
 * displaced cbz, so NULL never reaches the prologue body.
 * --------------------------------------------------------------------------- */
#define FREE178_ENTRY_OFF_FALLBACK 0x92f880u
#define FREE178_STOCK_CBZ          0xB4000901u /* cbz x1, #+0x120 */
static const uint8_t PAT_FREE178_ENTRY[] = {
  0x01, 0x09, 0x00, 0xb4, 0xfd, 0x7b, 0xbd, 0xa9,
  0xfd, 0x03, 0x00, 0x91, 0xf3, 0x0b, 0x00, 0xf9,
  0xf3, 0x03, 0x00, 0xaa, 0xe1, 0x17, 0x00, 0xf9 }; /* cbz/stp/mov/str/mov/str */

typedef void *(*free178_fn_t)(void *ctx, void *ptr);
static free178_fn_t free178_real = NULL;
static uintptr_t free178_base = 0;
static uintptr_t free178_entry = 0;
static uintptr_t free178_slot_off = 0;   /* 0 = unknown -> guard passes through */
static unsigned free178_n = 0;           /* double-free events (log capped) */

/* Walk one circular list (first -> ... -> head) looking for block.
 * Returns 1 found, 0 not found, -1 bad pointer, -2 budget out.
 * Syscall-free by design (see the #178 header): range + alignment +
 * shared node budget only. Never skips on -1/-2 -- only on a proven 1. */
static int free178_contains(uintptr_t first, uintptr_t head, uintptr_t block,
                            unsigned *budget) {
  uintptr_t cur = first;
  while (cur != head) {
    if (!*budget) return -2;
    (*budget)--;
    if (!cur || cur >= WALK175_AS_TOP || (cur & 7)) return -1;
    if (cur == block) return 1;
    cur = *(volatile uintptr_t *)(cur + 0x18);
  }
  return 0;
}

void *free178_guard(void *ctx, void *ptr) {
  if (!ptr) return ctx; /* replicate the displaced entry cbz */
  if (free178_real && free178_slot_off && free178_base) {
    uintptr_t desc = *(volatile uintptr_t *)(free178_base + free178_slot_off);
    if (desc) {
      MemoryInfo mi; u32 pi;
      int desc_ok = R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)desc)) &&
                    mi.addr <= desc && desc + 0x400 <= mi.addr + mi.size;
      if (desc_ok) {
        uintptr_t block = (uintptr_t)ptr - 0x10;
        unsigned budget = WALK175_MAX_TOTAL;
        int found_cls = -2; /* -2 = not found, -1 = head list, else class */
        int walk_bad = 0, walk_bad_cls = -2;
        uintptr_t h = *(volatile uintptr_t *)(desc + 0x20);
        if (h != desc + 0x10) {
          int r = free178_contains(h, desc + 0x10, block, &budget);
          if (r == 1) found_cls = -1;
          else if (r < 0) { walk_bad = 1; walk_bad_cls = -1; }
        }
        if (found_cls == -2 && !walk_bad) {
          uint64_t bm = *(volatile uint64_t *)(desc + 8);
          for (int i = 0; i <= 62 && found_cls == -2 && !walk_bad; i++) {
            if (!((bm >> (i >> 2)) & 1)) continue;
            uintptr_t el = desc + (uintptr_t)i * 16;
            if (el + 0x18 >= mi.addr + mi.size) continue;
            uintptr_t first = *(volatile uintptr_t *)(el + 0x18);
            if (first == el) continue; /* empty */
            int r = free178_contains(first, el, block, &budget);
            if (r == 1) found_cls = i;
            else if (r < 0) { walk_bad = 1; walk_bad_cls = i; }
          }
        }
        if (walk_bad) {
          if (free178_n < WALK175_LOG_CAP)
            debugPrintf("[free178] walk bad class %d block %p, NOT skipping (n=%u)\n",
                        walk_bad_cls, (void *)block, free178_n + 1);
          /* fall through to the real free: never skip on unproven evidence */
        } else if (found_cls != -2) {
          if (free178_n < WALK175_LOG_CAP)
            debugPrintf("[free178] DOUBLE-FREE block %p class %d caller %p (n=%u)\n",
                        (void *)block, found_cls, __builtin_return_address(0), free178_n + 1);
          free178_n++;
          return ctx; /* skip the second insert: freed exactly once */
        }
      }
      /* desc unmapped: fall through to the real free */
    }
    /* desc == 0: pre-init: fall through */
  }
  if (free178_real) return free178_real(ctx, ptr);
  return ctx;
}

void free178_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&free178_arm)) || !mi.size) {
    debugPrintf("[free178] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  free178_base = base;
  uintptr_t entry_off = 0;
  uintptr_t found = text_scan(PAT_FREE178_ENTRY, sizeof PAT_FREE178_ENTRY);
  if (found) {
    entry_off = found - base;
    debugPrintf("[free178] scan: entry NRO+0x%x\n", entry_off);
  } else {
    debugPrintf("[free178] scan MISS, falling back to #177 constant\n");
    entry_off = FREE178_ENTRY_OFF_FALLBACK;
  }
  /* Decode the descriptor slot from the free fn's adrp+ldr (+0x20/+0x24, x7). */
  uintptr_t entry = base + entry_off;
  uint32_t aw = *(volatile uint32_t *)(entry + 0x20);
  uint32_t lw = *(volatile uint32_t *)(entry + 0x24);
  if ((aw & 0x9F000000u) == 0x90000000u && (lw & 0xFFC00000u) == 0xF9400000u &&
      (lw & 0x1Fu) == 7 && ((lw >> 5) & 0x1Fu) == 7) {
    int64_t imm = (int64_t)((((aw >> 5) & 0x7FFFFu) << 2) | ((aw >> 29) & 0x3u));
    if (imm & 0x200000) imm -= 0x400000;
    uintptr_t page = (entry + 0x20) & ~(uintptr_t)0xFFF;
    uintptr_t slot = page + (uintptr_t)(imm << 12) + (((lw >> 10) & 0xFFFu) << 3);
    free178_slot_off = slot - base;
    debugPrintf("[free178] desc slot NRO+0x%x\n", free178_slot_off);
  } else {
    debugPrintf("[free178] desc slot decode FAILED (aw %08x lw %08x), guard passes through\n",
                aw, lw);
    free178_slot_off = 0;
  }
  volatile uint32_t *ep = (volatile uint32_t *)entry;
  uint32_t stock = *ep;
  if (stock != FREE178_STOCK_CBZ) {
    debugPrintf("[free178] entry word mismatch (got %08x, want %08x), patch skipped\n",
                stock, FREE178_STOCK_CBZ);
    return;
  }
  free178_real = (free178_fn_t)(entry + 4);
  int64_t diff = (int64_t)(uintptr_t)&free178_guard - (int64_t)entry;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[free178] guard out of b range (diff %lld), patch skipped\n",
                (long long)diff);
    free178_real = NULL;
    return;
  }
  uint32_t nw = 0x14000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)ep, &nw, sizeof nw) != 0) {
    debugPrintf("[free178] so_patch_code FAILED, patch skipped\n");
    free178_real = NULL;
    return;
  }
  free178_entry = entry;
  debugPrintf("[free178] armed: entry NRO+0x%x -> guard %p (real free+4 %p, desc slot NRO+0x%x)\n",
              entry_off, (void *)&free178_guard, (void *)free178_real, free178_slot_off);
}

/* ---------------------------------------------------------------------------
 * Build #179 -- diagnostic mutex logging (fullram frame-1 stall decode).
 *
 * The #178 fullram run parks its main thread in the wrapper's kernel mutex
 * lock (svc #0x1a) via a virtual call from Unity's render loop, stably from
 * stall #20 to #40, while the job system never completes a job (compl=0 on
 * LIVE hooks: the #120 complete hook is armed, its prologue matches the
 * game's libunity byte-for-byte, and push/sched move -- so compl=0 is real,
 * not a snoop misread). The lock's address and holder are invisible in
 * #178's log (the wrapper logs no mutex operations), so this build logs
 * ONLY contended waits -- the sleep path, never every lock/unlock (which
 * would flood the log) -- for two sites:
 *   (a) the mutex lock's bl to the svc #0x1a stub (the park site), and
 *   (b) the sync-object wait's bl to the svc #0x1c stub (the transitional
 *       wait the main thread was in at stall #10, and sphaira at #40).
 * Each site is retargeted to a naked trampoline that logs (lock/obj,
 * holder/value, caller) then jumps to the real svc stub, preserving the
 * svc args (x0-x2) and x30, so the wait itself is unchanged. The caller is
 * the lock/wrapper function's saved x30 at [sp+8]: both functions save
 * x29/x30 as their first frame action (stp ... [sp, #-0x20]! / #-0x30]!),
 * and the mutex lock's retry loop reuses that frame (it jumps to the
 * post-stp instruction), so [sp+8] is the saved x30 on every sleep.
 * Pattern-scan (.text, shift-invariant, verified unique in the #178 NRO)
 * + verify-first (the bl word must be a bl whose target decodes to the
 * expected svc stub); on any miss that site is left unpatched and the
 * other still arms. NOTE on opcodes: the replaced instruction is a BL, so
 * the new word uses the BL base 0x94000000 -- NOT the B base 0x14000000
 * used by free178 (which replaces a cbz, a branch). Using B here would
 * leave x30 unset and the svc stub's ret would skip the lock function's
 * post-wait code. The loggers are __attribute__((used)): they are
 * referenced ONLY from bare asm strings in the trampolines, which the
 * compiler cannot see (build #154 lesson); without used they may be
 * discarded as unused.
 * ------------------------------------------------------------------------- */
#define MUTEX179_LOG_CAP 64
static unsigned mutex179_n = 0;
/* Written in C (mutex179_arm) but read ONLY from trampoline asm strings,
 * so the compiler cannot see the reads (build #154 lesson, and the run
 * #182 link failure: without used, GCC discards these as unused and the
 * link fails with "undefined reference to mutex179_svc1a"). */
__attribute__((used)) static uintptr_t mutex179_svc1a = 0;
__attribute__((used)) static uintptr_t mutex179_svc1c = 0;
static const uint8_t PAT_MUTEX179_LOCK[] = {
  0xfd, 0x7b, 0xbe, 0xa9, 0xfd, 0x03, 0x00, 0x91,
  0xe2, 0x03, 0x04, 0x2a, 0xe1, 0x03, 0x03, 0xaa,
  0x00, 0x78, 0x01, 0x12, 0xe3, 0x0b, 0x00, 0xf9,
  0xe4, 0x1b, 0x00, 0xb9 }; /* lock fn contended path, bl at +28 */
static const uint8_t PAT_MUTEX179_SYNC[] = {
  0xfd, 0x7b, 0xbd, 0xa9, 0xfd, 0x03, 0x00, 0x91,
  0xe4, 0x03, 0x01, 0xaa, 0xe3, 0x03, 0x02, 0xaa,
  0xf3, 0x0b, 0x00, 0xf9, 0xf3, 0x03, 0x01, 0xaa,
  0x61, 0xd0, 0x3b, 0xd5, 0x22, 0xe4, 0x41, 0xb9,
  0xe1, 0x03, 0x00, 0xaa, 0xe0, 0x03, 0x04, 0xaa }; /* syncwait wrapper, bl at +40 */
static const uint8_t PAT_MUTEX179_SVC1A[] = {
  0x41, 0x03, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6 }; /* svc #0x1a; ret */
static const uint8_t PAT_MUTEX179_SVC1C[] = {
  0x81, 0x03, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6 }; /* svc #0x1c; ret */

__attribute__((used)) static void mutex179_log_wait(uintptr_t lock, uintptr_t holder, uintptr_t caller) {
  if (mutex179_n < MUTEX179_LOG_CAP)
    debugPrintf("[mutex179] wait lock=%p holder=%llu caller=%p (n=%u)\n",
                (void *)lock, (unsigned long long)holder, (void *)caller, mutex179_n);
  mutex179_n++;
}

__attribute__((used)) static void mutex179_log_sync(uintptr_t obj, uintptr_t val, uintptr_t caller) {
  if (mutex179_n < MUTEX179_LOG_CAP)
    debugPrintf("[mutex179] syncwait obj=%p val=%llu caller=%p (n=%u)\n",
                (void *)obj, (unsigned long long)val, (void *)caller, mutex179_n);
  mutex179_n++;
}

__attribute__((naked, used)) static void mutex179_tramp_wait(void) {
  __asm__ volatile(
    "ldr x3, [sp, #8]\n"
    "stp x0, x1, [sp, #-0x20]!\n"
    "stp x2, x30, [sp, #0x10]\n"
    "mov x4, x0\n"
    "mov x0, x1\n"
    "mov x1, x4\n"
    "mov x2, x3\n"
    "bl mutex179_log_wait\n"
    "ldp x2, x30, [sp, #0x10]\n"
    "ldp x0, x1, [sp], #0x20\n"
    "adrp x16, mutex179_svc1a\n"
    "ldr x16, [x16, :lo12:mutex179_svc1a]\n"
    "br x16\n"
  );
}

__attribute__((naked, used)) static void mutex179_tramp_sync(void) {
  __asm__ volatile(
    "ldr x3, [sp, #8]\n"
    "stp x0, x1, [sp, #-0x20]!\n"
    "stp x2, x30, [sp, #0x10]\n"
    "mov x4, x0\n"
    "mov x0, x1\n"
    "mov x1, x4\n"
    "mov x2, x3\n"
    "bl mutex179_log_sync\n"
    "ldp x2, x30, [sp, #0x10]\n"
    "ldp x0, x1, [sp], #0x20\n"
    "adrp x16, mutex179_svc1c\n"
    "ldr x16, [x16, :lo12:mutex179_svc1c]\n"
    "br x16\n"
  );
}

void mutex179_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&mutex179_arm)) || !mi.size) {
    debugPrintf("[mutex179] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t s1a = text_scan(PAT_MUTEX179_SVC1A, sizeof PAT_MUTEX179_SVC1A);
  uintptr_t s1c = text_scan(PAT_MUTEX179_SVC1C, sizeof PAT_MUTEX179_SVC1C);
  if (s1a) {
    mutex179_svc1a = s1a;
    debugPrintf("[mutex179] svc #0x1a stub NRO+0x%x\n", s1a - base);
  } else {
    debugPrintf("[mutex179] svc #0x1a stub scan MISS\n");
  }
  if (s1c) {
    mutex179_svc1c = s1c;
    debugPrintf("[mutex179] svc #0x1c stub NRO+0x%x\n", s1c - base);
  } else {
    debugPrintf("[mutex179] svc #0x1c stub scan MISS\n");
  }
  uintptr_t found = text_scan(PAT_MUTEX179_LOCK, sizeof PAT_MUTEX179_LOCK);
  if (found && s1a) {
    uintptr_t bl = found + sizeof PAT_MUTEX179_LOCK;
    uint32_t w = *(volatile uint32_t *)bl;
    if ((w & 0xFC000000u) == 0x94000000u && (uintptr_t)bl_target(bl, w) == s1a) {
      int64_t diff = (int64_t)(uintptr_t)&mutex179_tramp_wait - (int64_t)bl;
      if (!(diff & 3) && diff >= -(128 * 1024 * 1024) && diff < (128 * 1024 * 1024)) {
        uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
        if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
          debugPrintf("[mutex179] armed wait: bl NRO+0x%x -> tramp %p (svc stub NRO+0x%x)\n",
                      bl - base, (void *)&mutex179_tramp_wait, s1a - base);
        else
          debugPrintf("[mutex179] wait so_patch_code FAILED\n");
      } else {
        debugPrintf("[mutex179] wait tramp out of bl range\n");
      }
    } else {
      debugPrintf("[mutex179] wait bl target mismatch (word %08x target %p want %p), patch skipped\n",
                  w, (void *)(uintptr_t)bl_target(bl, w), (void *)s1a);
    }
  } else {
    debugPrintf("[mutex179] wait site scan MISS or svc stub missing, patch skipped\n");
  }
  found = text_scan(PAT_MUTEX179_SYNC, sizeof PAT_MUTEX179_SYNC);
  if (found && s1c) {
    uintptr_t bl = found + sizeof PAT_MUTEX179_SYNC;
    uint32_t w = *(volatile uint32_t *)bl;
    if ((w & 0xFC000000u) == 0x94000000u && (uintptr_t)bl_target(bl, w) == s1c) {
      int64_t diff = (int64_t)(uintptr_t)&mutex179_tramp_sync - (int64_t)bl;
      if (!(diff & 3) && diff >= -(128 * 1024 * 1024) && diff < (128 * 1024 * 1024)) {
        uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
        if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
          debugPrintf("[mutex179] armed syncwait: bl NRO+0x%x -> tramp %p (svc stub NRO+0x%x)\n",
                      bl - base, (void *)&mutex179_tramp_sync, s1c - base);
        else
          debugPrintf("[mutex179] syncwait so_patch_code FAILED\n");
      } else {
        debugPrintf("[mutex179] syncwait tramp out of bl range\n");
      }
    } else {
      debugPrintf("[mutex179] syncwait bl target mismatch (word %08x target %p want %p), patch skipped\n",
                  w, (void *)(uintptr_t)bl_target(bl, w), (void *)s1c);
    }
  } else {
    debugPrintf("[mutex179] syncwait site scan MISS or svc stub missing, patch skipped\n");
  }
}

/* ---- contended-unlock logging (build #180) -------------------------------
 * Test #179 parked both modes in the mesa mutex (lock fn 0x8ec080 in the
 * #179 layout): fullram 1 wait, holder 33279 never released in 10 min;
 * sphaira 4 waits, same lock, holders alternating 33279/3670491. The
 * question #179 left open is whether the holder EVER releases. This
 * section logs ONLY contended unlocks -- the wake path of the mutex
 * unlock fn, taken when the old lock word had the waiters bit set
 * (0x40000000), i.e. exactly when a waiter was parked on the lock.
 * Uncontended unlocks (the common case) are never logged, so the log
 * cannot flood. Same pattern-scan + verify-first + bl-retarget technique
 * as mutex179; the unlock fn's entry pattern is layout-independent
 * (all immediates inside it are relative within the fn) and verified
 * unique (1 match) in NRO #179.
 *
 * Unlock fn (NRO #179 layout, 0x8ec180): only the owner (tid from TLS
 * [tpidrro+0x1e4]) may store 0; if the old word had the waiters bit,
 * it calls the wake stub (svc #0x1b; ret, 8 bytes 610300d4c0035fd6).
 * The patched bl is at fn_start + 0x30.
 * At the bl site: x0 = lock address, x2 = unlocking thread's tid
 * (w2, from TLS, unmodified through the fn). The trampoline preserves
 * x0-x2 + x30, logs, then branches to the real wake stub, whose ret
 * returns to the original return address (restored x30).
 * Globals read only from trampoline asm MUST be __attribute__((used)):
 * without it GCC discards them as unused and the link fails with
 * "undefined reference" -- the run #182 failure (build #179), same
 * #154 trap. */

#define MUTEX180_LOG_CAP 64
__attribute__((used)) static uintptr_t mutex180_svc_wake = 0;
static unsigned mutex180_n = 0;

static const uint8_t PAT_MUTEX180_UNLOCK[] = {
  /* unlock fn entry, NRO #179 0x8ec180..0x8ec1ab (44 bytes, through the
   * wake block's stp; the bl at +0x30 is excluded: its immediate is
   * layout-dependent since the stub lives in another region). */
  0x61, 0xd0, 0x3b, 0xd5, 0x22, 0xe4, 0x41, 0xb9, 0x01, 0xfc, 0x5f, 0x88,
  0x03, 0x00, 0x80, 0x52, 0x3f, 0x00, 0x02, 0x6b, 0x61, 0x02, 0x00, 0x54,
  0x03, 0xfc, 0x04, 0x88, 0xc4, 0x01, 0x00, 0x35, 0x41, 0x00, 0xf0, 0x37,
  0xc0, 0x03, 0x5f, 0xd6, 0xfd, 0x7b, 0xbf, 0xa9
};

__attribute__((used)) void mutex180_log_unlock(void *lock, unsigned long long by) {
  if (mutex180_n >= MUTEX180_LOG_CAP) return;
  debugPrintf("[mutex180] unlock lock=%p by=%llu (n=%u)\n", lock, by, mutex180_n++);
}

__attribute__((naked, used)) void mutex180_tramp_unlock(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x1, x2\n"
    "bl mutex180_log_unlock\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, mutex180_svc_wake\n"
    "ldr x16, [x16, :lo12:mutex180_svc_wake]\n"
    "br x16\n"
  );
}

void mutex180_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&mutex180_arm)) || !mi.size) {
    debugPrintf("[mutex180] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t found = text_scan(PAT_MUTEX180_UNLOCK, sizeof PAT_MUTEX180_UNLOCK);
  if (!found) {
    debugPrintf("[mutex180] unlock site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = found + 0x30;
  uint32_t w = *(volatile uint32_t *)bl;
  if ((w & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[mutex180] unlock bl not BL (word %08x), patch skipped\n", w);
    return;
  }
  uintptr_t tgt = (uintptr_t)bl_target(bl, w);
  uint32_t tw0 = *(volatile uint32_t *)tgt;
  uint32_t tw1 = *(volatile uint32_t *)(tgt + 4);
  if ((tw0 & 0xFFE0001Fu) != 0xD4000001u || tw1 != 0xD65F03C0u) {
    debugPrintf("[mutex180] unlock bl target not svc stub (words %08x %08x), patch skipped\n", tw0, tw1);
    return;
  }
  mutex180_svc_wake = tgt;
  debugPrintf("[mutex180] svc #0x1b stub NRO+0x%x\n", tgt - base);
  int64_t diff = (int64_t)(uintptr_t)&mutex180_tramp_unlock - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[mutex180] unlock tramp out of bl range\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[mutex180] armed unlock: bl NRO+0x%x -> tramp %p (svc stub NRO+0x%x)\n",
                bl - base, (void *)&mutex180_tramp_unlock, tgt - base);
  else
    debugPrintf("[mutex180] unlock so_patch_code FAILED\n");
}
