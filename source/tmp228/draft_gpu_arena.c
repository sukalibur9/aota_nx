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
/* #204: handle captured at setmask (defined in the #198 section below);
 * tentative declaration — merges with the initialized definition there. */
static unsigned liveness198_handle;

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
/* ---- build #205: raw-SVC heartbeat + liveness poll thread ------------------
 * #204 proved the libnx canary sweeper thread stops executing around/after
 * game load (one [live204] line pre-[base], then silence), while kernel
 * threads (main, waiter) run fine. Question: is libnx thread machinery the
 * casualty, or is it global? This thread bypasses libnx entirely: created
 * with raw svcCreateThread/svcStartThread (no Thread object, no libnx TLS),
 * own 64KB static stack, prio 59 core -2 like the sweeper, started early
 * from the first can_track (same site + timing as the sweeper, whose start
 * is proven safe). It calls only SVC wrappers + debugPrintf, both proven
 * to work from foreign (non-libnx) threads by the waiter's own prints.
 * Loop: sleep 2s; every 30th iteration (~60s) print a heartbeat, plus the
 * liveness poll result once the setmask handle is known. The first
 * #207: the raw thread's execution is proven by raw207_state/seq in the
 * ring (reported by the sweeper below), NOT by its own print — #206's own
 * 'running' print crashed the process, so this thread prints nothing. */
static uint8_t  raw207_stack[0x10000] __attribute__((aligned(0x1000)));
static Handle   raw207_thr = 0;
static int      raw207_started = 0;
/* ---- build #207 ring: the raw thread NEVER calls newlib -------------------
 * #206 proved a raw thread (zero kernel TLS, no initialized newlib reent)
 * crashes the process on its first newlib call (its debugPrintf 'running'
 * never landed; both modes died via the wrapper's svcBreak handler). So this
 * thread writes only plain words below — no debugPrintf, no vfprintf, no
 * malloc, no errno — and the canary sweeper (a libnx thread, proven to
 * print) reports them. Word-sized aligned volatile accesses are atomic on
 * AArch64, so the sweeper never sees a torn value. state: 0 = never ran,
 * 1 = running, 2 = has a poll result. */
static volatile unsigned raw207_state = 0;
static volatile unsigned raw207_seq = 0;    /* increments every 2s loop */
static volatile unsigned raw207_wait = 0xFFFFFFFFu; /* last poll result */
static volatile int      raw207_idx = -2;   /* last poll idx */
static void raw207_thread(void *arg) {
  (void)arg;
  raw207_state = 1;   /* proves the thread EXECUTED (sweeper reports it) */
  for (;;) {
    svcSleepThread(2000000000ULL);   /* 2s; SVC only, no libc */
    {
      static unsigned n = 0;
      raw207_seq++;
      if ((++n % 30) == 0) {
        unsigned h = liveness198_handle;
        if (h) {
          Handle hs = (Handle)h;
          s32 idx = -1;
          unsigned w = (unsigned)svcWaitSynchronization(&idx, &hs, 1, 0);
          raw207_wait = w;
          raw207_idx = (int)idx;
          raw207_state = 2;
        }
      }
    }
  }
}
/* #206: start entry, called from main() AFTER the first [boot] print (log
 * open, root resolved, libnx initialized). Bracketed: if the raw start
 * wedges, the log stops right after the [boot] start line. */
void raw207_start(void) {
  if (!raw207_started) {
    raw207_started = 1;
    debugPrintf("[live207] raw thread starting (svcCreateThread)\n");
    {
      u32 r = (u32)svcCreateThread(&raw207_thr, (void *)raw207_thread, NULL, (void *)(raw207_stack + sizeof raw207_stack), 59, -2);
      if (r == 0) {
        debugPrintf("[live207] raw thread created, starting\n");
        svcStartThread(raw207_thr);
        debugPrintf("[live207] raw thread started\n");
      } else {
        debugPrintf("[live207] raw thread create FAILED res=0x%x\n", r);
      }
    }
  }
}
static void can_sweeper_thread(void *arg) {
  (void)arg;
  for (;;) {
    svcSleepThread(2000000000ULL);   /* 2s */
    /* #208: try-lock only — the sweeper must NEVER block here. #204/#207
     * showed exactly one sweeper report then silence; if it was blocked on
     * g_can_lk, this frees it, and the 30th-iteration report below now runs
     * unconditionally so a blocked scan can no longer hide the report. */
    if (mutexTryLock(&g_can_lk)) {
      for (unsigned i = 0; i < CAN_TAB_N; i++) {
        if (g_can[i].p && !can_ok(g_can[i].p, g_can[i].sz)) {
          can_report(g_can[i].p, g_can[i].sz, "LIVE-SWEEP");
          can_report_neighbor(g_can[i].p, g_can[i].caller);
          g_can[i].p = 0;              /* report once */
        }
      }
      mutexUnlock(&g_can_lk);
    }
    /* #204: liveness poll from THIS pre-existing thread — NO new threadStart
     * anywhere (#203 proved a runtime start wedges or breaks the flow).
     * The submission now runs normally (create tail reverted), so setmask
     * captures the handle and the sweeper sees it here. Every 30th sweep
     * (~60s): poll with timeout 0 and print the verdict. */
    {
      static unsigned n = 0;
      if ((++n % 30) == 0) {
        unsigned h = liveness198_handle;
        if (h) {
          Handle hs[1]; hs[0] = (Handle)h;
          s32 idx = -1;
          unsigned w = (unsigned)svcWaitSynchronization(&idx, hs, 1, 0);
          debugPrintf("[live204] sweep poll: handle=%x wait=0x%x idx=%d (0+0=died, 0xEA01 timeout=alive-unscheduled)\n", h, w, (int)idx);
        } else {
          debugPrintf("[live204] sweep poll: handle unknown yet\n");
        }
        /* #207: report the raw thread's ring (written without any newlib
         * call). state 0 = raw thread never ran; seq frozen + state 1 =
         * ran then died; state 2 = polling, wait/idx are the verdict. */
        debugPrintf("[live207] raw ring: state=%u seq=%u wait=0x%x idx=%d (0+0=died, 0xEA01 timeout=alive-unscheduled)\n",
                    raw207_state, raw207_seq, raw207_wait, raw207_idx);
      }
    }
  }
}
/* ---- build #208: post-load reporter ---------------------------------------
 * #207's only ring report came BEFORE setmask captured the handle, and the
 * sweeper (the only reporter) then went silent exactly like #204. This
 * libnx reporter starts AFTER game load (main() calls live208_start right
 * after the [base] print), so if threads die AT load, this one starts after
 * the killing event and survives to report post-load. Same ring, same
 * handle poll, distinct [live208] marker so its lines attribute cleanly
 * against the sweeper's [live204]/[live207]. */
static void live208_thread(void *arg) {
  (void)arg;
  for (;;) {
    svcSleepThread(2000000000ULL);   /* 2s */
    static unsigned n = 0;
    if ((++n % 30) == 0) {
      unsigned h = liveness198_handle;
      if (h) {
        Handle hs = (Handle)h;
        s32 idx = -1;
        unsigned w = (unsigned)svcWaitSynchronization(&idx, &hs, 1, 0);
        debugPrintf("[live208] post-load poll: handle=%x wait=0x%x idx=%d (0+0=died, 0xEA01 timeout=alive-unscheduled) ring state=%u seq=%u\n", h, w, (int)idx, raw207_state, raw207_seq);
      } else {
        debugPrintf("[live208] post-load heartbeat: handle unknown yet, ring state=%u seq=%u\n", raw207_state, raw207_seq);
      }
    }
  }
}
static int live208_started = 0;
void live208_start(void) {
  if (!live208_started) {
    live208_started = 1;
    debugPrintf("[live208] post-load reporter starting\n");
    static Thread t;
    if (R_SUCCEEDED(threadCreate(&t, live208_thread, NULL, NULL, 0x4000, 0x3B, -2))) {
      threadStart(&t);
      debugPrintf("[live208] post-load reporter started\n");
    } else {
      debugPrintf("[live208] post-load reporter create FAILED\n");
    }
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

/* #218: re-start loop verdicts, stored by waiter188_log (lock path)
 * and carried on the [mutex179] syncwait line — the waiter-thread
 * print channel proven to work in every run since #216. */
static unsigned waiter218_loop_n = 0, waiter218_loop_r = 0xffffffffu;
static unsigned waiter218_loop_w = 0xffffffffu, waiter218_loop_sig = 0;
static int waiter218_loop_done = 0;

__attribute__((used)) static void mutex179_log_wait(uintptr_t lock, uintptr_t holder, uintptr_t caller) {
  if (mutex179_n < MUTEX179_LOG_CAP)
    debugPrintf("[mutex179] wait lock=%p holder=%llu caller=%p (n=%u)\n",
                (void *)lock, (unsigned long long)holder, (void *)caller, mutex179_n);
  mutex179_n++;
}

__attribute__((used)) static void mutex179_log_sync(uintptr_t obj, uintptr_t val, uintptr_t caller) {
  if (mutex179_n < MUTEX179_LOG_CAP)
    debugPrintf("[mutex179] syncwait obj=%p val=%llu caller=%p (n=%u) [live218] loop=%u restart=0x%x poll=0x%x sig=%u\n",
                (void *)obj, (unsigned long long)val, (void *)caller, mutex179_n,
                waiter218_loop_n, waiter218_loop_r, waiter218_loop_w, waiter218_loop_sig);
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

/* ---- build #181: condvar signal logging (answers test #180) ----
 * Test #180 parked EARLIER than #179: both modes stuck in the condvar
 * syncwait (same call site as #179, NRO+0x8fc7a0 = 0x8fc570 + 0x230
 * shift) and never returned in 10 min, with 0 mutex waits and 0
 * contended unlocks. So the condvar is never signaled: the thread that
 * should signal it is itself stuck upstream.
 *
 * The waiter (NRO #180 0x8fc6a0) submits work via 0x8ecdc0 with a
 * completion callback (0x8fc640), then:
 *   lock(mutex @ struct+0x14);
 *   while (!(flag @ struct+0x10 bit0)) syncwait(condvar @ struct+0x18, mutex, -1);
 *   unlock(mutex).
 * The callback (0x8fc640, no branches on its main path):
 *   lock; flag = 1; bl signal-stub; unlock; chain via blr x21.
 * The signal stub is svc #0x1d (bytes a10300d4c0035fd6 in NRO #180),
 * the immediate successor to syncwait's svc #0x1c -- confirming it is
 * the condvar signal, not another call.
 * The patched bl is at callback_start + 0x30. The callback prologue
 * pattern (28 bytes) is layout-independent (no bl inside it) and
 * verified unique (1 match) in NRO #180. At the bl site: x0 = condvar,
 * x1 = 1 (signal value). The trampoline preserves x0-x2 + x30, logs,
 * then branches to the real signal stub, whose ret returns to the
 * callback. Globals read only from trampoline asm MUST be
 * __attribute__((used)) (run #182 / #154 trap).
 * If a test logs 0 signal lines, the completion callback never ran:
 * the stall is in the 0x8ecdc0 submission/completion machinery (or its
 * worker thread), upstream of both the condvar and the mutex. */

#define SIGNAL181_LOG_CAP 64
__attribute__((used)) static uintptr_t signal181_svc = 0;
static unsigned signal181_n = 0;

static const uint8_t PAT_SIGNAL181_CB[] = {
  /* completion callback prologue, NRO #180 0x8fc640..0x8fc65b (28 bytes;
   * the signal bl at +0x30 is excluded: its immediate is
   * layout-dependent since the stub lives in another region). */
  0xfd, 0x7b, 0xbd, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xf3, 0x53, 0x01, 0xa9,
  0xf3, 0x03, 0x00, 0xaa, 0xf5, 0x5b, 0x02, 0xa9, 0x15, 0x58, 0x40, 0xa9,
  0x00, 0x50, 0x00, 0x91
};

/* #222: tentative declaration — the initialized definition lives just
 * above waiter188_log (line ~3442); a tentative static merges with it
 * (same file). Needed here because signal181_log_signal is defined
 * before waiter188_log and reports the marker. */
static volatile unsigned waiter222_lock_seen;

/* #223: tentative declaration — the initialized definition lives just
 * above waiter188_log; a tentative static merges with it (same file).
 * Same fix as #222 (the syntax check caught the same error there). */
static volatile unsigned waiter223_stage;

__attribute__((used)) void signal181_log_signal(void *condvar, unsigned long long val) {
  if (signal181_n >= SIGNAL181_LOG_CAP) return;
  debugPrintf("[signal181] signal condvar=%p val=%llu (n=%u) lock_seen=%u wstage=%u\n", condvar, val, signal181_n++, __atomic_load_n(&waiter222_lock_seen, __ATOMIC_ACQUIRE), __atomic_load_n(&waiter223_stage, __ATOMIC_ACQUIRE));
}

__attribute__((naked, used)) void signal181_tramp_signal(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "bl signal181_log_signal\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, signal181_svc\n"
    "ldr x16, [x16, :lo12:signal181_svc]\n"
    "br x16\n"
  );
}

void signal181_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&signal181_arm)) || !mi.size) {
    debugPrintf("[signal181] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t found = text_scan(PAT_SIGNAL181_CB, sizeof PAT_SIGNAL181_CB);
  if (!found) {
    debugPrintf("[signal181] signal site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = found + 0x30;
  uint32_t w = *(volatile uint32_t *)bl;
  if ((w & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[signal181] signal bl not BL (word %08x), patch skipped\n", w);
    return;
  }
  uintptr_t tgt = (uintptr_t)bl_target(bl, w);
  uint32_t tw0 = *(volatile uint32_t *)tgt;
  uint32_t tw1 = *(volatile uint32_t *)(tgt + 4);
  if ((tw0 & 0xFFE0001Fu) != 0xD4000001u || tw1 != 0xD65F03C0u) {
    debugPrintf("[signal181] signal bl target not svc stub (words %08x %08x), patch skipped\n", tw0, tw1);
    return;
  }
  signal181_svc = tgt;
  debugPrintf("[signal181] svc #0x%x stub NRO+0x%x\n", (tw0 >> 5) & 0xFFFFu, tgt - base);
  int64_t diff = (int64_t)(uintptr_t)&signal181_tramp_signal - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[signal181] signal tramp out of bl range\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[signal181] armed signal: bl NRO+0x%x -> tramp %p (svc stub NRO+0x%x)\n",
                bl - base, (void *)&signal181_tramp_signal, tgt - base);
  else
    debugPrintf("[signal181] signal so_patch_code FAILED\n");
}

/* ---- build #182: completion-dispatcher logging (answers test #181) ----
 * Test #181 proved the completion callback never runs (0 signal lines),
 * yet the waiter reached syncwait past the submission bl -- so the
 * submission (0x8ecff0 in NRO #181) returned 0 but its work never
 * completes. The submission maps memory (svc #4), builds a work item
 * (callback + waiter struct embedded), calls the enqueue helper
 * 0x9011e8 (not an svc), builds a buffer header, and returns 0.
 * The completion side is the dispatcher (NRO #181 0x8ed340): it loads a
 * per-thread struct from TLS [tpidrro+0x1e8], atomically loads a
 * 12-slot completion bitmask from a global, and for each set bit
 * invokes the slot's callback via blr; then it locks, unlinks, unlocks.
 * If the dispatcher never runs, completions are never drained; if it
 * runs with bitmask 0, completions never arrive; if bits are set but
 * the waiter still parks, the slots' callbacks are not the waiter's.
 * The patched bl is the dispatcher's lock call at dispatcher_start +
 * 0x74. The dispatcher prologue pattern (28 bytes) is
 * layout-independent (no adrp/bl inside it) and verified unique
 * (1 match) in NRO #181. At the bl site: x0 = lock object,
 * x21 = completion bitmask (callee-saved, survives the blr callbacks),
 * x20 = per-thread struct (likewise). The trampoline preserves
 * x0-x2 + x30, logs (bitmask, struct), then branches to the real lock
 * fn, whose ret returns to the dispatcher. Verify-first: the bl target
 * must be the lock fn, checked against its 16-byte entry (game code,
 * stable across wrapper builds; only its address shifts). Globals read
 * only from trampoline asm MUST be __attribute__((used)) (run #182 /
 * #154 trap). */

#define DISPATCH182_LOG_CAP 64
__attribute__((used)) static uintptr_t dispatch182_lock = 0;
static unsigned dispatch182_n = 0;

static const uint8_t PAT_DISPATCH182[] = {
  /* dispatcher prologue, NRO #181 0x8ed340..0x8ed35b (28 bytes;
   * the lock bl at +0x74 is excluded: its immediate is
   * layout-dependent since the lock fn lives in another region). */
  0xfd, 0x7b, 0xbd, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0x60, 0xd0, 0x3b, 0xd5,
  0xf3, 0x53, 0x01, 0xa9, 0x14, 0xf4, 0x40, 0xf9, 0xf5, 0x5b, 0x02, 0xa9,
  0x34, 0x04, 0x00, 0xb4
};

__attribute__((used)) void dispatch182_log_dispatch(unsigned long long bits, void *st) {
  if (dispatch182_n >= DISPATCH182_LOG_CAP) return;
  debugPrintf("[dispatch182] dispatch bits=%llx struct=%p (n=%u)\n", bits, st, dispatch182_n++);
}

__attribute__((naked, used)) void dispatch182_tramp_lock(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x0, x21\n"
    "mov x1, x20\n"
    "bl dispatch182_log_dispatch\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, dispatch182_lock\n"
    "ldr x16, [x16, :lo12:dispatch182_lock]\n"
    "br x16\n"
  );
}

void dispatch182_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&dispatch182_arm)) || !mi.size) {
    debugPrintf("[dispatch182] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t found = text_scan(PAT_DISPATCH182, sizeof PAT_DISPATCH182);
  if (!found) {
    debugPrintf("[dispatch182] dispatch site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = found + 0x74;
  uint32_t w = *(volatile uint32_t *)bl;
  if ((w & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[dispatch182] dispatch bl not BL (word %08x), patch skipped\n", w);
    return;
  }
  uintptr_t tgt = (uintptr_t)bl_target(bl, w);
  /* lock fn entry, NRO #181 0x8ec4e0 (bytes
   * e30300aa60d03bd504e441b960fc5f88, little-endian words below). */
  uint32_t lw0 = *(volatile uint32_t *)tgt;
  uint32_t lw1 = *(volatile uint32_t *)(tgt + 4);
  uint32_t lw2 = *(volatile uint32_t *)(tgt + 8);
  uint32_t lw3 = *(volatile uint32_t *)(tgt + 12);
  if (lw0 != 0xaa0003e3u || lw1 != 0xd53bd060u || lw2 != 0xb941e404u || lw3 != 0x885ffc60u) {
    debugPrintf("[dispatch182] dispatch bl target not lock fn, patch skipped\n");
    return;
  }
  dispatch182_lock = tgt;
  debugPrintf("[dispatch182] lock fn NRO+0x%x\n", tgt - base);
  int64_t diff = (int64_t)(uintptr_t)&dispatch182_tramp_lock - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[dispatch182] dispatch tramp out of bl range\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[dispatch182] armed dispatch: bl NRO+0x%x -> tramp %p (lock fn NRO+0x%x)\n",
                bl - base, (void *)&dispatch182_tramp_lock, tgt - base);
  else
    debugPrintf("[dispatch182] dispatch so_patch_code FAILED\n");
}

/* ---- build #183: worker-thread progress logging (answers test #182) ----
 * Test #182 proved the completion dispatcher never runs (0 dispatch
 * lines), yet the submission returns 0 and the waiter reaches syncwait.
 * The submission (0x8ed240 in NRO #182) does NOT enqueue to a queue: it
 * CREATES A THREAD via svc #8 (the "enqueue helper" 0x901438 is the
 * svc #8 CreateThread stub in the game's svc stub table), with entry
 * 0x8ed640. The waiter then sets the thread's core mask (svc #0xf) and
 * starts it via the helper at 0x8ed6f0 (tail-call to svc #9
 * StartThread) -- so the thread IS started, and the missing link is
 * inside the worker itself. The worker entry (NRO #182 0x8ed640):
 * TLS setup, lock (bl at +0x6c), link into a list, unlock (bl at
 * +0x9c), blr the function at [arg+8] (the completion callback, from
 * the submission's work item), then bl the dispatcher (at +0xa8).
 * Patching all three bl sites in one build shows exactly where the
 * worker sticks: 0 lock lines = worker never started; lock lines but
 * 0 unlock lines = worker blocks on the lock; unlock lines but 0
 * dispatch lines = worker stuck in the blr (callback/work fn);
 * dispatch lines = worker finished and the dispatcher ran (and the
 * #182 patch should then log dispatch lines too). The worker entry
 * prologue pattern (32 bytes, incl. the 0x21545624 tag mov/movk) is
 * layout-independent (no adrp/bl inside it) and verified unique
 * (1 match) in NRO #182. At all three bl sites x19 = the thread arg
 * (callee-saved, preserved across the calls). Verify-first per site:
 * the bl target's entry bytes must match the lock fn, unlock fn, or
 * dispatcher prologue (game code, stable across wrapper builds; only
 * addresses shift). Globals read only from trampoline asm MUST be
 * __attribute__((used)) (run #182 / #154 trap). Stage numbers:
 * 0 = worker reached lock bl, 1 = worker reached unlock bl (lock
 * acquired + list linked), 2 = worker finished blr, calling
 * dispatcher. */

#define WORKER183_LOG_CAP 64
__attribute__((used)) static uintptr_t worker183_lock = 0;
__attribute__((used)) static uintptr_t worker183_unlock = 0;
__attribute__((used)) static uintptr_t worker183_dispatch = 0;
static unsigned worker183_n = 0;

static const uint8_t PAT_WORKER183[] = {
  /* worker thread entry prologue, NRO #182 0x8ed640..0x8ed65f
   * (32 bytes; the three bl sites at +0x6c/+0x9c/+0xa8 are excluded:
   * their immediates are layout-dependent since the targets live in
   * other regions). */
  0xfd, 0x7b, 0xbd, 0xa9, 0x81, 0xc4, 0x8a, 0x52, 0x81, 0x2a, 0xa4, 0x72,
  0xfd, 0x03, 0x00, 0x91, 0x02, 0x02, 0x80, 0xd2, 0xf3, 0x53, 0x01, 0xa9,
  0xf3, 0x03, 0x00, 0xaa, 0x74, 0xd0, 0x3b, 0xd5
};

__attribute__((used)) void worker183_log_stage(unsigned stage, void *arg) {
  if (worker183_n >= WORKER183_LOG_CAP) return;
  debugPrintf("[worker183] stage=%u arg=%p (n=%u)\n", stage, arg, worker183_n++);
}

__attribute__((naked, used)) void worker183_tramp_lock(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x0, #0\n"
    "mov x1, x19\n"
    "bl worker183_log_stage\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, worker183_lock\n"
    "ldr x16, [x16, :lo12:worker183_lock]\n"
    "br x16\n"
  );
}

/* #211: lock-SKIP tramp. Same save/restore and stage-0 log as
 * worker183_tramp_lock, but returns to the entry (LR = the instruction
 * after the lock bl) instead of branching to the real lock fn — the
 * worker entry proceeds as if the lock call returned, without ever
 * taking the lock. x0/x1 are restored to the original call args (x0 =
 * the lock pointer, non-NULL), so any return check sees a plausible
 * value. This is the discriminator for #210's verdict (thread alive,
 * wait=timeout): stage 0/1 lines mean the thread CAN be scheduled and
 * the blocker was the entry lock itself (held by the waiter across its
 * wait); still zero stage lines mean pure scheduling. */
__attribute__((naked, used)) void worker183_tramp_lock_skip(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x0, #0\n"
    "mov x1, x19\n"
    "bl worker183_log_stage\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "ret\n"
  );
}

__attribute__((naked, used)) void worker183_tramp_unlock(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x0, #1\n"
    "mov x1, x19\n"
    "bl worker183_log_stage\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, worker183_unlock\n"
    "ldr x16, [x16, :lo12:worker183_unlock]\n"
    "br x16\n"
  );
}

__attribute__((naked, used)) void worker183_tramp_dispatch(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x0, #2\n"
    "mov x1, x19\n"
    "bl worker183_log_stage\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, worker183_dispatch\n"
    "ldr x16, [x16, :lo12:worker183_dispatch]\n"
    "br x16\n"
  );
}

void worker183_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&worker183_arm)) || !mi.size) {
    debugPrintf("[worker183] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t found = text_scan(PAT_WORKER183, sizeof PAT_WORKER183);
  if (!found) {
    debugPrintf("[worker183] worker site scan MISS, patch skipped\n");
    return;
  }
  /* Site table: offset from worker entry, stage, expected target entry
   * words (little-endian), target global, trampoline, label. */
  static const struct { uintptr_t off; unsigned stage; uint32_t w[4]; uintptr_t *tgt; void *tramp; const char *label; } sites[3] = {
    /* lock fn entry, NRO #182 0x8ec730 (bytes
     * e30300aa60d03bd504e441b960fc5f88). */
    /* #211: lock bl now goes to the SKIP tramp (logs stage 0, returns
     * without taking the lock). Verify-first on the bl target is unchanged. */
    { 0x6c, 0, { 0xaa0003e3u, 0xd53bd060u, 0xb941e404u, 0x885ffc60u }, &worker183_lock, (void *)&worker183_tramp_lock_skip, "lock" },
    /* unlock fn entry, NRO #182 0x8ec830 (bytes
     * 61d03bd522e441b901fc5f8803008052). */
    { 0x9c, 1, { 0xd53bd061u, 0xb941e422u, 0x885ffc01u, 0x52800003u }, &worker183_unlock, (void *)&worker183_tramp_unlock, "unlock" },
    /* dispatcher prologue first 16 bytes, NRO #182 0x8ed590 (bytes
     * fd7bbda9fd03009160d03bd5f35301a9). */
    { 0xa8, 2, { 0xa9bd7bfd, 0x910003fd, 0xd53bd060u, 0xa90153f3 }, &worker183_dispatch, (void *)&worker183_tramp_dispatch, "dispatch" }
  };
  for (unsigned i = 0; i < 3; i++) {
    uintptr_t bl = found + sites[i].off;
    uint32_t w = *(volatile uint32_t *)bl;
    if ((w & 0xFC000000u) != 0x94000000u) {
      debugPrintf("[worker183] %s bl not BL (word %08x), patch skipped\n", sites[i].label, w);
      continue;
    }
    uintptr_t tgt = (uintptr_t)bl_target(bl, w);
    uint32_t tw0 = *(volatile uint32_t *)tgt;
    uint32_t tw1 = *(volatile uint32_t *)(tgt + 4);
    uint32_t tw2 = *(volatile uint32_t *)(tgt + 8);
    uint32_t tw3 = *(volatile uint32_t *)(tgt + 12);
    if (tw0 != sites[i].w[0] || tw1 != sites[i].w[1] || tw2 != sites[i].w[2] || tw3 != sites[i].w[3]) {
      debugPrintf("[worker183] %s bl target mismatch, patch skipped\n", sites[i].label);
      continue;
    }
    *sites[i].tgt = tgt;
    debugPrintf("[worker183] %s fn NRO+0x%x\n", sites[i].label, tgt - base);
    int64_t diff = (int64_t)(uintptr_t)sites[i].tramp - (int64_t)bl;
    if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
      debugPrintf("[worker183] %s tramp out of bl range\n", sites[i].label);
      continue;
    }
    uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
    if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
      debugPrintf("[worker183] armed %s: bl NRO+0x%x -> tramp %p (fn NRO+0x%x)\n",
                  sites[i].label, bl - base, sites[i].tramp, tgt - base);
    else
      debugPrintf("[worker183] %s so_patch_code FAILED\n", sites[i].label);
  }
}

/* ---- build #184: core-mask logging (answers test #183) ----
 * Test #183 proved the worker thread never executes its entry (0
 * worker183 stage lines), yet the waiter checks all three steps and
 * reaching syncwait proves all returned 0: submission==0,
 * SetThreadCoreMask==0, StartThread==0. So the thread is created and
 * started per return codes, but its entry never runs -- the prime
 * suspect is the core mask: if it selects no runnable core, the
 * thread is never scheduled despite StartThread succeeding. The mask
 * comes from GetInfo (svc #0x29, waiter bl at +0x58) into the
 * waiter's stack slot [sp+0x48], and is passed as w2 to
 * SetThreadCoreMask (svc #0xf) at the waiter's bl at +0xc8, with
 * w0 = the thread handle (from [x21]) and w1 = -1. Patching that
 * single bl logs (handle, mask): a mask of 0 or one excluding all
 * runnable cores is the smoking gun; a sane mask (e.g. covering the
 * process's cores) sends the investigation to #185 (CreateThread
 * args: entry/stack/priority/core). The waiter prologue pattern
 * (32 bytes) is layout-independent (no adrp/bl inside it; the b.ne
 * is relative) and verified unique (1 match) in NRO #183. The bl
 * target must be the svc #0xf stub (svc; ret, game code, stable
 * across wrapper builds; only its address shifts). The trampoline
 * preserves x0-x2 + x30, logs (handle, mask), then branches to the
 * real stub, whose ret returns to the waiter. The global read only
 * from trampoline asm MUST be __attribute__((used)) (run #182 /
 * #154 trap). */

#define COREMASK184_LOG_CAP 64
__attribute__((used)) static uintptr_t coremask184_stub = 0;
static unsigned coremask184_n = 0;

static const uint8_t PAT_COREMASK184[] = {
  /* waiter prologue, NRO #183 0x8fce10..0x8fce2f (32 bytes;
   * the SetThreadCoreMask bl at +0xc8 is excluded: its immediate is
   * layout-dependent since the stub table lives in another region). */
  0xfd, 0x7b, 0xb9, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe5, 0x03, 0x00, 0xaa,
  0xf7, 0x63, 0x03, 0xa9, 0xf8, 0x03, 0x00, 0xaa, 0x60, 0x00, 0x04, 0xaa,
  0x1f, 0x2c, 0x40, 0xf2, 0x41, 0x08, 0x00, 0x54
};

/* #198: created-thread handle captured for the liveness poll (zero
 * until the setmask runs, i.e. before StartThread; plain-word read
 * by the poll thread, stored once here). */
static unsigned liveness198_handle = 0;

__attribute__((used)) void coremask184_log_mask(unsigned handle, unsigned long long mask) {
  if (!liveness198_handle && handle) liveness198_handle = handle; /* #198: capture created handle */
  if (coremask184_n >= COREMASK184_LOG_CAP) return;
  debugPrintf("[coremask184] setmask handle=%x mask=%llx (n=%u)\n", handle, mask, coremask184_n++);
}

__attribute__((naked, used)) void coremask184_tramp_setmask(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x1, x2\n"
    "bl coremask184_log_mask\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, coremask184_stub\n"
    "ldr x16, [x16, :lo12:coremask184_stub]\n"
    "br x16\n"
  );
}

void coremask184_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&coremask184_arm)) || !mi.size) {
    debugPrintf("[coremask184] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t found = text_scan(PAT_COREMASK184, sizeof PAT_COREMASK184);
  if (!found) {
    debugPrintf("[coremask184] waiter site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = found + 0xc8;
  uint32_t w = *(volatile uint32_t *)bl;
  if ((w & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[coremask184] setmask bl not BL (word %08x), patch skipped\n", w);
    return;
  }
  uintptr_t tgt = (uintptr_t)bl_target(bl, w);
  /* svc #0xf stub: svc #0xf (0xd40001e1), ret (0xd65f03c0). */
  uint32_t tw0 = *(volatile uint32_t *)tgt;
  uint32_t tw1 = *(volatile uint32_t *)(tgt + 4);
  if (tw0 != 0xd40001e1u || tw1 != 0xd65f03c0u) {
    debugPrintf("[coremask184] setmask bl target not svc #0xf stub, patch skipped\n");
    return;
  }
  coremask184_stub = tgt;
  debugPrintf("[coremask184] svc #0xf stub NRO+0x%x\n", tgt - base);
  int64_t diff = (int64_t)(uintptr_t)&coremask184_tramp_setmask - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[coremask184] setmask tramp out of bl range\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[coremask184] armed setmask: bl NRO+0x%x -> tramp %p (svc #0xf stub NRO+0x%x)\n",
                bl - base, (void *)&coremask184_tramp_setmask, tgt - base);
  else
    debugPrintf("[coremask184] setmask so_patch_code FAILED\n");
}

/* ---- build #185: CreateThread-args logging (answers test #184) ----
 * Test #184 refuted the core-mask hypothesis (mask 7 = cores 0,1,2,
 * sane and schedulable), yet the worker entry still never runs
 * (0 worker183 stage lines). The last unexamined link is the
 * CreateThread call itself: the submission's bl at +0x1b8 to the
 * svc #8 stub, with x0 = handle out-pointer (sp+0x8c), x1 = entry,
 * x2 = arg (item), x3 = stack (mapped buffer end), x4 = priority
 * (0x3b = 59), x5 = core (-2, then masked to 0-2). Those values were
 * read from disassembly; #185 logs them live from hardware, so a
 * surprising arg (bad stack, bad priority, wrong entry) is caught
 * rather than assumed. If all args are sane, the thread mechanism
 * itself is broken in this environment and the endgame is bypassing
 * thread creation (running the worker entry inline in the waiter).
 * The submission prologue pattern (32 bytes) is layout-independent
 * (no adrp/bl inside it; the b.ne is relative) and verified unique
 * (1 match) in NRO #184. The bl target must be the svc #8 stub
 * (str; svc #8, game code, stable across wrapper builds; only its
 * address shifts). The trampoline saves x0-x5 + x30, shifts the args
 * forward (logger takes entry/arg/stack/prio/core, dropping the
 * out-pointer; the shift is safe because each source is read before
 * its register is overwritten), logs, restores, then branches to the
 * real stub, whose ret returns to the submission. The global read
 * only from trampoline asm MUST be __attribute__((used)) (run #182 /
 * #154 trap). Trampoline asm is re-read against the proven pattern
 * before the check: -fsyntax-only does NOT assemble inline asm. */

#define CREATETHREAD185_LOG_CAP 64
__attribute__((used)) static uintptr_t createthread185_stub = 0;
static unsigned createthread185_n = 0;

static const uint8_t PAT_CREATETHREAD185[] = {
  /* submission prologue, NRO #184 0x8ed770..0x8ed78f (32 bytes;
   * the CreateThread bl at +0x1b8 is excluded: its immediate is
   * layout-dependent since the stub table lives in another region). */
  0xfd, 0x7b, 0xb7, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xf5, 0x5b, 0x02, 0xa9,
  0x36, 0xeb, 0x82, 0x52, 0x9f, 0x2c, 0x40, 0xf2, 0xe1, 0x07, 0x00, 0x54,
  0xe7, 0x03, 0x00, 0xaa, 0xe8, 0x03, 0x01, 0xaa
};

/* #213: forward decls (tentative definitions; the initialized definitions
 * live in the #213 section below -- same idiom as liveness198_handle). */
static uintptr_t tls213_setup_fn;
static uintptr_t tls213_real_entry;
static uintptr_t tls213_tramp_addr;
void tls213_entry_tramp(void);

__attribute__((used)) void createthread185_log_create(void *entry, void *arg, void *stack, long long prio, long long core) {
  /* #204: create tail REVERTED (back to print-only) — #203 proved a runtime
   * start in this tail wedges (full RAM) or breaks the flow (sphaira), so
   * the submission must run normally to setmask; liveness is polled from
   * the canary sweeper instead. */
  if (createthread185_n >= CREATETHREAD185_LOG_CAP) return;
  debugPrintf("[createthread185] create entry=%p arg=%p stack=%p prio=%lld core=%lld (n=%u)\n", entry, arg, stack, prio, core, createthread185_n++);
  /* #213: stash the real entry for the wrapper tramp (it reads
   * tls213_real_entry at thread start). Runs on the creating thread
   * (main), so debugPrintf is safe here. */
  tls213_real_entry = (uintptr_t)entry;
  if (tls213_setup_fn)
    debugPrintf("[tls213] wrap entry=%p -> tramp=%p setup=0x%lx\n", entry, (void *)tls213_entry_tramp, tls213_setup_fn);
  else
    debugPrintf("[tls213] wrap SKIPPED (setup fn not found), entry passes through\n");
}

/* ---- build #197: force prio/core on the real CreateThread (answers test #196) ----
 * Test #196 exonerated the stack: a proper dedicated 256KB page-aligned
 * stack top changed NOTHING (entry195 + stage still silent, waiter still
 * parks). The stack substitution is KEPT; #197's delta is prio/core only.
 * The remaining unusual CreateThread args vs normal libnx threads are
 * prio 59 (the wrapper's own clock thread runs at 0x2C = 44, via
 * threadCreate(..., 0x8000, 0x2C, -2) in main.c) and core -2 (any core).
 * #197 forces, in createthread185_tramp_create AFTER the register
 * restores and AFTER the #196 stack substitution, x4 = 44 and x5 = 0
 * (core 0 is inside the waiter's setmask 7), before the jump to the
 * real svc #8 stub. The create log still shows the ORIGINAL prio/core
 * (it runs before the forcing, same idiom as the #196 stack log), while
 * the kernel receives the forced values. Reading: ENTRY RAN/stage
 * appear = prio/core mattered (bisect prio vs core next if needed);
 * still silent = stack + prio + core ALL exonerated, next = TLS /
 * StartThread-return live check / thread-state inspection. */
__attribute__((naked, used)) void createthread185_tramp_create(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x3, [sp, #-16]!\n"
    "stp x4, x5, [sp, #-16]!\n"
    "str x30, [sp, #-16]!\n"
    "mov x0, x1\n"
    "mov x1, x2\n"
    "mov x2, x3\n"
    "mov x3, x4\n"
    "mov x4, x5\n"
    "bl createthread185_log_create\n"
    "ldr x30, [sp], #16\n"
    "ldp x4, x5, [sp], #16\n"
    "ldp x2, x3, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, createthread196_stack_top\n"
    "ldr x16, [x16, :lo12:createthread196_stack_top]\n"
    "cbz x16, 196f\n"
    "mov x3, x16\n"
    "196:\n"
    "mov x4, #44\n"
    "mov x5, #0\n"
    /* #213: substitute the entry with the TLS-setup wrapper tramp, but
     * ONLY when the setup fn was found (tls213_setup_fn != 0); on a scan
     * MISS x1 keeps the real entry and the build behaves like #212. */
    "adrp x16, tls213_setup_fn\n"
    "ldr x16, [x16, :lo12:tls213_setup_fn]\n"
    "cbz x16, 213f\n"
    "adrp x16, tls213_tramp_addr\n"
    "ldr x16, [x16, :lo12:tls213_tramp_addr]\n"
    "mov x1, x16\n"
    "213:\n"
    "adrp x16, createthread185_stub\n"
    "ldr x16, [x16, :lo12:createthread185_stub]\n"
    "br x16\n"
  );
}

/* ---- build #196: substitute thread stack (answers test #195) ----
 * Test #195 proved a real kernel thread is created and started yet
 * never executes its entry (entry195 + stage patches armed, both
 * silent; waiter reaches its lock and parks). The one genuinely
 * unusual CreateThread parameter vs normal libnx threads is the
 * stack: the submission passes the item pointer itself as BOTH arg
 * and stack (arg==stack in #185 and #195), while libnx threads get
 * a dedicated, page-aligned buffer and pass its TOP. #196 keeps
 * entry/arg/prio/core identical and replaces ONLY the stack arg
 * (x3) with the top of a fresh 256KB page-aligned buffer allocated
 * via __real_memalign (NOT memalign: this file wraps memalign into
 * __wrap_memalign's GPU-arena tracking, which must not touch a
 * thread stack). The substitution happens in
 * createthread185_tramp_create after the registers are restored and
 * before the jump to the real svc #8 stub, so the create log still
 * shows the ORIGINAL stack arg while the kernel receives the
 * substitute. If allocation fails, the global stays 0 and the
 * trampoline passes x3 through unchanged (safe fallback, visible
 * via the [stack196] alloc FAILED line). Caveat: a single buffer
 * is shared if more than one CreateThread is ever intercepted (only
 * one was observed in #185/#195); a second create (n>0) in the test
 * log would flag that case. The buffer is never freed: a thread
 * stack must outlive its thread. */
__attribute__((used)) static uintptr_t createthread196_stack_top = 0;

void liveness198_arm(void); /* #198: defined in the #198 section below. */

void createthread185_arm(void) {
  /* #204: the liveness poll thread is NOT started anywhere — #203 proved a
   * runtime start wedges (full RAM) or breaks the flow (sphaira). Liveness
   * is polled from the pre-existing canary sweeper (can_sweeper_thread). */
  debugPrintf("[live199] createthread185_arm entered\n");
  /* #196: allocate the substitute thread stack (see note above). */
  if (!createthread196_stack_top) {
    void *buf = __real_memalign(0x1000, 0x40000);
    if (buf) {
      createthread196_stack_top = (uintptr_t)buf + 0x40000;
      debugPrintf("[stack196] subst stack buffer=%p top=%p (256KB, page-aligned)\n",
                  buf, (void *)createthread196_stack_top);
    } else {
      debugPrintf("[stack196] stack buffer alloc FAILED, substitution disabled (x3 passes through)\n");
    }
  }
  /* #197: prio/core forcing lives in the trampoline (see note above);
   * this line proves the #197 code path is armed at patch time. */
  debugPrintf("[prio197] forcing prio=44 core=0 in CreateThread trampoline (create log shows ORIGINAL prio/core; kernel receives forced values)\n");
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&createthread185_arm)) || !mi.size) {
    debugPrintf("[createthread185] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t found = text_scan(PAT_CREATETHREAD185, sizeof PAT_CREATETHREAD185);
  if (!found) {
    debugPrintf("[createthread185] submission site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = found + 0x1b8;
  uint32_t w = *(volatile uint32_t *)bl;
  if ((w & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[createthread185] create bl not BL (word %08x), patch skipped\n", w);
    return;
  }
  uintptr_t tgt = (uintptr_t)bl_target(bl, w);
  /* svc #8 stub: str x0, [sp, #-0x10]! (0xf81f0fe0), svc #8 (0xd4000101). */
  uint32_t tw0 = *(volatile uint32_t *)tgt;
  uint32_t tw1 = *(volatile uint32_t *)(tgt + 4);
  if (tw0 != 0xf81f0fe0u || tw1 != 0xd4000101u) {
    debugPrintf("[createthread185] create bl target not svc #8 stub, patch skipped\n");
    return;
  }
  createthread185_stub = tgt;
  debugPrintf("[createthread185] svc #8 stub NRO+0x%x\n", tgt - base);
  int64_t diff = (int64_t)(uintptr_t)&createthread185_tramp_create - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[createthread185] create tramp out of bl range\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[createthread185] armed create: bl NRO+0x%x -> tramp %p (svc #8 stub NRO+0x%x)\n",
                bl - base, (void *)&createthread185_tramp_create, tgt - base);
  else
    debugPrintf("[createthread185] create so_patch_code FAILED\n");
}

/* ---- build #213: game-TLS setup on the created thread (answers test #212) ----
 * Test #212 proved the re-start schedules the created thread (first time it
 * ever ran), but the thread crashed immediately in the game's own fatal path:
 * the job system calls the TLS-check at NRO+0x8fe400, which reads TLS+0x1e0
 * and compares it to the magic 0x21545624; on mismatch it calls FatalError
 * (0x8fded0) with code 0x1959, which stores the code at [sp,#0x1c] and calls
 * svcBreak(0, sp+0x1c, 4) -- exactly the crash report (Result 0x1959, Break
 * Address = SP+0x1c, Size 4, identical in both modes). The crashed thread's
 * TLS was all zeros: the wrapper's raw kernel-thread creation never ran the
 * game's per-thread TLS init. The game's TLS-setup fn (NRO+0x8fecd0 in #212)
 * writes the magic to TLS+0x1e0, 0 to +0x1e8, a global-derived pointer to
 * +0x1f0, and more; it is called only from the per-thread init chain at
 * 0x8fe390, which the worker thread never reached.
 *
 * #213 wraps the created thread's entry: createthread185_tramp_create stashes
 * the real entry in tls213_real_entry and substitutes x1 with
 * tls213_entry_tramp (only when the setup fn was found). The tramp runs ON
 * the new thread (so `mrs tpidrro_el0` inside the setup fn reads the NEW
 * thread's TLS), calls the setup fn, then branches to the real entry with
 * the original args. The tramp calls NO newlib (no debugPrintf): like #206's
 * raw thread, a game thread has a zero kernel TLS and no initialized newlib
 * reent, so any newlib call from it would fault; the setup fn is pure game
 * code (TLS writes + global loads + one game call), safe on a game thread.
 * The wrap is observable only indirectly: no more 0x1959 crash + stage lines
 * (or further progress) mean the TLS check passed. If the setup fn is not
 * found (scan MISS), the entry passes through untouched and the build behaves
 * exactly like #212 (same 0x1959 crash), and the [tls213] arm line says so.
 * The re-start (#212) is KEPT: it is what schedules the thread.
 * Caveat: a single static holds the real entry; only one CreateThread was
 * ever observed (n=0) and the waiter blocks on it before any second create
 * could happen, so the first thread always reads the static before a second
 * create could overwrite it. */
static uintptr_t scan_verified(uintptr_t base, size_t size, const uint8_t *pat, size_t len, int (*ok)(uintptr_t cand));

/* mov w1, #0x5624 (0x528ac481) ; movk w1, #0x2154, lsl #16 (0x72a42a81):
 * the TLS-magic immediate pair. Six w1 sites exist in the #212 NRO; the
 * verify fn below picks the setup fn (the only one whose next words are
 * `mrs x0, tpidrro_el0` then `str w1, [x0, #0x1e0]`). */
static const uint8_t PAT_TLS213_SETUP[] = {
  0x81, 0xc4, 0x8a, 0x52, 0x81, 0x2a, 0xa4, 0x72
};

static int tls213_setup_ok(uintptr_t cand) {
  /* cand = address of the mov (setup fn starts 4 bytes earlier, at its
   * `stp x29, x30, [sp, #-0x20]!` prologue). All words are internal
   * immediates / fixed encodings -- exact match, no address immediates. */
  if (*(volatile uint32_t *)(cand - 4) != 0xa9be7bfdu) return 0;
  if (*(volatile uint32_t *)(cand + 0x0c) != 0xd53bd060u) return 0; /* mrs x0, tpidrro_el0 */
  if (*(volatile uint32_t *)(cand + 0x18) != 0xb901e001u) return 0; /* str w1, [x0, #0x1e0] */
  return 1;
}

__attribute__((used)) static uintptr_t tls213_setup_fn = 0;
__attribute__((used)) static uintptr_t tls213_real_entry = 0;
__attribute__((used)) static uintptr_t tls213_tramp_addr = (uintptr_t)&tls213_entry_tramp;

/* Entry wrapper tramp. Runs on the new thread with x0 = the game's thread
 * arg (and x8 as the kernel set it -- the entry reads x8). Saves x0-x3, x8
 * and x30, calls the game TLS-setup fn if found, restores, then branches to
 * the real entry. SP is exactly restored before the branch, so the entry
 * sees the kernel-provided stack. No newlib anywhere in this path. */
__attribute__((naked, used)) void tls213_entry_tramp(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x3, [sp, #-16]!\n"
    "stp x8, x30, [sp, #-16]!\n"
    "adrp x16, tls213_setup_fn\n"
    "ldr x16, [x16, :lo12:tls213_setup_fn]\n"
    "cbz x16, 213f\n"
    "blr x16\n"
    "213:\n"
    "ldp x8, x30, [sp], #16\n"
    "ldp x2, x3, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, tls213_real_entry\n"
    "ldr x16, [x16, :lo12:tls213_real_entry]\n"
    "cbz x16, 214f\n"
    "br x16\n"
    "214:\n"
    "svc #0xa\n"
    "b 214b\n"
  );
}

void tls213_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&tls213_arm)) || !mi.size) {
    debugPrintf("[tls213] nro base resolve FAILED, entry wrap disabled (build behaves like #212)\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t mov = scan_verified(base, mi.size, PAT_TLS213_SETUP, sizeof PAT_TLS213_SETUP, tls213_setup_ok);
  if (!mov) {
    debugPrintf("[tls213] TLS-setup scan MISS, entry wrap disabled (build behaves like #212)\n");
    return;
  }
  tls213_setup_fn = mov - 4;
  debugPrintf("[tls213] TLS-setup fn NRO+0x%x (mov NRO+0x%x), entry wrap armed\n", tls213_setup_fn - base, mov - base);
}

/* ---- build #198: thread-liveness poll (answers test #197) ----
 * Test #197 exonerated stack + prio + core, and the StartThread-return
 * proposal was WITHDRAWN before building: disassembly of the delivered
 * #197 NRO shows the submission stores the CreateThread handle to
 * item+0, the helper loads it and tail-calls the real svc #9 stub, and
 * the waiter checks w0 (cbnz) before reaching its lock -- the lock
 * firing in #195/#196/#197 already proves StartThread returned 0 on
 * the CORRECT handle, so logging its return would print a known 0.
 * What is still unknown is whether the created thread is
 * ALIVE-but-unscheduled or DEAD. #198 answers it without touching
 * the game path: a wrapper thread (libnx threadCreate, same idiom as
 * the canary sweeper; prio 44, stack 0x8000, core -2, as the clock
 * thread) waits for the created handle -- captured in
 * coremask184_log_mask, i.e. before StartThread runs -- then polls it
 * with svcWaitSynchronization(index, handles, count, timeout) once per
 * second -- NOTE (fixed after run #202 compile failure): this libnx
 * version's svcWaitSynchronization takes FOUR arguments (out index,
 * handle array, count, timeout), NOT the two-argument single-handle
 * form; the 2-arg call failed the cloud build at gpu_arena.c:2607
 * (svc.h:676). The poll therefore passes a 1-element array and logs
 * the returned index alongside the result.
 * svcWaitSynchronization on a thread handle is how libnx pthread_join
 * waits for thread exit, so a 0 result means the thread exited and a
 * timeout result means it is still alive. Logs: one [live198] started
 * line (proves the poll thread itself runs), a waiting heartbeat
 * every 60 loops while the handle is still unknown, then the first
 * poll result, every change, and a heartbeat every 60 polls (~1 min).
 * Reading: wait=0 with idx=0 = thread died silently after start;
 * wait=timeout (0xEA01) = thread alive but never scheduled; any other
 * value = kernel error, named by the value; started line with zero
 * poll lines = the wait itself blocked (unexpected); zero [live198]
 * lines at all = the poll thread never started. main.c is untouched:
 * the arm call is chained from createthread185_arm, and the handle is
 * captured in coremask184_log_mask. No asm is touched in #198. */
static void liveness198_thread(void *arg) {
  (void)arg;
  unsigned n = 0;
  unsigned last = 0xFFFFFFFFu;
  /* #200: sleep BEFORE the first debugPrintf. #199 showed main wedging at the
   * first print that needs g_log_lock after threadStart, with the poll thread
   * as the only consistent lock holder — i.e. the poll thread's first print
   * may be the wedge. Delaying it lets main proceed through arms + init first:
   * if game lines then appear and the wedge only comes later, the lock-wedge
   * theory is confirmed; if main still wedges immediately, the wedge is in
   * threadStart/thread machinery itself, not the print lock. */
  svcSleepThread(5000000000LL);
  debugPrintf("[live198] poll thread started (1s interval, svcWaitSynchronization timeout 0)\n");
  for (;;) {
    unsigned h = liveness198_handle;
    if (h) {
      int idx = -1;
      unsigned hs[1]; hs[0] = h;
      unsigned r = (unsigned)svcWaitSynchronization(&idx, hs, 1, 0);
      if (n == 0 || r != last || (n % 60) == 0)
        debugPrintf("[live198] poll handle=%x wait=%x idx=%d (n=%u)\n", h, r, idx, n);
      last = r;
    } else if ((n % 60) == 0) {
      debugPrintf("[live198] waiting for handle (n=%u)\n", n);
    }
    n++;
    svcSleepThread(1000000000LL);
  }
}

/* #204: DORMANT — no longer called by anything (create tail reverted);
 * liveness is polled from can_sweeper_thread instead. Kept for reference. */
void liveness198_arm(void) {
  static Thread t;
  debugPrintf("[live199] before threadCreate\n");
  if (R_SUCCEEDED(threadCreate(&t, liveness198_thread, NULL, NULL, 0x8000, 0x2C, -2))) {
    /* #203: start the poll thread FOR REAL (the #201 skip is gone) — called
     * only from createthread185_log_create at runtime, never during arms. */
    debugPrintf("[live203] threadCreate OK, before threadStart\n");
    threadStart(&t);
    debugPrintf("[live203] after threadStart\n");
  } else
    debugPrintf("[live198] poll threadCreate FAILED\n");
  debugPrintf("[live198] poll thread armed\n");
}

/* ---- build #195: real-thread entry-execution probe (answers test #194) ----
 * Test #194 proved the table-loop queue fully static (all 114/116 enter
 * lines identical, ret 0, slots matching the disasm setup) and reframed
 * the loop as an eternal worker loop, correctly idle -- the blockage is
 * that it runs INLINE in the waiter thread via the bypass, so its
 * eternity blocks the entry's dispatcher (stage 2). The queue being
 * empty is expected for an idle worker during a blocked init. The
 * root-cause focus therefore returns to #185: a real kernel thread
 * (svc #8 stub verified REAL in the #194 NRO: str; svc #8; str w1;
 * ret -- the fake-stub theory is dead) is created and started with
 * sane args, yet the entry never executes.
 * #195 turns the bypass OFF (main.c) so the real CreateThread /
 * StartThread path runs again, and adds an entry-execution log that
 * is INDEPENDENT of the worker183 stage patches: entry+0 is replaced
 * with a bl to entry195_tramp, which logs and then executes the
 * displaced prologue instruction (stp x29, x30, [sp, #-0x30]!, word
 * 0xa9bd7bfd -- position-independent: it stores registers and moves
 * sp exactly as the original prologue would) before returning to
 * entry+4. The trampoline is STACK-BASED and race-free (no globals
 * for ret/arg: x30 + x0 are pushed, the log call is balanced, then
 * popped -- so even if several threads ever ran this entry, each
 * thread's return address and arg stay on its own stack). At thread
 * start only x0 (arg) is meaningful, so only x0 + x30 are preserved
 * across the log call. The arm fn pattern-scans the entry prologue
 * (PAT_ENTRY195, game code, stable across wrapper builds) and
 * verify-first checks entry+0 == 0xa9bd7bfd before patching; a scan
 * MISS or mismatch logs and skips WITHOUT touching the create path,
 * so the primary signals (stage patches armed?, stage lines?,
 * waiter lock event?, syncwait park?) survive even if this arm
 * fails. Expected #195 signatures: (a) real thread runs: [entry195]
 * ENTRY RAN + stage 0/1 + signal + waiter lock event, and the #185
 * conclusion is overturned; (b) real thread never runs: stage
 * patches ARMED + [createthread185] args sane + [coremask184] mask
 * + waiter lock event + syncwait park + NO signal + NO stage lines
 * + NO [entry195] -- then the hunt moves to kernel-side causes
 * (stack validity, core -2, priority 59, TLS, starvation). */

__attribute__((used)) static uintptr_t entry195_entry = 0;

__attribute__((used)) void entry195_log(void *entry, void *arg) {
  debugPrintf("[entry195] ENTRY RAN entry=%p arg=%p\n", entry, arg);
}

__attribute__((naked, used)) void entry195_tramp(void) {
  __asm__ volatile (
    "stp x30, x0, [sp, #-16]!\n"
    "adrp x16, entry195_entry\n"
    "ldr x0, [x16, :lo12:entry195_entry]\n"
    "ldr x1, [sp, #8]\n"
    "bl entry195_log\n"
    "ldp x30, x0, [sp], #16\n"
    "stp x29, x30, [sp, #-0x30]!\n"
    "ret\n"
  );
}

/* Entry prologue, 10 words (40 bytes), NRO #194 0x8eed00..0x8eed27.
 * Uniqueness verified by full-file scan of NRO #194: the 8-word
 * prefix still matches a fake prologue at 0xa31890, but the 10-word
 * prefix matches ONLY 0x8eed00. No adrp/bl inside the pattern, so
 * its bytes are layout-independent (game code, stable across
 * wrapper builds; only its address shifts). */
static const uint8_t PAT_ENTRY195[] = {
  0xfd, 0x7b, 0xbd, 0xa9, 0x81, 0xc4, 0x8a, 0x52, 0x81, 0x2a, 0xa4, 0x72,
  0xfd, 0x03, 0x00, 0x91, 0x02, 0x02, 0x80, 0xd2, 0xf3, 0x53, 0x01, 0xa9,
  0xf3, 0x03, 0x00, 0xaa, 0x74, 0xd0, 0x3b, 0xd5, 0x94, 0x02, 0x06, 0x91,
  0x03, 0x00, 0x40, 0xf9
};

void entry195_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&entry195_arm)) || !mi.size) {
    debugPrintf("[entry195] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t fn = text_scan(PAT_ENTRY195, sizeof PAT_ENTRY195);
  if (!fn) {
    debugPrintf("[entry195] entry site scan MISS, patch skipped\n");
    return;
  }
  if (*(volatile uint32_t *)fn != 0xa9bd7bfdu) {
    debugPrintf("[entry195] entry+0 not prologue stp (word %08x), patch skipped\n",
                *(volatile uint32_t *)fn);
    return;
  }
  entry195_entry = fn;
  int64_t diff = (int64_t)(uintptr_t)&entry195_tramp - (int64_t)fn;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[entry195] entry tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)fn, &nw, sizeof nw) == 0)
    debugPrintf("[entry195] armed entry: NRO+0x%x -> tramp %p\n",
                fn - base, (void *)&entry195_tramp);
  else
    debugPrintf("[entry195] entry so_patch_code FAILED\n");
}

/* ---- build #217: work-fn boundary logging on the PROVEN channel ----
 * Test #216 proved the created thread DOES execute its entry
 * ([entry195] ENTRY RAN, sphaira, first time ever) and then goes
 * silent with no crash and no unlock. The entry body after entry+4
 * is straight-line TLS init + global reads (cannot block), then:
 *   entry+0x6c  bl lock     (SKIPPED by the #211 tramp, returns at once)
 *   entry+0x9c  bl unlock   (real unlock fn, non-blocking by disassembly)
 *   entry+0xa0  ldp x1, x0, [x19, #8]   (x1 = work fn, x0 = arg)
 *   entry+0xa4  blr x1      (THE WORK FN — job callback)
 *   entry+0xa8  bl dispatch (0x8ef270 dispatcher loop, blr per bit)
 *   entry+0xac  udf
 * So the hang is either inside the work fn / dispatcher, or the
 * thread is descheduled mid-entry, or it deadlocks in a log call
 * before reaching the blr. The worker183 stage channel has NEVER
 * produced a line in any build, so it cannot answer this — #217
 * instruments the work-fn boundary with the entry195 mechanism
 * instead (a naked tramp that logs via plain debugPrintf, then
 * executes the displaced instruction and returns — the exact
 * pattern ENTRY RAN proved works from the worker thread).
 * Two patches, both located off entry195_entry (the entry found by
 * entry195_arm — work217_arm runs after it in main.c and skips
 * cleanly if entry195 found nothing):
 *   pre-work:  entry+0xa0 (ldp x1, x0, [x19, #8], word 0xa9408261
 *              read off the delivered #216 NRO, layout-independent)
 *              -> bl work217_tramp_pre, which executes the displaced
 *              ldp, logs "[work217] WORK FN fn=%p arg=%p", restores
 *              x0/x1/x30 and rets to entry+0xa4 (the blr).
 *   post-work: entry+0xa8 (bl dispatch; masked BL check only, the
 *              real target is resolved at runtime via bl_target)
 *              -> bl work217_tramp_post, which logs "[work217] WORK
 *              DONE" and br's to the real dispatch fn (x30 still
 *              holds entry+0xac, so dispatch rets to the udf as
 *              the original bl would have).
 * Readings: WORK FN present + DONE absent = hang inside the work fn
 * or the dispatcher (next: instrument the job callback itself).
 * WORK FN absent = stuck between entry+4 and the blr (stage-log
 * call, unlock path, or descheduling). DONE present = work fn
 * returned; hang is in the dispatcher, or the waiter never wakes. */

__attribute__((used)) static uintptr_t work217_dispatch = 0;

__attribute__((used)) void work217_log_fn(void *fn, void *arg) {
  debugPrintf("[work217] WORK FN fn=%p arg=%p\n", fn, arg);
}

__attribute__((used)) void work217_log_done(void) {
  debugPrintf("[work217] WORK DONE\n");
}

__attribute__((naked, used)) void work217_tramp_pre(void) {
  __asm__ volatile (
    "stp x30, x2, [sp, #-16]!\n"
    "ldp x1, x0, [x19, #8]\n"
    "stp x0, x1, [sp, #-16]!\n"
    "mov x0, x1\n"
    "ldr x1, [sp]\n"
    "bl work217_log_fn\n"
    "ldp x0, x1, [sp], #16\n"
    "ldp x30, x2, [sp], #16\n"
    "ret\n"
  );
}

__attribute__((naked, used)) void work217_tramp_post(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "bl work217_log_done\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, work217_dispatch\n"
    "ldr x16, [x16, :lo12:work217_dispatch]\n"
    "br x16\n"
  );
}

void work217_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&work217_arm)) || !mi.size) {
    debugPrintf("[work217] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  if (!entry195_entry) {
    debugPrintf("[work217] entry195_entry unset, patch skipped\n");
    return;
  }
  uintptr_t pre = entry195_entry + 0xa0;
  uintptr_t post = entry195_entry + 0xa8;
  if (*(volatile uint32_t *)pre != 0xa9408261u) {
    debugPrintf("[work217] entry+0xa0 not ldp x1,x0,[x19,#8] (word %08x), patch skipped\n",
                *(volatile uint32_t *)pre);
    return;
  }
  uint32_t wpost = *(volatile uint32_t *)post;
  if ((wpost & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[work217] entry+0xa8 not BL (word %08x), patch skipped\n", wpost);
    return;
  }
  work217_dispatch = (uintptr_t)bl_target(post, wpost);
  int64_t diff = (int64_t)(uintptr_t)&work217_tramp_pre - (int64_t)pre;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[work217] pre-work tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)pre, &nw, sizeof nw) != 0) {
    debugPrintf("[work217] pre-work so_patch_code FAILED\n");
    return;
  }
  debugPrintf("[work217] armed pre-work: entry+0xa0 -> tramp %p\n",
              (void *)&work217_tramp_pre);
  diff = (int64_t)(uintptr_t)&work217_tramp_post - (int64_t)post;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[work217] post-work tramp out of bl range, patch skipped\n");
    return;
  }
  nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)post, &nw, sizeof nw) == 0)
    debugPrintf("[work217] armed post-work: entry+0xa8 -> tramp %p (dispatch NRO+0x%x)\n",
                (void *)&work217_tramp_post, work217_dispatch - base);
  else
    debugPrintf("[work217] post-work so_patch_code FAILED\n");
}

/* ---- build #186: BYPASS thread creation (answers test #185) ----
 * Test #185 proved every CreateThread argument sane (entry, arg,
 * stack, prio 59, core -2) and the core mask sane (#184), yet the
 * worker entry still never executes. The thread mechanism itself is
 * broken in this environment, so #186 stops depending on the spawned
 * thread: the worker entry runs INLINE in the waiter thread.
 * Three sites, all located in NRO #185, patched ALL-OR-NOTHING
 * (a partial bypass is worse than none: the waiter would call
 * SetThreadCoreMask/StartThread on a never-created handle and take
 * its error path instead of proceeding):
 *  (A) Submission's CreateThread bl (submission+0x1b8) -> trampoline
 *      that logs the call, runs the worker entry inline with
 *      x0 = item (a new thread starts with x0 = arg), then fakes
 *      CreateThread success (w0 = 0) and returns to the submission's
 *      post-bl code, which reloads x3/x7 from its own stack and
 *      takes the success path. The trampoline saves/restores
 *      x0-x5 + x19-x21 + x30 across BOTH the logger call and the
 *      entry call, so the post-bl register state matches a real
 *      successful CreateThread except w0 = 0 (which is what success
 *      returns). Stack layout after the six pushes (top first):
 *      [x30][x21][x19,x20][x4,x5][x2,x3][x0,x1] at sp+0x00/0x10/
 *      0x20/0x30/0x40/0x50 (each push is 16 bytes; the str pushes
 *      leave 8 bytes unused). Logger args are loaded from those
 *      slots: entry=[sp+0x58], arg=[sp+0x40], stack=[sp+0x48],
 *      prio=[sp+0x30], core=[sp+0x38]. The entry's own frame is
 *      restored by the epilogue stub (site C), so the trampoline's
 *      pops land on its own stack.
 *  (B) Waiter's SetThreadCoreMask bl (waiter+0xc8) -> branch straight
 *      to the lock site (waiter+0xdc), skipping setmask + StartThread
 *      + both error checks. After the inline entry, the callback has
 *      already set the waiter's flag byte, so the waiter takes its
 *      tbnz path past the syncwait and returns 0 via unlock.
 *  (C) Worker entry's trailing udf (entry+0xac) -> branch to the
 *      epilogue stub, which restores the entry's frame
 *      (ldp x29, x30, [sp], #0x30) and returns to the trampoline.
 *      Without this, the inline entry would fault at the udf (the
 *      entry has no epilogue: it never returns normally, it ends
 *      in udf after the dispatcher call). If the dispatcher never
 *      returns, this site is unreached and harmless.
 * KNOWN RISK, stated plainly: the entry writes worker TLS slots
 * (tag + item pointers at [tpidrro+0x180+0x60/0x68/0x70]) into the
 * WAITER thread's TLS, since it runs in the waiter thread. Those
 * slots are per-job scratch rewritten by every worker entry, so
 * the corruption is bounded; the alternative is parking forever.
 * PATTERN LESSON from this build (durable): the three prologue
 * patterns each match TWICE in NRO #185. The second matches are
 * NOT second copies of the functions: they are prologue bytes
 * packed without bodies (entry prologue + waiter prologue +
 * submission prologue inside 0x40 bytes near NRO+0xa2ffd0, with
 * ASCII data and 0xffffffff where the real code has bl sites).
 * They fail every bl-target check. So the arm function NEVER takes
 * the first match: it iterates ALL matches and picks the one whose
 * verify-first checks pass. A first-match scan would have patched
 * dead bytes and silently done nothing.
 * createthread185_arm is deliberately NOT called in #186: it
 * patches the SAME submission CreateThread bl that site (A)
 * replaces. The bypass trampoline logs the same arguments itself
 * under [bypass186], so no signal is lost. The createthread185
 * code stays in the file, uncalled.
 * Trampoline asm is re-read against the proven pattern before the
 * check: -fsyntax-only does NOT assemble inline asm. */

#define BYPASS186_LOG_CAP 64
__attribute__((used)) static uintptr_t bypass186_entry = 0;
static unsigned bypass186_n = 0;

static const uint8_t PAT_BYPASS186_SUB[] = {
  /* submission prologue, NRO #185 0x8ed9b0..0x8ed9cf (32 bytes). */
  0xfd, 0x7b, 0xb7, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xf5, 0x5b, 0x02, 0xa9,
  0x36, 0xeb, 0x82, 0x52, 0x9f, 0x2c, 0x40, 0xf2, 0xe1, 0x07, 0x00, 0x54,
  0xe7, 0x03, 0x00, 0xaa, 0xe8, 0x03, 0x01, 0xaa
};
static const uint8_t PAT_BYPASS186_WAITER[] = {
  /* waiter prologue, NRO #185 0x8fd290..0x8fd2af (32 bytes). */
  0xfd, 0x7b, 0xb9, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xe5, 0x03, 0x00, 0xaa,
  0xf7, 0x63, 0x03, 0xa9, 0xf8, 0x03, 0x00, 0xaa, 0x60, 0x00, 0x04, 0xaa,
  0x1f, 0x2c, 0x40, 0xf2, 0x41, 0x08, 0x00, 0x54
};
static const uint8_t PAT_BYPASS186_ENTRY[] = {
  /* worker entry prologue incl. tag mov/movk, NRO #185 0x8eddb0..0x8eddc7
   * (24 bytes). The tag 0x21545624 is what makes it worker-specific. */
  0xfd, 0x7b, 0xbd, 0xa9, 0x81, 0xc4, 0x8a, 0x52, 0x81, 0x2a, 0xa4, 0x72,
  0xfd, 0x03, 0x00, 0x91, 0x02, 0x02, 0x80, 0xd2, 0xf3, 0x53, 0x01, 0xa9
};

__attribute__((used)) void bypass186_log_inline(void *entry, void *arg, void *stack, long long prio, long long core, void *cb) {
  if (bypass186_n >= BYPASS186_LOG_CAP) return;
  debugPrintf("[bypass186] inline entry=%p arg=%p stack=%p prio=%lld core=%lld cb=%p (n=%u)\n", entry, arg, stack, prio, core, cb, bypass186_n++);
}

__attribute__((naked, used)) void bypass186_tramp_create(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x3, [sp, #-16]!\n"
    "stp x4, x5, [sp, #-16]!\n"
    "stp x19, x20, [sp, #-16]!\n"
    "str x21, [sp, #-16]!\n"
    "str x30, [sp, #-16]!\n"
    "ldr x4, [sp, #0x38]\n"
    "ldr x3, [sp, #0x30]\n"
    "ldr x2, [sp, #0x48]\n"
    "ldr x1, [sp, #0x40]\n"
    "ldr x0, [sp, #0x58]\n"
    "ldr x5, [sp, #0x40]\n"
    "ldr x5, [x5, #8]\n"
    "bl bypass186_log_inline\n"
    "ldr x0, [sp, #0x40]\n"
    "adrp x16, bypass186_entry\n"
    "ldr x16, [x16, :lo12:bypass186_entry]\n"
    "blr x16\n"
    "ldr x30, [sp], #16\n"
    "ldr x21, [sp], #16\n"
    "ldp x19, x20, [sp], #16\n"
    "ldp x4, x5, [sp], #16\n"
    "ldp x2, x3, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "mov w0, wzr\n"
    "ret\n"
  );
}

__attribute__((naked, used)) void bypass186_entry_epilogue(void) {
  __asm__ volatile (
    "ldp x29, x30, [sp], #0x30\n"
    "ret\n"
  );
}

/* Iterate all pattern matches in [base, base+size) and return the
 * first whose candidate address passes ok(), else 0. */
static uintptr_t scan_verified(uintptr_t base, size_t size, const uint8_t *pat, size_t len, int (*ok)(uintptr_t cand)) {
  if (size < len) return 0;
  const uint8_t *t = (const uint8_t *)base;
  for (size_t i = 0; i + len <= size; i++)
    if (memcmp(t + i, pat, len) == 0 && ok(base + i)) return base + i;
  return 0;
}

static int bypass186_sub_ok(uintptr_t cand) {
  uintptr_t bl = cand + 0x1b8;
  uint32_t w = *(volatile uint32_t *)bl;
  if ((w & 0xFC000000u) != 0x94000000u) return 0;
  uintptr_t tgt = (uintptr_t)bl_target(bl, w);
  return *(volatile uint32_t *)tgt == 0xf81f0fe0u &&
         *(volatile uint32_t *)(tgt + 4) == 0xd4000101u;
}

/* #187 fix: do NOT follow the +0xc8 bl target. coremask184_arm() runs
 * before bypass186_arm() and already redirects that bl to its logging
 * trampoline, so the stub-target check fails on the true waiter (this
 * caused #186's site scan MISS). The +0xc8 word is still required to be
 * a bl (true for the pristine waiter and for the coremask-patched one),
 * and the +0xdc lock-setup word (add x0,sp,#0x64) is untouched by any
 * earlier arm. The known packed-prologue false matches fail both: their
 * +0xc8 words are not bl, and their +0xdc words are data. */
static int bypass186_waiter_ok(uintptr_t cand) {
  uint32_t w = *(volatile uint32_t *)(cand + 0xc8);
  if ((w & 0xFC000000u) != 0x94000000u) return 0;
  return *(volatile uint32_t *)(cand + 0xdc) == 0x910193e0u;
}

static int bypass186_entry_ok(uintptr_t cand) {
  uint32_t w = *(volatile uint32_t *)(cand + 0xa8);
  return (w & 0xFC000000u) == 0x94000000u &&
         *(volatile uint32_t *)(cand + 0xac) == 0x00000000u;
}

void bypass186_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&bypass186_arm)) || !mi.size) {
    debugPrintf("[bypass186] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t sub = scan_verified(base, mi.size, PAT_BYPASS186_SUB, sizeof PAT_BYPASS186_SUB, bypass186_sub_ok);
  uintptr_t waiter = scan_verified(base, mi.size, PAT_BYPASS186_WAITER, sizeof PAT_BYPASS186_WAITER, bypass186_waiter_ok);
  uintptr_t entry = scan_verified(base, mi.size, PAT_BYPASS186_ENTRY, sizeof PAT_BYPASS186_ENTRY, bypass186_entry_ok);
  if (!sub || !waiter || !entry) {
    debugPrintf("[bypass186] site scan MISS (sub=%p waiter=%p entry=%p), patch skipped (all-or-nothing)\n",
                (void *)sub, (void *)waiter, (void *)entry);
    return;
  }
  uintptr_t bl_a = sub + 0x1b8;
  uintptr_t bl_b = waiter + 0xc8;
  uintptr_t lock = waiter + 0xdc;
  uintptr_t udf = entry + 0xac;
  bypass186_entry = entry;
  debugPrintf("[bypass186] sites: sub NRO+0x%x waiter NRO+0x%x entry NRO+0x%x\n",
              sub - base, waiter - base, entry - base);
  int64_t diff_a = (int64_t)(uintptr_t)&bypass186_tramp_create - (int64_t)bl_a;
  int64_t diff_b = (int64_t)lock - (int64_t)bl_b;
  int64_t diff_c = (int64_t)(uintptr_t)&bypass186_entry_epilogue - (int64_t)udf;
  if ((diff_a & 3) || diff_a < -(128 * 1024 * 1024) || diff_a >= (128 * 1024 * 1024) ||
      (diff_b & 3) || diff_b < -(128 * 1024 * 1024) || diff_b >= (128 * 1024 * 1024) ||
      (diff_c & 3) || diff_c < -(128 * 1024 * 1024) || diff_c >= (128 * 1024 * 1024)) {
    debugPrintf("[bypass186] branch out of range, patch skipped (all-or-nothing)\n");
    return;
  }
  uint32_t nw_a = 0x94000000u | ((uint32_t)(diff_a >> 2) & 0x3FFFFFFu);
  uint32_t nw_b = 0x14000000u | ((uint32_t)(diff_b >> 2) & 0x3FFFFFFu);
  uint32_t nw_c = 0x14000000u | ((uint32_t)(diff_c >> 2) & 0x3FFFFFFu);
  int r_a = so_patch_code((void *)bl_a, &nw_a, sizeof nw_a);
  int r_b = so_patch_code((void *)bl_b, &nw_b, sizeof nw_b);
  int r_c = so_patch_code((void *)udf, &nw_c, sizeof nw_c);
  if (r_a == 0 && r_b == 0 && r_c == 0)
    debugPrintf("[bypass186] armed: create bl NRO+0x%x -> tramp %p; setmask bl NRO+0x%x -> b lock NRO+0x%x; entry udf NRO+0x%x -> b epilogue %p\n",
                bl_a - base, (void *)&bypass186_tramp_create, bl_b - base, lock - base,
                udf - base, (void *)&bypass186_entry_epilogue);
  else
    debugPrintf("[bypass186] so_patch_code FAILED (a=%d b=%d c=%d)\n", r_a, r_b, r_c);
}

/* Build #188: waiter lock/unlock logging. The waiter (found with the same
 * prologue pattern + relaxed check as bypass186) returns 0 after its
 * unlock; a waiter-lock line proves the inline entry returned (the
 * submission returned), zero lines proves the hang is inside the
 * entry/callback. Lock bl at waiter+0xe4, unlock bl at waiter+0x10c,
 * verified against the lock/unlock fn prologues (game-code constants,
 * shared with worker183's site table). Logging-only patches: a site that
 * fails verification is skipped individually. */
#define WAITER188_LOG_CAP 64
static unsigned waiter188_n = 0;

/* #216: lock-time verdicts, stored by waiter188_log on the lock path
 * (which prints nothing anymore) so the unlock print can carry them. */
static unsigned waiter216_lock_h = 0, waiter216_lock_w = 0xffffffffu;
static int waiter216_lock_idx = -2;
static unsigned waiter216_lock_r = 0xffffffffu, waiter216_lock_w2 = 0xffffffffu;
static int waiter216_lock_idx2 = -2;
static uintptr_t waiter188_lock = 0;
static uintptr_t waiter188_unlock = 0;

/* Build #222: print-free LOCK-arrival marker.
 * Test #221 proved the waiter gets PAST the setmask svc (START logged
 * both modes) and the game's StartThread returned 0 (the worker runs,
 * and only the game's StartThread could have started it — the re-start
 * loop in waiter188_log never runs, the waiter never reaches the lock
 * bl). The waiter is descheduled somewhere between the StartThread
 * return and the flag check (waiter+0xe8). The next question is whether
 * it ever reaches the lock bl (waiter+0xe4) at all.
 * The lock bl is currently INVISIBLE: #216 removed the lock-path print
 * from waiter188_log, and its verdicts ride only on the syncwait /
 * unlock lines, which never appear. Re-adding a print here is
 * forbidden by the #209 lesson (a print in waiter188_log wedged the
 * waiter — code after the print never ran). So this build uses a
 * print-free marker instead: a single atomic store at the top of the
 * lock path (which==0), which cannot wedge, and the WORKER's existing
 * [signal181] line — which DOES print, after the job completes —
 * reports the marker value. The worker signals strictly after the
 * waiter would have reached the lock bl, so the read is timely.
 * Readings (from the signal line's lock_seen field):
 *   lock_seen=1 -> the waiter reached the lock bl before the worker
 *     signaled; the stall is inside waiter188_log or the lock fn.
 *   lock_seen=0 and no FLAG line -> the waiter never reached the lock
 *     bl within the log; the stall is in the 2-instruction window
 *     after the StartThread return (add/mov) or inside the StartThread
 *     svc's return path — pure descheduling, no code left to probe.
 *   lock_seen=0 but a FLAG line appears later -> the waiter reached
 *     the lock bl after the signal; the FLAG line itself is the proof. */
static volatile unsigned waiter222_lock_seen = 0;

/* Build #223: progress counter inside waiter188_log's lock path.
 * Test #222 proved the waiter REACHES the lock bl (lock_seen=1 both
 * modes) — the #221 reading "stuck in the 2-instruction window after
 * StartThread" is DEAD. The waiter is now pinned to waiter188_log
 * (lock path) or the real lock fn: after the marker store, it runs a
 * poll (timeout 0), a re-start + re-poll, the #218 loop (10x
 * start + 1ms sleep + poll), stores verdicts to statics, and returns —
 * then the tramp br's to the real lock fn. No later line ever appears
 * (no FLAG, no WAIT, no unlock, no spin), so the waiter stops
 * somewhere in that stretch, and the verdict statics are never
 * printed. This build sets a monotonic stage counter at each step
 * (same print-free atomic-store rule as #222 — no print, no SVC in
 * the marker itself) and the worker's [signal181] line reports it.
 * The worker signals strictly after the waiter entered waiter188_log
 * (the waiter has a head start of the worker's whole job), so the
 * snapshot is timely, though the loop is ~10ms and the worker's job
 * is fast — a mid-loop stage means the waiter was in the loop when
 * the worker signaled, not necessarily stuck there.
 * Readings (wstage on the signal line):
 *   1-3  -> stuck early: after the marker but before/during the loop
 *           (1=entered, 2=after poll, 3=after re-start + re-poll).
 *   5-14 -> in the loop at signal time (5+i = after iteration i);
 *           the loop is running, so the re-start loop may be what
 *           starts the worker (the #221 "only the game's StartThread"
 *           derivation relied on the waiter never reaching the lock bl
 *           and is now UNPROVEN — do NOT remove the loop on that basis).
 *   15   -> loop done; 16 = waiter188_log completed and returned —
 *           the stall is in the real lock fn (preamble or fast path),
 *           not in our hook. */
static volatile unsigned waiter223_stage = 0;

__attribute__((used)) void waiter188_log(unsigned which, void *lockarg) {
  /* #216: the lock-path print is REMOVED. #209 proved code after the
   * lock print never executes, and #215's silence (no unlock line, no
   * progress, log ends at the lock line) is consistent with the waiter
   * wedging in OUR hook right after the print — so the game could never
   * observe job completion even if the worker did its job. The poll +
   * re-start (proven to run: they sit before any print) are KEPT, and
   * their verdicts are stored to statics so the unlock print — kept —
   * can carry them. If the waiter proceeds past the lock and the unlock
   * line appears, the wedge was ours and the worker was fine; if the
   * log still ends at setmask, the worker never ran and/or the wedge
   * is elsewhere. The lock path now prints NOTHING. */
  unsigned live210_h = 0, live210_w = 0xffffffffu;
  int live210_idx = -2;
  if (which == 0) {
    /* #222: print-free marker — the waiter reached the lock bl. A plain
     * atomic store; no print, no SVC, cannot wedge (see the #222 comment
     * above). Reported by the worker's [signal181] line. */
    __atomic_store_n(&waiter222_lock_seen, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&waiter223_stage, 1, __ATOMIC_RELEASE);
    live210_h = liveness198_handle;
    if (live210_h) {
      Handle hs = (Handle)live210_h;
      s32 idx = -1;
      live210_w = (unsigned)svcWaitSynchronization(&idx, &hs, 1, 0);
      live210_idx = (int)idx;
    }
    __atomic_store_n(&waiter223_stage, 2, __ATOMIC_RELEASE);
  }
  /* #212: re-start the created thread once, from the waiter thread.
   * The game's StartThread was only INFERRED to return 0 (the waiter
   * reaches its lock); if its helper lied and the thread is still
   * suspended, this second start wakes it — the only probe so far that
   * can fix, not just diagnose. On an already-started thread
   * svcStartThread returns an error and changes nothing. Result + a
   * re-poll are stored to the #216 statics below (no lock print
   * anymore); the unlock print carries them. */
  unsigned live212_r = 0xffffffffu, live212_w2 = 0xffffffffu;
  int live212_idx2 = -2;
  if (which == 0 && live210_h) {
    live212_r = (unsigned)svcStartThread((Handle)live210_h);
    Handle hs2 = (Handle)live210_h;
    s32 idx2 = -1;
    live212_w2 = (unsigned)svcWaitSynchronization(&idx2, &hs2, 1, 0);
    live212_idx2 = (int)idx2;
    __atomic_store_n(&waiter223_stage, 3, __ATOMIC_RELEASE);
  }
  /* #218: re-start LOOP. Retest #217 (same NRO, twice) had zero ENTRY
   * RAN in either mode: with the re-start the thread runs in 4 of 12
   * mode-runs, without it 0 of 4 — scheduling is the dominant blocker
   * and the single re-start is unreliable. So kick the thread 10×
   * (start + 1ms sleep + poll) before the waiter parks, and stop
   * early if the poll signals (wait==0 means the thread ran and then
   * terminated). Pure SVCs, no print on the lock path (still
   * print-free since #216); verdicts go to statics, carried by the
   * [mutex179] syncwait line. The waiter's park is delayed ~10ms —
   * a missed-wakeup needs the whole job to finish inside that window,
   * and the job takes far longer. One variable per build: core mask
   * and priority are NOT touched here. */
  /* #228: restore the #218 re-start loop, with a FLAG break. Tests
   * #225/#226/#227 all gave the same signature (START -> ENTRY RAN ->
   * silence): the burst and the start-and-kick get the worker to its
   * entry but no further, and the waiter never reaches FLAG. Only
   * the #218 loop (10x start + 1ms sleep + poll) ever got the worker
   * to run FULLY (stage 0/1, WORK FN, signal). The loop's sleeps are
   * what give the worker CPU time; the burst/start-and-kick never
   * yield enough. The loop's flaw was that it never exits early: it
   * breaks only when the poll returns 0 (thread terminated), but the
   * worker is a one-shot job runner that tail-jumps and NEVER
   * terminates, so the poll never returns 0 and the waiter sits in
   * the loop for the full 10ms. This version also breaks when the
   * WORKER sets the flag: lockarg is the mutex (item+0x14), so the
   * flag (item+0x10) is lockarg-4, and the worker sets flag=1 before
   * signaling. Breaking on flag lets the waiter exit the loop as soon
   * as the job completes and proceed to the flag check (where it sees
   * flag=1 and unlocks), instead of sleeping through the remaining
   * iterations. The single #212 re-start above is kept; the #225
   * burst and the #226 sleep are removed (replaced by the loop).
   * The #227 start-and-kick in waiter221 stays as background.
   * Readings: FLAG flag=1 + unlock -> the loop+flag-break works, the
   * job completes. FLAG flag=0 + WAIT appears -> the worker runs but
   * the waiter still goes through the wait (loop did not break on
   * flag, or the worker signaled after the waiter left the loop).
   * Worker runs fully but no FLAG -> the waiter is descheduled after
   * the loop (the loop helps the worker, not the waiter). */
  if (which == 0 && live210_h && !waiter218_loop_done) {
    waiter218_loop_done = 1;
    for (unsigned i = 0; i < 10; i++) {
      waiter218_loop_n = i + 1;
      waiter218_loop_r = (unsigned)svcStartThread((Handle)live210_h);
      svcSleepThread(1000000ULL);
      {
        Handle hs = (Handle)live210_h;
        s32 idx = -1;
        waiter218_loop_w = (unsigned)svcWaitSynchronization(&idx, &hs, 1, 0);
      }
      __atomic_store_n(&waiter223_stage, 5 + i, __ATOMIC_RELEASE);
      if (lockarg && *(volatile uint8_t *)((uintptr_t)lockarg - 4)) {
        waiter218_loop_sig = 1;
        break;
      }
      if (waiter218_loop_w == 0) break;
    }
  }
  if (which == 0) {
    __atomic_store_n(&waiter223_stage, 15, __ATOMIC_RELEASE);
    waiter216_lock_h = live210_h;
    waiter216_lock_w = live210_w;
    waiter216_lock_idx = live210_idx;
    waiter216_lock_r = live212_r;
    waiter216_lock_w2 = live212_w2;
    waiter216_lock_idx2 = live212_idx2;
    waiter188_n++;
    __atomic_store_n(&waiter223_stage, 16, __ATOMIC_RELEASE);
    return;
  }
  if (waiter188_n >= WAITER188_LOG_CAP) return;
  debugPrintf("[waiter188] waiter unlock lockarg=%p (n=%u) [lock-time live210] poll handle=%x wait=0x%x idx=%d [live212] restart=0x%x repoll wait=0x%x idx=%d\n", lockarg, waiter188_n++, waiter216_lock_h, waiter216_lock_w, waiter216_lock_idx, waiter216_lock_r, waiter216_lock_w2, waiter216_lock_idx2);
}

__attribute__((naked, used)) void waiter188_tramp_lock(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x1, x0\n"
    "mov x0, #0\n"
    "bl waiter188_log\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, waiter188_lock\n"
    "ldr x16, [x16, :lo12:waiter188_lock]\n"
    "br x16\n"
  );
}

__attribute__((naked, used)) void waiter188_tramp_unlock(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x1, x0\n"
    "mov x0, #1\n"
    "bl waiter188_log\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, waiter188_unlock\n"
    "ldr x16, [x16, :lo12:waiter188_unlock]\n"
    "br x16\n"
  );
}

void waiter188_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&waiter188_arm)) || !mi.size) {
    debugPrintf("[waiter188] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t waiter = scan_verified(base, mi.size, PAT_BYPASS186_WAITER, sizeof PAT_BYPASS186_WAITER, bypass186_waiter_ok);
  if (!waiter) {
    debugPrintf("[waiter188] waiter site scan MISS, patch skipped\n");
    return;
  }
  static const struct { uintptr_t off; unsigned which; uint32_t w[4]; uintptr_t *tgt; void *tramp; const char *label; } sites[2] = {
    /* waiter lock bl -> lock fn (prologue words shared with worker183). */
    { 0xe4, 0, { 0xaa0003e3u, 0xd53bd060u, 0xb941e404u, 0x885ffc60u }, &waiter188_lock, (void *)&waiter188_tramp_lock, "lock" },
    /* waiter unlock bl -> unlock fn. */
    { 0x10c, 1, { 0xd53bd061u, 0xb941e422u, 0x885ffc01u, 0x52800003u }, &waiter188_unlock, (void *)&waiter188_tramp_unlock, "unlock" },
  };
  for (unsigned i = 0; i < 2; i++) {
    uintptr_t bl = waiter + sites[i].off;
    uint32_t w = *(volatile uint32_t *)bl;
    if ((w & 0xFC000000u) != 0x94000000u) {
      debugPrintf("[waiter188] %s bl not BL (word %08x), patch skipped\n", sites[i].label, w);
      continue;
    }
    uintptr_t tgt = (uintptr_t)bl_target(bl, w);
    uint32_t tw0 = *(volatile uint32_t *)tgt;
    uint32_t tw1 = *(volatile uint32_t *)(tgt + 4);
    uint32_t tw2 = *(volatile uint32_t *)(tgt + 8);
    uint32_t tw3 = *(volatile uint32_t *)(tgt + 12);
    if (tw0 != sites[i].w[0] || tw1 != sites[i].w[1] || tw2 != sites[i].w[2] || tw3 != sites[i].w[3]) {
      debugPrintf("[waiter188] %s bl target mismatch, patch skipped\n", sites[i].label);
      continue;
    }
    *sites[i].tgt = tgt;
    int64_t diff = (int64_t)(uintptr_t)sites[i].tramp - (int64_t)bl;
    if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
      debugPrintf("[waiter188] %s tramp out of bl range\n", sites[i].label);
      continue;
    }
    uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
    if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
      debugPrintf("[waiter188] armed %s: bl NRO+0x%x -> tramp %p (fn NRO+0x%x)\n",
                  sites[i].label, bl - base, sites[i].tramp, tgt - base);
    else
      debugPrintf("[waiter188] %s so_patch_code FAILED\n", sites[i].label);
  }
}

/* ---- build #219: waiter-side probe (answers test #218) ----
 * Test #218: the worker ran the full entry + job callback in BOTH
 * modes (ENTRY RAN, stage 0/1, WORK FN, signal — all firsts), yet
 * the game still hangs and the waiter left NO trace after setmask:
 * no syncwait line, no waiter188 unlock line. Disassembly of the
 * delivered #218 NRO explains the silence: the waiter (submitter
 * fn 0x8feb70) waits via the wrapper at 0x8ee660 (bl svc #0x1c stub
 * 0x90351c = WaitProcessWideKeyAtomic), NOT via the mutex179-hooked
 * syncwait wrapper — so the syncwait line can never appear even if
 * the waiter is parked there, and the [live218] loop verdicts (which
 * ride on that line) are unobservable. The waiter is stuck somewhere
 * between its lock bl (waiter+0xe4, where waiter188_log runs) and its
 * unlock bl (waiter+0x10c): in the lock fn, in the wait loop (the
 * flag [sp+0x60] reads 0), or the submitting thread is descheduled.
 * Two patches, both located off the SAME waiter base waiter188_arm
 * finds (PAT_BYPASS186_WAITER + bypass186_waiter_ok — proven in
 * #212-#218), so no new scan:
 *   flag-check: waiter+0xe8 (ldrb w0, [sp, #0x60], word 0x394183e0
 *              read off the delivered #218 NRO, verified with
 *              Capstone — never trust a remembered hex encoding)
 *              -> bl waiter219_tramp_flag, which logs "[waiter219]
 *              FLAG flag=%u", executes the displaced ldrb and rets
 *              to waiter+0xec (the tbnz).
 *   wait-call:  waiter+0xfc (bl wait fn; masked BL check only, the
 *              real target is resolved at runtime via bl_target and
 *              verified: prologue 0xa9bd7bfd (stp #-0x30) + the
 *              POST-bl sequence at +0x2c..+0x38 (mov w1,w0 / and
 *              w2,w0,#0x3fffff / mov w0,#0xea01 / cmp w2,w0).
 *              #220 FIX: the bl at +0x28 must NOT be read through —
 *              it is ALREADY PATCHED by mutex179_arm (which runs
 *              before this arm) to its syncwait tramp, so the word
 *              behind it is the tramp's first instruction (test #219
 *              read 0xf94007e3 there and skipped the patch — my bug,
 *              a direct violation of the verify-first lesson).
 *              -> bl waiter219_tramp_wait, which logs "[waiter219]
 *              WAIT n=%u flag=%u key=%p mutex=%p timeout=%ld" (plus
 *              the [live218] loop verdicts) and br's to the real
 *              wait fn with x30 still holding waiter+0x100, so the
 *              wait fn returns straight to the waiter.
 * Readings: FLAG flag=1 + no WAIT = the waiter passed the flag check
 * (the job IS complete as far as the flag says) and is stuck in the
 * lock fn or descheduled before the wait. WAIT with flag=0, repeated
 * = the waiter IS in the wait loop and the flag never becomes 1
 * (the worker writes a different address than the waiter reads).
 * WAIT with flag=1 = the waiter woke, saw the flag, and the hang is
 * past the unlock. No FLAG line at all = the waiter never reached
 * the flag check (stuck in/before the lock fn, or descheduled). */

#define WAITER219_LOG_CAP 64
static unsigned waiter219_n = 0;
__attribute__((used)) static uintptr_t waiter219_wait_fn = 0;

__attribute__((used)) void waiter219_log(unsigned which, unsigned flag, uintptr_t key, uintptr_t mutex, long timeout) {
  if (which == 0) {
    debugPrintf("[waiter219] FLAG flag=%u\n", flag);
    return;
  }
  if (waiter219_n >= WAITER219_LOG_CAP) return;
  debugPrintf("[waiter219] WAIT n=%u flag=%u key=%p mutex=%p timeout=%ld [live218] loop=%u restart=0x%x poll=0x%x sig=%u\n",
              waiter219_n++, flag, (void *)key, (void *)mutex, timeout,
              waiter218_loop_n, waiter218_loop_r, waiter218_loop_w, waiter218_loop_sig);
}

__attribute__((naked, used)) void waiter219_tramp_flag(void) {
  __asm__ volatile (
    "ldrb w0, [sp, #0x60]\n"
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x3, [sp, #-16]!\n"
    "stp x4, x30, [sp, #-16]!\n"
    "ldr x1, [sp, #32]\n"
    "mov x0, #0\n"
    "mov x2, #0\n"
    "mov x3, #0\n"
    "mov x4, #0\n"
    "bl waiter219_log\n"
    "ldp x4, x30, [sp], #16\n"
    "ldp x2, x3, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "ldrb w0, [sp, #0x60]\n"
    "ret\n"
  );
}

__attribute__((naked, used)) void waiter219_tramp_wait(void) {
  __asm__ volatile (
    "ldrb w3, [sp, #0x60]\n"
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x3, [sp, #-16]!\n"
    "stp x4, x30, [sp, #-16]!\n"
    "mov x0, #1\n"
    "ldr x1, [sp, #24]\n"
    "ldr x2, [sp, #32]\n"
    "ldr x3, [sp, #40]\n"
    "ldr x4, [sp, #16]\n"
    "bl waiter219_log\n"
    "ldp x4, x30, [sp], #16\n"
    "ldp x2, x3, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "adrp x16, waiter219_wait_fn\n"
    "ldr x16, [x16, :lo12:waiter219_wait_fn]\n"
    "br x16\n"
  );
}

void waiter219_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&waiter219_arm)) || !mi.size) {
    debugPrintf("[waiter219] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t waiter = scan_verified(base, mi.size, PAT_BYPASS186_WAITER, sizeof PAT_BYPASS186_WAITER, bypass186_waiter_ok);
  if (!waiter) {
    debugPrintf("[waiter219] waiter site scan MISS, patch skipped\n");
    return;
  }
  /* flag-check site: waiter+0xe8 must be ldrb w0, [sp, #0x60]. */
  uintptr_t flag = waiter + 0xe8;
  if (*(volatile uint32_t *)flag != 0x394183e0u) {
    debugPrintf("[waiter219] flag site not ldrb w0,[sp,#0x60] (word %08x), patch skipped\n",
                *(volatile uint32_t *)flag);
  } else {
    int64_t diff = (int64_t)(uintptr_t)&waiter219_tramp_flag - (int64_t)flag;
    if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
      debugPrintf("[waiter219] flag tramp out of bl range, patch skipped\n");
    } else {
      uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
      if (so_patch_code((void *)flag, &nw, sizeof nw) == 0)
        debugPrintf("[waiter219] armed flag: waiter+0xe8 -> tramp %p\n", (void *)&waiter219_tramp_flag);
      else
        debugPrintf("[waiter219] flag so_patch_code FAILED\n");
    }
  }
  /* wait-call site: waiter+0xfc must be a BL; its target is the wait
   * fn — verify prologue + the post-bl sequence at +0x2c..+0x38.
   * (#220: the +0x28 bl is NOT read — mutex179_arm already patched
   * it to its syncwait tramp; see the header comment.) */
  uintptr_t wait = waiter + 0xfc;
  uint32_t ww = *(volatile uint32_t *)wait;
  if ((ww & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[waiter219] wait site not BL (word %08x), patch skipped\n", ww);
    return;
  }
  uintptr_t wfn = (uintptr_t)bl_target(wait, ww);
  if (*(volatile uint32_t *)wfn != 0xa9bd7bfdu) {
    debugPrintf("[waiter219] wait fn prologue mismatch (word %08x), patch skipped\n",
                *(volatile uint32_t *)wfn);
    return;
  }
  if (*(volatile uint32_t *)(wfn + 0x2c) != 0x2a0003e1u ||
      *(volatile uint32_t *)(wfn + 0x30) != 0x12005402u ||
      *(volatile uint32_t *)(wfn + 0x34) != 0x529d4020u ||
      *(volatile uint32_t *)(wfn + 0x38) != 0x6b00005fu) {
    debugPrintf("[waiter219] wait fn post-bl sequence mismatch (+0x2c=%08x +0x30=%08x +0x34=%08x +0x38=%08x), patch skipped\n",
                *(volatile uint32_t *)(wfn + 0x2c), *(volatile uint32_t *)(wfn + 0x30),
                *(volatile uint32_t *)(wfn + 0x34), *(volatile uint32_t *)(wfn + 0x38));
    return;
  }
  waiter219_wait_fn = wfn;
  int64_t diff = (int64_t)(uintptr_t)&waiter219_tramp_wait - (int64_t)wait;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[waiter219] wait tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)wait, &nw, sizeof nw) == 0)
    debugPrintf("[waiter219] armed wait: waiter+0xfc -> tramp %p (wait fn NRO+0x%x)\n",
                (void *)&waiter219_tramp_wait, wfn - base);
  else
    debugPrintf("[waiter219] wait so_patch_code FAILED\n");
}


/* Build #220: lock-fn retry-loop spin probe.
 * Test #219 answered the flag question: the waiter NEVER reaches the
 * flag check (waiter+0xe8) — zero [waiter219] FLAG lines in either mode
 * with the flag tramp armed. The only code between the lock bl
 * (waiter+0xe4, where waiter188_log runs — bounded, ~10ms) and the
 * flag check is the real lock fn (waiter188_lock, resolved by
 * waiter188_arm, which runs before this arm). The lock fn's slow path
 * would log a [mutex179] wait line — absent in #219 — so if the waiter
 * is executing at all it is spinning in the lock fn's stlxr retry loop
 * (lock+0xc0: ldaxr w0,[x3] / b back to the fast-path check; words
 * 0x885ffc60 / 0x17ffffd3 read off the delivered #219 NRO with
 * Capstone). The alternative is that the submitting thread is
 * descheduled inside the lock fn.
 * This probe patches the retry-loop ldaxr with a bl to
 * waiter220_tramp_spin, which logs "[lockspin] spin mutex=%p tid=%u
 * (n=%u)" — capped at 8, so a tight spin cannot flood the log — then
 * executes the displaced ldaxr and returns to lock+0xc4 (the b).
 * Readings: [lockspin] lines appear = the waiter (or the worker — the
 * tid distinguishes them) IS spinning in the retry loop, i.e. an
 * exclusive-monitor livelock on the job mutex. No [lockspin] lines =
 * no thread is spinning there, so the waiter is descheduled. */
#define WAITER220_LOG_CAP 8
static unsigned waiter220_n = 0;

__attribute__((used)) void waiter220_log_spin(uintptr_t mutex, unsigned tid) {
  if (waiter220_n >= WAITER220_LOG_CAP) return;
  debugPrintf("[lockspin] spin mutex=%p tid=%u (n=%u)\n", (void *)mutex, tid, waiter220_n++);
}

__attribute__((naked, used)) void waiter220_tramp_spin(void) {
  __asm__ volatile (
    "mrs x0, tpidrro_el0\n"
    "ldr w0, [x0, #0x1e4]\n"
    "stp x0, x3, [sp, #-16]!\n"
    "stp x4, x30, [sp, #-16]!\n"
    "mov x1, x0\n"
    "mov x0, x3\n"
    "bl waiter220_log_spin\n"
    "ldp x4, x30, [sp], #16\n"
    "ldp x0, x3, [sp], #16\n"
    "ldaxr w0, [x3]\n"
    "ret\n"
  );
}

void waiter220_arm(void) {
  if (!waiter188_lock) {
    debugPrintf("[lockspin] waiter188_lock unknown, patch skipped\n");
    return;
  }
  uintptr_t loop = waiter188_lock + 0xc0;
  if (*(volatile uint32_t *)loop != 0x885ffc60u ||
      *(volatile uint32_t *)(loop + 4) != 0x17ffffd3u) {
    debugPrintf("[lockspin] retry loop mismatch (loop=%08x +4=%08x), patch skipped\n",
                *(volatile uint32_t *)loop, *(volatile uint32_t *)(loop + 4));
    return;
  }
  int64_t diff = (int64_t)(uintptr_t)&waiter220_tramp_spin - (int64_t)loop;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[lockspin] spin tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)loop, &nw, sizeof nw) == 0)
    debugPrintf("[lockspin] armed retry loop: lock+0xc0 -> tramp %p\n", (void *)&waiter220_tramp_spin);
  else
    debugPrintf("[lockspin] spin so_patch_code FAILED\n");
}


/* Build #221: StartThread-call probe.
 * Test #220 answered the spin question: the waiter is DESCHEDULED, not
 * spinning — zero [lockspin] lines, and the waiter never even reached
 * the lock fn. Its last observable point is the setmask bl
 * (waiter+0xc8): the coremask184 tramp logs BEFORE jumping to the svc
 * stub, so the setmask line proves the waiter REACHED the setmask bl,
 * not that the svc returned. The waiter never reached the lock bl
 * (waiter+0xe4). The window between them holds only the setmask svc
 * (#0xf), a cbnz, a mov, the StartThread helper bl (waiter+0xd4), a
 * cbnz, an add, a mov — and the lock bl. This probe patches the
 * StartThread bl with a bl to waiter221_tramp_start, which logs
 * "[waiter221] START handle=%x (n=%u)" (the handle is [x0], the
 * thread-arg struct's first word, read before the call) and then br's
 * to the real StartThread helper with x30 still holding waiter+0xd8,
 * so the helper returns straight to the waiter. The helper is verified
 * by shape: prologue `ldr w0, [x0]` (0xb9400000) + a `b` whose target
 * word is 0xd4000121 (svc #9) — both read off the delivered #220 NRO
 * with Capstone. The +0xd4 site is not patched by any earlier arm, so
 * the verify-first rule is respected.
 * Readings: START appears = the waiter got past the setmask svc and
 * reached the StartThread call; the stall is in/after StartThread (or
 * descheduled between StartThread and the lock bl). START never
 * appears = the waiter never got past the setmask svc — it is stuck
 * inside svc #0xf or descheduled immediately after the setmask bl. */
#define WAITER221_LOG_CAP 16
static unsigned waiter221_n = 0;
__attribute__((used)) static uintptr_t waiter221_start_fn = 0;

/* #227: start-and-kick. The tramp now calls this C function with the
 * thread-arg struct (x0) and the function RETURNS the game's
 * StartThread result in x0, so the waiter sees it and proceeds
 * normally. The function (1) logs START, (2) calls the game's
 * StartThread helper through waiter221_start_fn, (3) kicks the
 * worker once with svcStartThread and IGNORES the result (0xFA01,
 * already started). The kick must NOT overwrite w0: if the waiter
 * saw 0xFA01 it would take the error path (cbnz at waiter+0xd8).
 * The helper is callable as a C function: it is `ldr w0,[x0]` +
 * `b` to a stub that is `svc #9` + `ret` (verified off the
 * delivered #226 NRO: helper 0x8eff70, stub 0x903ccc, word after
 * the svc is 0xd65f03c0), so the stub's ret returns to the caller.
 * The kick happens EARLY (at the StartThread call, before the lock
 * bl and the flag check), giving the worker a head start without
 * the burst's 5 back-to-back SVCs and without any sleep delaying
 * the waiter. Test #225/#226 showed the burst gets the worker to
 * ENTRY RAN but deschedules the waiter before FLAG, while #224
 * (no burst) lets the waiter reach FLAG but never runs the worker.
 * If the worker runs and signals before the waiter reaches FLAG,
 * the waiter sees flag=1 and skips the wait entirely. */
__attribute__((used)) unsigned waiter221_log(void *arg) {
  unsigned handle = *(volatile unsigned *)arg;
  if (waiter221_n < WAITER221_LOG_CAP)
    debugPrintf("[waiter221] START handle=%x (n=%u)\n", handle, waiter221_n++);
  int ret = ((int (*)(void *))waiter221_start_fn)(arg);
  (void)svcStartThread((Handle)handle);
  return (unsigned)ret;
}

__attribute__((naked, used)) void waiter221_tramp_start(void) {
  __asm__ volatile (
    "stp x1, x2, [sp, #-16]!\n"
    "stp x3, x4, [sp, #-16]!\n"
    "str x30, [sp, #-16]!\n"
    "bl waiter221_log\n"
    "ldr x30, [sp], #16\n"
    "ldp x3, x4, [sp], #16\n"
    "ldp x1, x2, [sp], #16\n"
    "ret\n"
  );
}

void waiter221_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&waiter221_arm)) || !mi.size) {
    debugPrintf("[waiter221] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t waiter = scan_verified(base, mi.size, PAT_BYPASS186_WAITER, sizeof PAT_BYPASS186_WAITER, bypass186_waiter_ok);
  if (!waiter) {
    debugPrintf("[waiter221] waiter site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t start = waiter + 0xd4;
  uint32_t sw = *(volatile uint32_t *)start;
  if ((sw & 0xFC000000u) != 0x94000000u) {
    debugPrintf("[waiter221] start site not BL (word %08x), patch skipped\n", sw);
    return;
  }
  uintptr_t hfn = (uintptr_t)bl_target(start, sw);
  if (*(volatile uint32_t *)hfn != 0xb9400000u) {
    debugPrintf("[waiter221] start helper prologue mismatch (word %08x), patch skipped\n",
                *(volatile uint32_t *)hfn);
    return;
  }
  uint32_t bw = *(volatile uint32_t *)(hfn + 4);
  if ((bw & 0xFC000000u) != 0x14000000u) {
    debugPrintf("[waiter221] start helper +4 not B (word %08x), patch skipped\n", bw);
    return;
  }
  uintptr_t stub = (uintptr_t)bl_target(hfn + 4, bw);
  if (*(volatile uint32_t *)stub != 0xd4000121u) {
    debugPrintf("[waiter221] start helper stub not svc #9 (word %08x), patch skipped\n",
                *(volatile uint32_t *)stub);
    return;
  }
  waiter221_start_fn = hfn;
  int64_t diff = (int64_t)(uintptr_t)&waiter221_tramp_start - (int64_t)start;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[waiter221] start tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)start, &nw, sizeof nw) == 0)
    debugPrintf("[waiter221] armed start: waiter+0xd4 -> tramp %p (helper NRO+0x%x)\n",
                (void *)&waiter221_tramp_start, hfn - base);
  else
    debugPrintf("[waiter221] start so_patch_code FAILED\n");
}


/* Build #190: log the completion callback's chained function. The callback
 * (found via its prologue pattern + verify-first) does lock -> flag=1 ->
 * signal -> unlock -> blr x21 (chained fn, arg in x0) -> tail-call to the
 * small dispatcher-calling fn. Since #189 proved the entry never returns
 * after the signal, the hang is in the callback tail: its unlock, the
 * chained fn, or the tail fn. This patch replaces the blr x21 (callback
 * +0x40) with a bl to a trampoline that logs the chained fn + arg + the
 * mapping base containing the fn (via svcQueryMemory, so the address is
 * self-identifying even if it lands outside the NRO), then jumps to the
 * chained fn with the original arg and return address intact. Reading
 * the log: no [chain190] line = hang in the callback unlock (before the
 * chained call); a [chain190] line with no stage 2 = hang in the chained
 * fn or the tail fn; a [chain190] line plus stage 2 = the entry resumed.
 * The patch touches only callback+0x40, which no earlier arm patches. */
#define CHAIN190_LOG_CAP 64
static unsigned chain190_n = 0;

static const uint8_t PAT_CHAIN190_CB[] = {
  0xfd, 0x7b, 0xbd, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xf3, 0x53, 0x01, 0xa9,
  0xf3, 0x03, 0x00, 0xaa, 0xf5, 0x5b, 0x02, 0xa9, 0x15, 0x58, 0x40, 0xa9
};

__attribute__((used)) void chain190_log(void *fn, void *arg) {
  if (chain190_n >= CHAIN190_LOG_CAP) return;
  MemoryInfo mi; u32 pi;
  uintptr_t mapbase = 0;
  if (!R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)fn)) && mi.size)
    mapbase = mi.addr;
  debugPrintf("[chain190] chained fn=%p arg=%p mapbase=%p (n=%u)\n", fn, arg, (void *)mapbase, chain190_n++);
}

__attribute__((naked, used)) void chain190_tramp(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "mov x1, x0\n"
    "mov x0, x21\n"
    "bl chain190_log\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "br x21\n"
  );
}

static int chain190_cb_ok(uintptr_t cand) {
  /* blr x21 at +0x40, and the lock bl at +0x1c must reach the lock fn
   * prologue (same words as worker183's lock site table). */
  if (*(volatile uint32_t *)(cand + 0x40) != 0xd63f02a0u) return 0;
  uint32_t w = *(volatile uint32_t *)(cand + 0x1c);
  if ((w & 0xFC000000u) != 0x94000000u) return 0;
  uintptr_t t = (uintptr_t)bl_target(cand + 0x1c, w);
  return *(volatile uint32_t *)t == 0xaa0003e3u &&
         *(volatile uint32_t *)(t + 4) == 0xd53bd060u &&
         *(volatile uint32_t *)(t + 8) == 0xb941e404u &&
         *(volatile uint32_t *)(t + 12) == 0x885ffc60u;
}

void chain190_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&chain190_arm)) || !mi.size) {
    debugPrintf("[chain190] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t cb = scan_verified(base, mi.size, PAT_CHAIN190_CB, sizeof PAT_CHAIN190_CB, chain190_cb_ok);
  if (!cb) {
    debugPrintf("[chain190] callback site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t blr = cb + 0x40;
  int64_t diff = (int64_t)(uintptr_t)&chain190_tramp - (int64_t)blr;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[chain190] tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)blr, &nw, sizeof nw) == 0)
    debugPrintf("[chain190] armed blr: NRO+0x%x -> tramp %p\n", blr - base, (void *)&chain190_tramp);
  else
    debugPrintf("[chain190] so_patch_code FAILED\n");
}


/* Build #191: log the chained function's spin-wait loop. The chained fn
 * (found via its prologue pattern + verify-first) spins while a global
 * pointer [struct+0x90] is NULL: mov w0,#1; bl wait-helper; reload; cbz
 * back. #190 proved the flow reaches the chained fn and then goes silent,
 * so the hang is either this spin (pointer never published) or downstream
 * (table loop / tail fn). This patch replaces the loop's wait bl (fn+0x2c)
 * with a bl to a trampoline that FIRST calls the original wait helper
 * (target resolved at arm time, so the wait still happens exactly as
 * before), THEN logs the post-wait pointer value read fresh from
 * [x21,#0x90] — the exact value the loop's cbz will test — and returns
 * to the loop with all registers and the stack intact. Reading the log:
 * 64 NULL lines and no stage 2 = spin confirmed (pointer never published,
 * next hunt is the publisher); a non-NULL line followed by stage 2 / waiter
 * lines = the fn proceeded, hang is downstream. The patch touches only
 * fn+0x2c, which no earlier arm patches. */
#define SPIN191_LOG_CAP 64
static unsigned spin191_n = 0;
static uintptr_t spin191_target = 0;

static const uint8_t PAT_SPIN191_FN[] = {
  0xff, 0x03, 0x02, 0xd1, 0xfd, 0x7b, 0x04, 0xa9, 0xfd, 0x03, 0x01, 0x91,
  0xf3, 0x53, 0x05, 0xa9, 0xf5, 0x5b, 0x06, 0xa9
};

__attribute__((used)) void spin191_log(void *ptr) {
  if (spin191_n >= SPIN191_LOG_CAP) return;
  debugPrintf("[spin191] iter=%u ptr=%p\n", spin191_n++, ptr);
}

__attribute__((naked, used)) void spin191_tramp(void) {
  __asm__ volatile (
    "stp x0, x1, [sp, #-16]!\n"
    "stp x2, x30, [sp, #-16]!\n"
    "str x30, [sp, #-16]!\n"
    "adrp x16, spin191_target\n"
    "ldr x16, [x16, :lo12:spin191_target]\n"
    "blr x16\n"
    "ldr x30, [sp], #16\n"
    "ldr x0, [x21, #0x90]\n"
    "bl spin191_log\n"
    "ldp x2, x30, [sp], #16\n"
    "ldp x0, x1, [sp], #16\n"
    "ret\n"
  );
}

static int spin191_fn_ok(uintptr_t cand) {
  /* add x21,x19,#imm at +0x18 (SHAPE check, #193: the immediate is an
   * address-immediate — it shifted #191->#192 as wrapper growth moved the
   * struct, so only the opcode/registers are pinned, not the immediate);
   * ldr x20,[x21,#0x90] at +0x20; loop wait bl at +0x2c reaching the
   * wait-helper prologue; cbz x20 back to the loop head at +0x34. */
  if ((*(volatile uint32_t *)(cand + 0x18) & 0xFFC003FFu) != 0x91000275u) return 0;
  if (*(volatile uint32_t *)(cand + 0x20) != 0xf9404ab4u) return 0;
  if (*(volatile uint32_t *)(cand + 0x34) != 0xb4ffffb4u) return 0;
  uint32_t w = *(volatile uint32_t *)(cand + 0x2c);
  if ((w & 0xFC000000u) != 0x94000000u) return 0;
  uintptr_t t = (uintptr_t)bl_target(cand + 0x2c, w);
  return *(volatile uint32_t *)t == 0xa9be7bfdu &&
         *(volatile uint32_t *)(t + 4) == 0x2a0003e0u &&
         *(volatile uint32_t *)(t + 8) == 0x910003fdu &&
         *(volatile uint32_t *)(t + 12) == 0x910043e1u;
}

void spin191_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&spin191_arm)) || !mi.size) {
    debugPrintf("[spin191] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t fn = scan_verified(base, mi.size, PAT_SPIN191_FN, sizeof PAT_SPIN191_FN, spin191_fn_ok);
  if (!fn) {
    debugPrintf("[spin191] chained fn site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = fn + 0x2c;
  spin191_target = (uintptr_t)bl_target(bl, *(volatile uint32_t *)bl);
  int64_t diff = (int64_t)(uintptr_t)&spin191_tramp - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[spin191] tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[spin191] armed loop wait: bl NRO+0x%x -> tramp %p (wait fn NRO+0x%x)\n",
                bl - base, (void *)&spin191_tramp, spin191_target - base);
  else
    debugPrintf("[spin191] so_patch_code FAILED\n");
}

/* Build #192: table-loop processor call probe (follow-up to #191).
 *
 * TEST #191 refuted the spin hypothesis: [spin191] armed but produced ZERO
 * iter lines, so the chained fn's prologue cbnz skipped the spin loop (the
 * global pointer was already non-NULL) and the hang is inside the chained
 * fn's table region. That loop (head: ldr x1,[x24]) reads the queue pointers
 * fresh each iteration but NOTHING in it advances them, and it has NO exit
 * branch — every path (process / unaligned / null entry) funnels through
 * the per-entry processor bl at fn+0xc4 and a wait(5) back to the head.
 * The processor itself is bounded (lock -> work-or-init -> unlock -> ret),
 * so the fn behaves like a worker loop that only stops if a callee never
 * returns. This patch logs entry/exit around that bl, distinguishing:
 *   enter/exit pairs with the same x1 and a climbing counter = the loop
 *   reprocessing the same entry forever (queue never advances);
 *   enter without exit = parked inside the processor (lock / inner work);
 *   exit without a next enter = parked in the wait(5) after the call.
 * ZERO-STACK TRAMPOLINE (critical, unlike spin191): this bl passes STACK
 * args ([sp..sp+0x38]) and the processor computes its caller-sp as
 * sp+0x130, so any push before the call would shift the callee's view of
 * its stack args. The trampoline therefore never touches sp: it saves the
 * return address and all register args (x0,x1,x2,x3,x4,x5,x6,x7,x13) to
 * globals, logs, restores them, calls the original target, logs exit,
 * restores the return address and returns. The patch touches only fn+0xc4,
 * which no earlier arm patches, and the verify fn checks only bytes no
 * earlier arm touches (spin191 patches +0x2c, which is NOT checked here).
 * #194 QUEUE-STATE PROBE (why: TEST #193 proved x1=0 on all 64 logged
 * iterations, and the #193 NRO disassembly shows x1 at the call IS [x24]
 * loaded at the loop head -- every path head->call leaves x1 untouched --
 * so [x24] was NULL on every iteration; the loop body stores only to [sp]
 * (call args) and never to [x24]/[x23]/[x22]/[x20], so the queue can only
 * advance from outside the loop (a producer, or the processor via globals)
 * -- and the processor returned 64/64 times without [x24] ever changing.
 * The #194 log therefore records the FULL queue state per iteration: the
 * call args (x0 is always the const context pointer the call path moves
 * into x0 before the bl; x2 = flag byte [x23], x3 = word [x22],
 * x4 = value [x20], x5/x6/x7/x13 = entry fields on the aligned path, 0 on
 * the NULL path) plus the slot addresses themselves (q20/q22/q23/q24) plus
 * the processor return value at exit. Constant x2/x3/x4 + constant slots
 * + x1=0 across the cap means a fully static queue (producer missing);
 * any movement localises the writer. Cap raised 64->256, with a one-time
 * cap-hit line and a short state sample every 4096 iterations past cap so
 * late queue changes are not invisible. x0-on-return semantics are
 * DELIBERATELY unchanged from #193 (log_exit residue, retval only logged,
 * not restored) -- zero behaviour change to the loop. */
#define TABLE192_LOG_CAP 256
__attribute__((used)) static unsigned table192_n = 0;
__attribute__((used)) static unsigned table192_last_n = 0;
__attribute__((used)) static uintptr_t table192_target = 0;
__attribute__((used)) static uintptr_t table192_ret = 0;
__attribute__((used)) static uintptr_t table192_x0 = 0;
__attribute__((used)) static uintptr_t table192_x1 = 0;
__attribute__((used)) static uintptr_t table192_x2 = 0;
__attribute__((used)) static uintptr_t table192_x3 = 0;
__attribute__((used)) static uintptr_t table192_x4 = 0;
__attribute__((used)) static uintptr_t table192_x5 = 0;
__attribute__((used)) static uintptr_t table192_x6 = 0;
__attribute__((used)) static uintptr_t table192_x7 = 0;
__attribute__((used)) static uintptr_t table192_x13 = 0;
__attribute__((used)) static uintptr_t table192_q20 = 0;
__attribute__((used)) static uintptr_t table192_q22 = 0;
__attribute__((used)) static uintptr_t table192_q23 = 0;
__attribute__((used)) static uintptr_t table192_q24 = 0;
__attribute__((used)) static uintptr_t table192_retval = 0;

__attribute__((used)) void table192_log_enter(void *x1) {
  unsigned n = table192_n++;
  table192_last_n = n;
  if (n == TABLE192_LOG_CAP)
    debugPrintf("[table192] cap reached, further pairs silent (samples every 4096)\n");
  if (n < TABLE192_LOG_CAP)
    debugPrintf("[table192] enter n=%u x0=%p x1=%p x2=%p x3=%p x4=%p x5=%p x6=%p x7=%p x13=%p q20=%p q22=%p q23=%p q24=%p\n",
                n, (void *)table192_x0, x1, (void *)table192_x2, (void *)table192_x3,
                (void *)table192_x4, (void *)table192_x5, (void *)table192_x6,
                (void *)table192_x7, (void *)table192_x13, (void *)table192_q20,
                (void *)table192_q22, (void *)table192_q23, (void *)table192_q24);
  else if ((n & 4095u) == 0)
    debugPrintf("[table192] sample n=%u x1=%p x2=%p x3=%p x4=%p q24=%p\n",
                n, x1, (void *)table192_x2, (void *)table192_x3,
                (void *)table192_x4, (void *)table192_q24);
}

__attribute__((used)) void table192_log_exit(void) {
  if (table192_last_n < TABLE192_LOG_CAP)
    debugPrintf("[table192] exit n=%u ret=%p\n", table192_last_n, (void *)table192_retval);
}

__attribute__((naked, used)) void table192_tramp(void) {
  __asm__ volatile (
    "adrp x16, table192_ret\n"
    "str x30, [x16, :lo12:table192_ret]\n"
    "adrp x16, table192_x0\n"
    "str x0, [x16, :lo12:table192_x0]\n"
    "adrp x16, table192_x1\n"
    "str x1, [x16, :lo12:table192_x1]\n"
    "adrp x16, table192_x2\n"
    "str x2, [x16, :lo12:table192_x2]\n"
    "adrp x16, table192_x3\n"
    "str x3, [x16, :lo12:table192_x3]\n"
    "adrp x16, table192_x4\n"
    "str x4, [x16, :lo12:table192_x4]\n"
    "adrp x16, table192_x5\n"
    "str x5, [x16, :lo12:table192_x5]\n"
    "adrp x16, table192_x6\n"
    "str x6, [x16, :lo12:table192_x6]\n"
    "adrp x16, table192_x7\n"
    "str x7, [x16, :lo12:table192_x7]\n"
    "adrp x16, table192_x13\n"
    "str x13, [x16, :lo12:table192_x13]\n"
    "adrp x16, table192_q20\n"
    "str x20, [x16, :lo12:table192_q20]\n"
    "adrp x16, table192_q22\n"
    "str x22, [x16, :lo12:table192_q22]\n"
    "adrp x16, table192_q23\n"
    "str x23, [x16, :lo12:table192_q23]\n"
    "adrp x16, table192_q24\n"
    "str x24, [x16, :lo12:table192_q24]\n"
    "adrp x16, table192_x1\n"
    "ldr x0, [x16, :lo12:table192_x1]\n"
    "bl table192_log_enter\n"
    "adrp x16, table192_x0\n"
    "ldr x0, [x16, :lo12:table192_x0]\n"
    "adrp x16, table192_x1\n"
    "ldr x1, [x16, :lo12:table192_x1]\n"
    "adrp x16, table192_x2\n"
    "ldr x2, [x16, :lo12:table192_x2]\n"
    "adrp x16, table192_x3\n"
    "ldr x3, [x16, :lo12:table192_x3]\n"
    "adrp x16, table192_x4\n"
    "ldr x4, [x16, :lo12:table192_x4]\n"
    "adrp x16, table192_x5\n"
    "ldr x5, [x16, :lo12:table192_x5]\n"
    "adrp x16, table192_x6\n"
    "ldr x6, [x16, :lo12:table192_x6]\n"
    "adrp x16, table192_x7\n"
    "ldr x7, [x16, :lo12:table192_x7]\n"
    "adrp x16, table192_x13\n"
    "ldr x13, [x16, :lo12:table192_x13]\n"
    "adrp x16, table192_q20\n"
    "ldr x20, [x16, :lo12:table192_q20]\n"
    "adrp x16, table192_q22\n"
    "ldr x22, [x16, :lo12:table192_q22]\n"
    "adrp x16, table192_q23\n"
    "ldr x23, [x16, :lo12:table192_q23]\n"
    "adrp x16, table192_q24\n"
    "ldr x24, [x16, :lo12:table192_q24]\n"
    "adrp x16, table192_target\n"
    "ldr x16, [x16, :lo12:table192_target]\n"
    "blr x16\n"
    "adrp x16, table192_retval\n"
    "str x0, [x16, :lo12:table192_retval]\n"
    "bl table192_log_exit\n"
    "adrp x16, table192_ret\n"
    "ldr x30, [x16, :lo12:table192_ret]\n"
    "ret\n"
  );
}

static int table192_fn_ok(uintptr_t cand) {
  /* add x21,x19,#imm at +0x18 (SHAPE check, #193: address-immediate,
   * see spin191_fn_ok); ldr x20,[x21,#0x90] at +0x20; cbnz x20 to the
   * table setup at +0x24; per-entry processor bl at +0xc4 reaching the
   * processor prologue; loop head ldr x1,[x24] at +0xd0. */
  if ((*(volatile uint32_t *)(cand + 0x18) & 0xFFC003FFu) != 0x91000275u) return 0;
  if (*(volatile uint32_t *)(cand + 0x20) != 0xf9404ab4u) return 0;
  if (*(volatile uint32_t *)(cand + 0x24) != 0xb50000b4u) return 0;
  if (*(volatile uint32_t *)(cand + 0xd0) != 0xf9400301u) return 0;
  uint32_t w = *(volatile uint32_t *)(cand + 0xc4);
  if ((w & 0xFC000000u) != 0x94000000u) return 0;
  uintptr_t t = (uintptr_t)bl_target(cand + 0xc4, w);
  return *(volatile uint32_t *)t == 0xa9ad7bfdu &&
         *(volatile uint32_t *)(t + 4) == 0x910003fdu &&
         *(volatile uint32_t *)(t + 8) == 0xa90153f3u &&
         /* adrp x20 at +12 (SHAPE check, #193: its page immediate shifted
          * #191->#192 with the struct, so only opcode/registers pinned). */
         ((*(volatile uint32_t *)(t + 12) & 0x9F00001Fu) == 0x90000014u);
}

void table192_arm(void) {
  MemoryInfo mi; u32 pi;
  if (R_FAILED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&table192_arm)) || !mi.size) {
    debugPrintf("[table192] nro base resolve FAILED, patch skipped\n");
    return;
  }
  uintptr_t base = mi.addr;
  uintptr_t fn = scan_verified(base, mi.size, PAT_SPIN191_FN, sizeof PAT_SPIN191_FN, table192_fn_ok);
  if (!fn) {
    debugPrintf("[table192] chained fn site scan MISS, patch skipped\n");
    return;
  }
  uintptr_t bl = fn + 0xc4;
  table192_target = (uintptr_t)bl_target(bl, *(volatile uint32_t *)bl);
  int64_t diff = (int64_t)(uintptr_t)&table192_tramp - (int64_t)bl;
  if ((diff & 3) || diff < -(128 * 1024 * 1024) || diff >= (128 * 1024 * 1024)) {
    debugPrintf("[table192] tramp out of bl range, patch skipped\n");
    return;
  }
  uint32_t nw = 0x94000000u | ((uint32_t)(diff >> 2) & 0x3FFFFFFu);
  if (so_patch_code((void *)bl, &nw, sizeof nw) == 0)
    debugPrintf("[table192] armed proc bl: bl NRO+0x%x -> tramp %p (proc fn NRO+0x%x)\n",
                bl - base, (void *)&table192_tramp, table192_target - base);
  else
    debugPrintf("[table192] so_patch_code FAILED\n");
}
