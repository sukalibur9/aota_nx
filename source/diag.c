/* diag.c -- see diag.h. Frame-1 black-hang instrumentation.
 *
 * This software may be modified and distributed under the terms of the MIT
 * license. See the LICENSE file for details.
 */
#define _GNU_SOURCE
#include <switch.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>   /* aligned_alloc/free for the #265 heap-lock probe */
#include <stdarg.h>
#include <stdint.h>
#include <fcntl.h>    /* #290: open() for the lossless wd290.log */
#include <unistd.h>   /* #290: write() for the lossless wd290.log */

#include "diag.h"
#include "util.h"   /* debugPrintf */
#include "so_util.h" /* so_find_module_by_addr for backtrace symbolication */

/* ------------------------------------------------------------------ tunables */
#define DIAG_MAX_THREADS   96
#define DIAG_POLL_NS       (1000ull * 1000ull * 1000ull)   /* watchdog tick: 1s */
#define DIAG_STALL_NS      (6000ull * 1000ull * 1000ull)   /* declare stall: 6s  */
#define DIAG_REDUMP_NS     (6000ull * 1000ull * 1000ull)   /* re-dump cadence    */
/* #291: periodic snapshots. Test #290 (build #289) proved the progress
 * heartbeat is blind to the boot park: g_last_progress is only refreshed
 * BETWEEN nativeRender calls, so while frame 0 runs for minutes the stall
 * timer does fire -- yet debug.log held no [wd] STALL at all, while the
 * frame-0 park left the log mid-nativeRender. Whatever silences the dump
 * (wedged poll sleep, dropped line, dump path) must not also hide the
 * thread table, so take a bounded series of UNCONDITIONAL snapshots in the
 * first minute. Six dumps at 10s intervals: their presence proves the
 * watchdog thread runs and shows where frame 0 sits; their ABSENCE is just
 * as informative (the watchdog never got scheduled). */
#define DIAG_STATE_NS      (2000ull * 1000ull * 1000ull)   /* snapshot cadence   */
#define DIAG_STATE_DUMPS   10
/* #292: test #291 answered "did the watchdog thread start?" -- wd290.log holds
 * exactly one line, "[wd291] watchdog thread running", and then NOTHING, not
 * even the first STATE #1 at 10 s. Either the first 1 s poll sleep never
 * returned or the whole process (every thread, including this one) stopped at
 * the same moment debug.log did. Three markers settle it without guessing:
 *   [wd292] awake n=..        printed right after each poll sleep returns
 *                             -> a frozen n means the sleep never returns;
 *   [wd] snap <name>: pause   printed before svcSetThreadActivity, so a dump
 *                             that hangs names the exact thread it hung on;
 *   [s292] alive n=..         an independent sentinel thread on its own file
 *                             -> silence there means a process-wide freeze,
 *                             not a watchdog-only problem.
 * First snapshot at 2 s instead of 10 s: the process died inside the first
 * seconds of the render loop, earlier than any 10 s cadence could observe. */

typedef struct {
  volatile int          in_use;
  uint64_t              tid;            /* svcGetThreadId — matches crash reports */
  Handle                handle;         /* real thread handle for svcGetThreadContext3 */
  uintptr_t             tp;             /* #298: this thread's tpidrro_el0, captured
                                         * at registration -- the key that maps a
                                         * mutex holder (holder_tp from the lock
                                         * path) to its thread for PC sampling */
  pthread_t             pth;            /* host handle, for setname target match  */
  char                  name[32];
  const void           *entry;
  int                   is_main_engine;
  /* live wait beacon */
  volatile int          wait_kind;
  volatile const void  *wait_obj;
  volatile uint64_t     wait_since;     /* tick (raw) when current wait began     */
  /* liveness counters */
  volatile uint64_t     waits_total;
  volatile uint64_t     wakes_total;
  volatile uint64_t     futex_spins;
  volatile uint64_t     last_active;    /* tick of last beacon activity           */
} DiagThread;

static DiagThread       g_threads[DIAG_MAX_THREADS];
static Mutex            g_reg_lock;     /* zero-init libnx Mutex == unlocked       */
static __thread DiagThread *self;       /* this thread's slot (host TLS)           */

static volatile int      g_dump_periodic;   /* #291: header text selector      */
static volatile int      g_frame = -1;
static volatile uint64_t g_last_progress;   /* tick of last diag_frame()           */
static volatile int      g_wd_started;
static Thread            g_wd_thread;

/* ------------------------------------------------------------------ helpers */
static inline uint64_t now_tick(void) { return armGetSystemTick(); }
static inline uint64_t tick_to_ns(uint64_t t) { return armTicksToNs(t); }

static const char *wait_kind_name(int k) {
  switch (k) {
    case DIAG_W_COND:   return "cond_wait";
    case DIAG_W_JOIN:   return "join";
    case DIAG_W_SEM:    return "sem_wait";
    case DIAG_W_MUTEX:  return "mutex_lock";
    case DIAG_W_RWLOCK: return "rwlock";
    case DIAG_W_FUTEX:  return "futex_spin";
    default:            return "running";
  }
}

static DiagThread *slot_alloc(void) {
  mutexLock(&g_reg_lock);
  DiagThread *t = NULL;
  for (int i = 0; i < DIAG_MAX_THREADS; i++) {
    if (!g_threads[i].in_use) { t = &g_threads[i]; break; }
  }
  if (t) {
    memset(t, 0, sizeof(*t));
    t->in_use = 1;
    t->pth = pthread_self();
    t->handle = threadGetCurHandle();   /* real handle, usable from the watchdog */
    __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (t->tp));  /* #298: holder-PC key */
    uint64_t tid = 0;
    if (R_SUCCEEDED(svcGetThreadId(&tid, CUR_THREAD_HANDLE))) t->tid = tid;
    t->last_active = now_tick();
  }
  mutexUnlock(&g_reg_lock);
  return t;
}

/* Return this thread's slot, lazily allocating one if it ran code we didn't
 * trampoline (e.g. the process main thread). Never returns NULL unless the
 * registry is full (then beacons silently no-op). */
static DiagThread *diag_self(void) {
  if (self) return self;
  DiagThread *t = slot_alloc();
  if (t && t->name[0] == 0) {
    /* default label until a real name arrives */
    snprintf(t->name, sizeof(t->name), "T%llu", (unsigned long long)t->tid);
  }
  self = t;
  return t;
}

/* ------------------------------------------------------------------ public */
void diag_thread_register(const void *entry, int is_main_engine) {
  DiagThread *t = diag_self();
  if (!t) return;
  t->entry = entry;
  t->is_main_engine = is_main_engine;
  if (is_main_engine && t->name[0] == 'T')   /* keep until Unity renames it */
    snprintf(t->name, sizeof(t->name), "engine_main");
}

void diag_thread_unregister(void) {
  if (!self) return;
  mutexLock(&g_reg_lock);
  self->in_use = 0;
  mutexUnlock(&g_reg_lock);
  self = NULL;
}

/* Build #287: the current thread's registered name for diagnostic log
 * lines that must identify the waiter (e.g. [cond] WAIT). diag_self()
 * lazily allocates a slot (default name "T<tid>"), so the only NULL
 * case is a full registry -- then "?". Never returns NULL. */
const char *diag_self_name(void) {
  DiagThread *t = diag_self();
  if (!t || !t->name[0]) return "?";
  return t->name;
}

/* Build #285: periodic PC sampler for the ~1 FPS lag hunt. The watchdog only
 * dumps on stalls (6s without frame progress), but at ~1 FPS frames keep
 * advancing, so the watchdog never fires and no thread PC is ever seen. This
 * samples every registered thread's PC (pause, read, resume -- the same
 * ordering as snapshot_thread) into a compact comma-separated "name:pc" list
 * the snoop thread appends to its 5s line (snoop.log, lossless). A hotspot
 * shows up as the same PC across samples; a parked thread shows a constant
 * PC; a working thread's PC moves. Handles+names are copied under the
 * registry lock and sampled outside it, so a thread registering or
 * unregistering mid-sample cannot corrupt the read. Threads whose context
 * read fails are skipped silently (a dead handle, or a thread exiting). */
void diag_sample_all_pcs(char *buf, size_t n) {
  struct { Handle h; int parked; char name[32]; } snap[DIAG_MAX_THREADS];
  int count = 0;
  mutexLock(&g_reg_lock);
  for (int i = 0; i < DIAG_MAX_THREADS && count < DIAG_MAX_THREADS; i++) {
    if (!g_threads[i].in_use) continue;
    snap[count].h = g_threads[i].handle;
    /* #304: same rule as snapshot_thread -- sampling a RUNNING thread means
     * pausing it, and pausing one that sits in an fs IPC request wedges the FS
     * service for the whole process. Only parked threads are sampled. */
    snap[count].parked = (g_threads[i].wait_kind != DIAG_W_NONE);
    memcpy(snap[count].name, g_threads[i].name, sizeof snap[count].name);
    snap[count].name[sizeof snap[count].name - 1] = 0;
    count++;
  }
  mutexUnlock(&g_reg_lock);
  size_t used = 0;
  if (n) buf[0] = 0;
  for (int i = 0; i < count; i++) {
    if (!snap[i].h || snap[i].h == threadGetCurHandle() || !snap[i].parked) continue;
    ThreadContext ctx;
    Result pr = svcSetThreadActivity(snap[i].h, ThreadActivity_Paused);
    Result gr = R_SUCCEEDED(pr) ? svcGetThreadContext3(&ctx, snap[i].h) : pr;
    if (R_SUCCEEDED(pr)) svcSetThreadActivity(snap[i].h, ThreadActivity_Runnable);
    if (R_FAILED(gr)) continue;
    int w = snprintf(buf + used, n - used, "%s%s:%llx",
                     used ? "," : "", snap[i].name[0] ? snap[i].name : "?",
                     (unsigned long long)ctx.pc.x);
    if (w < 0 || (size_t)w >= n - used) break;
    used += (size_t)w;
  }
}

/* Build #298: sample the HOLDER thread's PC for a mutex the caller has been
 * waiting on. The #297 test showed a cross-thread stall (FR: worker waits on
 * main; SP: main waits on worker) where the holder never releases -- but the
 * logs cannot say WHERE the holder is stuck. This finds the holder in the
 * thread registry by its tpidrro_el0 (recorded at registration in slot_alloc),
 * pauses it briefly, reads its context, and resumes it (the same
 * pause/read/resume pattern as diag_sample_all_pcs above).
 *
 * Called from lock292_log, which runs on the WAITING thread inside the lock
 * fn's slow path -- so this must NEVER take g_reg_lock (the holder might be
 * holding it during registration, which would deadlock the waiter on top of
 * the game mutex it already waits for). The registry scan is lock-free: a
 * torn read of a slot being registered/unregistered can only yield a stale
 * handle (context read fails, we report failure) or a wrong tp match (we
 * sample the wrong thread's PC -- a diagnostic error, not a crash). The
 * registry is effectively static after init, so this is safe in practice.
 *
 * NOTE on tp identity: ThreadContext.tpidr is TPIDR_EL0 (the read/write
 * bionic TLS pointer), NOT TPIDRRO_EL0 (the kernel TLS base that holder_tp
 * / waiter_tp carry). The two registers hold DIFFERENT values, so the
 * context's tpidr can NOT be used to match the holder -- hence the tp field
 * captured at registration. Returns 1 and fills *out_pc/*out_lr on success,
 * 0 on failure (holder not registered, holder == caller -- pausing self
 * would deadlock -- or the context read failed). */
int diag_sample_holder_pc(uintptr_t holder_tp, uint64_t *out_pc, uint64_t *out_lr) {
  uintptr_t self_tp;
  __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (self_tp));
  if (!holder_tp || holder_tp == self_tp) return 0;  /* no holder, or holder is us */
  Handle h = 0;
  for (int i = 0; i < DIAG_MAX_THREADS; i++) {
    if (!g_threads[i].in_use) continue;
    if (g_threads[i].tp != holder_tp) continue;
    /* #304: only a holder parked in a shim may be paused; pausing one that is
     * running (e.g. inside fsdev_write) kills every later SD write. */
    if (g_threads[i].wait_kind == DIAG_W_NONE) return 0;
    h = g_threads[i].handle;
    break;
  }
  if (!h || h == threadGetCurHandle()) return 0;
  ThreadContext ctx;
  Result pr = svcSetThreadActivity(h, ThreadActivity_Paused);
  Result gr = R_SUCCEEDED(pr) ? svcGetThreadContext3(&ctx, h) : pr;
  if (R_SUCCEEDED(pr)) svcSetThreadActivity(h, ThreadActivity_Runnable);
  if (R_FAILED(gr)) return 0;
  *out_pc = ctx.pc.x;
  *out_lr = ctx.lr;
  return 1;
}

void diag_set_name(void *target_pthread, const char *name) {
  if (!name) return;
  DiagThread *t = NULL;
  if (target_pthread) {
    pthread_t want = (pthread_t)target_pthread;
    mutexLock(&g_reg_lock);
    for (int i = 0; i < DIAG_MAX_THREADS; i++) {
      if (g_threads[i].in_use && pthread_equal(g_threads[i].pth, want)) { t = &g_threads[i]; break; }
    }
    mutexUnlock(&g_reg_lock);
  }
  if (!t) t = diag_self();   /* PR_SET_NAME / self-naming case */
  if (!t) return;
  strncpy(t->name, name, sizeof(t->name) - 1);
  t->name[sizeof(t->name) - 1] = 0;
}

void diag_wait_enter(int kind, const void *obj) {
  DiagThread *t = diag_self();
  if (!t) return;
  t->wait_kind  = kind;
  t->wait_obj   = obj;
  t->wait_since = now_tick();
  t->waits_total++;
  t->last_active = t->wait_since;
}

void diag_wait_exit(void) {
  DiagThread *t = self;          /* exit without a prior enter is harmless */
  if (!t) return;
  t->wait_kind = DIAG_W_NONE;
  t->wait_obj  = NULL;
  t->wakes_total++;
  t->last_active = now_tick();
}

void diag_futex_spin(const void *obj) {
  DiagThread *t = diag_self();
  if (!t) return;
  /* publish as a futex wait but keep counting spins so the watchdog can tell
   * "alive but never satisfied" from "hard-parked". Reset wait_since only on
   * the transition *into* a futex wait (or onto a different uaddr), so the
   * dumped "parked secs" measures the current spin episode. */
  int was_futex = (t->wait_kind == DIAG_W_FUTEX && t->wait_obj == obj);
  t->wait_kind  = DIAG_W_FUTEX;
  t->wait_obj   = obj;
  uint64_t now = now_tick();
  if (!was_futex) t->wait_since = now;
  t->futex_spins++;
  t->last_active = now;
}

void diag_frame(int frame) {
  g_frame = frame;
  g_last_progress = now_tick();
}

/* ------------------------------------------------------------------ watchdog */
static uint64_t prev_waits[DIAG_MAX_THREADS];
static uint64_t prev_wakes[DIAG_MAX_THREADS];
static uint64_t prev_spins[DIAG_MAX_THREADS];

/* ---- CPU-context snapshot: see *where in libunity/il2cpp* a thread is wedged.
 * The shim beacons only show which sync primitive a thread sits in; when the
 * hang is inside native engine code (our case: main thread parked inside
 * Unity_nativeRender), this backtrace is what actually pinpoints it. */

/* Our own NRO code region, resolved once via svcQueryMemory on a local fn. */
static uint64_t g_nro_base, g_nro_size;
/* Set per-thread by snapshot_thread: enable the stack scan only for the main /
 * loader threads so the dump stays readable. */
static int g_scan_stack;
static void nro_range_init(void) {
  MemoryInfo mi; u32 pi;
  if (R_SUCCEEDED(svcQueryMemory(&mi, &pi, (u64)(uintptr_t)&nro_range_init)) && mi.size) {
    g_nro_base = mi.addr; g_nro_size = mi.size;
  }
}
/* Write a symbolicated label for `addr` into buf: "libX+0xoff" / "NRO+0xoff"
 * / raw absolute. */
static void resolve_addr(char *buf, size_t n, uint64_t addr) {
  so_module *m = so_find_module_by_addr((const void *)(uintptr_t)addr);
  if (m) {
    /* m->name is the full sdmc path; the leading dirs are identical for every
     * loaded .so, so a fixed-width truncation makes libunity and libil2cpp
     * indistinguishable. Print the basename instead. */
    const char *base = m->name, *p;
    for (p = m->name; *p; p++) if (*p == '/' || *p == '\\') base = p + 1;
    snprintf(buf, n, "%.20s+0x%llx", base,   /* bound %s: resolve_addr buffers are 40B */
             (unsigned long long)(addr - (uint64_t)(uintptr_t)m->load_virtbase));
  } else if (g_nro_size && addr >= g_nro_base && addr < g_nro_base + g_nro_size) {
    snprintf(buf, n, "NRO+0x%llx", (unsigned long long)(addr - g_nro_base));
  } else {
    snprintf(buf, n, "0x%llx", (unsigned long long)addr);
  }
}

/* Buffered dump: everything collected while a thread is PAUSED is written here
 * and printed only AFTER the thread is resumed. Calling debugPrintf while the
 * target is paused deadlocks if the target owns the log mutex (it usually does
 * during boot, when every thread logs constantly) -- that was the fbstub88
 * whole-process freeze. Collect lock-free, resume, then log. */
/* ------------------------------------------------------------------ #290
 * Lossless watchdog dump (wd290.log). Test #289 proved the debug.log lock
 * wedges when the game parks (~50s): ZERO [wd] STALL lines, ZERO [mem150]
 * lines in both modes, while the lossless channels (snoop/wake/gtid) kept
 * working. The watchdog dump is the ONLY observable that identifies the
 * park's mutex (main thread PC + X0/X1/X2: X1 = mutex address, X0 = owner
 * handle; plus the thread table's wait_obj), so it must survive the wedge.
 * wd290_log mirrors every dump_threads line to sdmc:/switch/aota/wd290.log
 * via raw open()/write() (same discipline as wake.log: no stdio FILE*, no
 * malloc, no g_log_lock -- works from the watchdog thread even with a
 * wedged log lock). The debugPrintf call is kept for the live log. The
 * watchdog thread is the sole writer; the fd is opened lazily on first use.
 * wd290_write_raw mirrors the snapshot_thread buffer (already formatted). */
static int wd290_fd = -1;
static void wd290_open(void) {
  if (wd290_fd >= 0) return;
  wd290_fd = open("sdmc:/switch/aota/wd290.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (wd290_fd < 0) return;
  const char *hdr = "[wd290] boot\n";
  ssize_t hw = write(wd290_fd, hdr, 13);
  (void)hw;
}
static void wd290_log(const char *fmt, ...) {
  char buf[2048];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  if (n <= 0) return;
  if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
  /* #303: no debugPrintf mirror. The watchdog must not touch stdio: if it
   * blocks on the stdio lock while a thread is paused, the whole process stops
   * (b302 did exactly that). wd290.log is written with the same raw fd/log
   * discipline as wake.log, so nothing is lost -- only the duplicate is. */
  wd290_open();
  if (wd290_fd < 0) return;
  ssize_t w = write(wd290_fd, buf, (size_t)n);
  (void)w;
}
static void wd290_write_raw(const char *buf, size_t len) {
  if (!buf || !len) return;
  wd290_open();
  if (wd290_fd < 0) return;
  ssize_t w = write(wd290_fd, buf, len);
  (void)w;
}

static char   g_dump_buf[16384];
static size_t g_dump_len;
static void dump_emit(const char *fmt, ...) {
  if (g_dump_len >= sizeof g_dump_buf - 1) return;
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(g_dump_buf + g_dump_len, sizeof g_dump_buf - g_dump_len, fmt, ap);
  va_end(ap);
  if (n > 0) {
    g_dump_len += (size_t)n;
    if (g_dump_len > sizeof g_dump_buf - 1) g_dump_len = sizeof g_dump_buf - 1;
  }
}

static void dump_thread_context(const char *name, const ThreadContext *ctx) {
  char a[40], b[40];
  resolve_addr(a, sizeof a, ctx->pc.x);
  resolve_addr(b, sizeof b, ctx->lr);
  dump_emit("[wd]   %s  PC=%s  LR=%s\n", name, a, b);
  /* Build #107: if the main thread is parked inside OUR wrapper (NRO) during a
   * stall, that's the smoking gun -- Unity called into our shim and never came
   * back. Make it unmissable. */
  if ((strstr(name, "Main") || strstr(name, "main")) &&
      g_nro_size && ctx->pc.x >= g_nro_base && ctx->pc.x < g_nro_base + g_nro_size) {
    dump_emit("[wd]   >>> MAIN THREAD PARKED IN WRAPPER CODE (%s) -- shim hang, not Unity <<<\n", a);
  }
  dump_emit("[wd]     SP=0x%llx FP=0x%llx X0=0x%llx X1=0x%llx X2=0x%llx\n",
              (unsigned long long)ctx->sp, (unsigned long long)ctx->fp,
              (unsigned long long)ctx->cpu_gprs[0].x,
              (unsigned long long)ctx->cpu_gprs[1].x,
              (unsigned long long)ctx->cpu_gprs[2].x);
  /* For a thread parked in svcArbitrateLock, X1 is typically the mutex address
   * and X0 the owner's thread-handle tag -> identifies who holds the lock. */
  /* Clean backtrace via the frame-pointer (x29) chain: [fp]=caller fp, [fp+8]=lr.
   * Bound every dereference to the thread's mapped stack so a wild fp can't fault
   * the watchdog itself. */
  uint64_t slo = 0, shi = 0;
  { MemoryInfo mi; u32 pi;
    if (R_SUCCEEDED(svcQueryMemory(&mi, &pi, ctx->sp)) && mi.size) { slo = mi.addr; shi = mi.addr + mi.size; } }
  uint64_t fp = ctx->fp;
  for (int depth = 0; depth < 32 && (fp & 7) == 0; depth++) {
    if (slo) { if (fp < slo || fp + 16 > shi) break; }     /* stay in mapped stack */
    else if (fp < 0x1000) break;                            /* query failed: loose guard */
    if (!slo) {   /* stack query failed: verify fp is mapped before dereferencing */
      MemoryInfo fmi; u32 fpi;
      if (R_FAILED(svcQueryMemory(&fmi, &fpi, fp)) || !(fmi.perm & Perm_R)
          || fp + 16 > fmi.addr + fmi.size) break; }
    const uint64_t nextfp = ((const uint64_t *)(uintptr_t)fp)[0];
    const uint64_t lr     = ((const uint64_t *)(uintptr_t)fp)[1];
    if (!lr) break;
    char s[40]; resolve_addr(s, sizeof s, lr);
    dump_emit("[wd]     bt[%d] %s\n", depth, s);
    if (nextfp <= fp) break;   /* fp must climb up the stack */
    fp = nextfp;
  }
  /* Unity's hand-written wait stubs clobber the FP chain, so the bt[] above
   * often dead-ends in our glue. Raw-scan the top of the stack for any slot that
   * points into libunity / libil2cpp code -- those are return addresses the FP
   * walk missed, and they reveal what the thread is actually wedged inside.
   * Caller gates this (main/loader threads only) to keep the log readable. */
  if (g_scan_stack && slo) {
    uint64_t sp = ctx->sp & ~7ull;
    if (sp < slo) sp = slo;
    uint64_t top = sp + 0x2000;            /* ~1024 slots is plenty for the active frames */
    if (top > shi) top = shi;
    int printed = 0;
    for (uint64_t addr = sp; addr + 8 <= top && printed < 24; addr += 8) {
      uint64_t v = ((const uint64_t *)(uintptr_t)addr)[0];
      so_module *m = so_find_module_by_addr((const void *)(uintptr_t)v);
      if (!m) continue;
      if (!strstr(m->name, "unity") && !strstr(m->name, "il2cpp")) continue;  /* skip glue/main */
      /* A real return address points to the instruction *after* a call, so the
       * 4 bytes at v-4 must be BL (0b100101 imm26) or BLR (0xD63F0000 mask).
       * Without this check the scan reports jump-table targets, vtable pointers
       * and stale frames -- all of which look like code addresses but are NOT on
       * the live call chain. This filter is what makes the backtrace trustworthy. */
      { MemoryInfo pmi; u32 ppi;   /* v-4 may be an unmapped prev page -> probe safely */
        if (R_FAILED(svcQueryMemory(&pmi, &ppi, v - 4)) || !(pmi.perm & Perm_R)) continue; }
      uint32_t prev = ((const uint32_t *)(uintptr_t)(v - 4))[0];
      int is_bl  = (prev & 0xFC000000u) == 0x94000000u;
      int is_blr = (prev & 0xFFFFFC1Fu) == 0xD63F0000u;
      if (!is_bl && !is_blr) continue;
      char s[48]; resolve_addr(s, sizeof s, v);
      dump_emit("[wd]     ret@0x%-4llx %s%s\n", (unsigned long long)(addr - sp), s,
                  is_blr ? " (via blr)" : "");
      printed++;
    }
  }
}

/* Pause just long enough to snapshot, RESUME before printing (so the watchdog
 * can't deadlock on a stdio/heap lock the paused thread was holding). */
static void snapshot_thread(DiagThread *t) {
  if (!t->handle || t->handle == threadGetCurHandle()) return;
  /* Only the main render/UI thread and the async loaders matter for the swap/load
   * hang; the ~30 idle Job.Worker/GC threads just slow the dump so it can't re-fire
   * on the real wedge. Skip their context entirely (they're in the summary table). */
    int want = (strstr(t->name, "Main") || strstr(t->name, "Preload") ||
              strstr(t->name, "AsyncRead"));
  /* #303: engine helper threads (AssetGarbageCollectorHelper 1560 in b302) are
   * table-only now. Pausing one wedged the freeze probe itself: it held the
   * libnx fs mutex mid-SD-write, and the watchdog's next write never returned. */
  if (!want) return;
  /* #304: NEVER pause a thread that is running arbitrary code. b303 paused
   * Unity Main Thread exactly once -- inside fsdev_write (PC=NRO+0x907ec0
   * svcSendSyncRequest, LR into serviceDispatchImpl) -- and from that moment on
   * no SD write in the process ever completed again: debug.log, sentinel.log and
   * wd290.log all stop while the game kept running. Interrupting an fs IPC
   * request leaves the FS service holding that session, so every later write
   * blocks forever. Only sample threads that are parked inside one of our own
   * sync shims, where a pause cannot land in the middle of an fs request. */
  if (t->wait_kind == DIAG_W_NONE) return;

  ThreadContext ctx;
  /* #292: if the dump hangs, the last marker names the thread it hung on. */
  wd290_log("[wd] snap %s tid=%llu: pause...\n", t->name[0] ? t->name : "?",
            (unsigned long long)t->tid);
  Result pr = svcSetThreadActivity(t->handle, ThreadActivity_Paused);
  /* #303: NOTHING may be logged between pause and resume. b302 froze exactly
   * here -- the previous build logged "paused rc=..." from inside the paused
   * window, and that write needs the libnx fs mutex which the paused thread was
   * holding, so the watchdog blocked forever with the game suspended behind it.
   * Everything below is buffered and reaches the SD card only after the thread
   * is running again. */
  Result gr = R_SUCCEEDED(pr) ? svcGetThreadContext3(&ctx, t->handle) : pr;
  if (R_FAILED(gr)) {
    if (R_SUCCEEDED(pr)) svcSetThreadActivity(t->handle, ThreadActivity_Runnable);
    wd290_log("[wd]   %-16s (snapshot failed rc=0x%x)\n", t->name, gr);
    return;
  }
  /* Collect while PAUSED (consistent stack), but into the buffer only -- no
   * logging until the thread is resumed (see dump_emit above). */
  g_dump_len = 0; g_dump_buf[0] = 0;
  dump_emit("[wd] snap %s: paused rc=0x%x, ctx read while stopped\n",
            t->name[0] ? t->name : "?", pr);
  g_scan_stack = 1;
  dump_thread_context(t->name[0] ? t->name : "?", &ctx);
  g_scan_stack = 0;
  if (R_SUCCEEDED(pr)) svcSetThreadActivity(t->handle, ThreadActivity_Runnable);
  debugPrintf("%s", g_dump_buf);
  wd290_write_raw(g_dump_buf, g_dump_len);   /* #290: lossless copy */
}

static void dump_threads(int episode, uint64_t now) {
  uint64_t stalled_ns = tick_to_ns(now - g_last_progress);
  if (g_dump_periodic)
    wd290_log("\n[wd] ===== STATE #%d : periodic snapshot, no frame progress for "
              "%llu.%llus (last frame=%d) =====\n",
              episode, (unsigned long long)(stalled_ns / 1000000000ull),
              (unsigned long long)((stalled_ns % 1000000000ull) / 100000000ull), g_frame);
  else
    wd290_log("\n[wd] ===== STALL #%d : no frame progress for %llu.%llus (last frame=%d) =====\n",
              episode, (unsigned long long)(stalled_ns / 1000000000ull),
              (unsigned long long)((stalled_ns % 1000000000ull) / 100000000ull), g_frame);
  {
    extern volatile u64 g_swap_enter_tick;   /* armed by egl_SwapBuffers_log (imports.c) */
    u64 t = g_swap_enter_tick;
    if (t) {
      u64 ms = armTicksToNs(armGetSystemTick() - t) / 1000000ull;
      wd290_log("[wd] eglSwapBuffers IN FLIGHT for %llu ms (the present is blocked)\n",
                  (unsigned long long)ms);
    }
  }
  {
    extern volatile u64 g_swap_enter_tick;   /* armed by egl_SwapBuffers_log (imports.c) */
    u64 t = g_swap_enter_tick;
    if (t) {
      u64 ms = armTicksToNs(armGetSystemTick() - t) / 1000000ull;
      wd290_log("[wd] >>> a thread is INSIDE eglSwapBuffers right now, for %llu ms <<<\n",
                  (unsigned long long)ms);
    }
  }
  wd290_log("[wd] %-16s %-10s %-11s %-18s %7s  d_wait d_wake d_spin\n",
              "name", "tid", "state", "wait_obj", "secs");
  for (int i = 0; i < DIAG_MAX_THREADS; i++) {
    DiagThread *t = &g_threads[i];
    if (!t->in_use) continue;
    int kind = t->wait_kind;
    uint64_t since = t->wait_since;
    uint64_t parked_ns = (kind != DIAG_W_NONE && since) ? tick_to_ns(now - since) : 0;
    uint64_t dwait = t->waits_total - prev_waits[i];
    uint64_t dwake = t->wakes_total - prev_wakes[i];
    uint64_t dspin = t->futex_spins - prev_spins[i];
    prev_waits[i] = t->waits_total;
    prev_wakes[i] = t->wakes_total;
    prev_spins[i] = t->futex_spins;
    wd290_log("[wd] %-16s %-10llu %-11s 0x%-16llx %3llu.%llu  %6llu %6llu %6llu%s\n",
                t->name[0] ? t->name : "?",
                (unsigned long long)t->tid,
                wait_kind_name(kind),
                (unsigned long long)(uintptr_t)t->wait_obj,
                (unsigned long long)(parked_ns / 1000000000ull),
                (unsigned long long)((parked_ns % 1000000000ull) / 100000000ull),
                (unsigned long long)dwait, (unsigned long long)dwake,
                (unsigned long long)dspin,
                t->is_main_engine ? "  <engine_main>" : "");
  }
  wd290_log("[wd] legend: d_* = delta since previous dump (0/0/0 == hard-parked; "
              "d_spin>0 == alive on futex; d_wait>d_wake == entered a wait it hasn't left)\n");
  /* native backtrace: where each thread is wedged inside libunity/il2cpp/NRO */
  wd290_log("[wd] --- thread CPU contexts (parked threads only, see #304) ---\n");
  for (int i = 0; i < DIAG_MAX_THREADS; i++) {
    if (g_threads[i].in_use) snapshot_thread(&g_threads[i]);
  }
  wd290_log("[wd] ===== end of dump #%d =====\n", episode);
  wd290_log("\n");
}

static void watchdog_main(void *unused) {
  (void)unused;
  int episode = 0;
  uint64_t last_dump = 0;
  int state_dumps = 0;
  uint64_t start = now_tick();
  /* prime so we don't false-trigger before the first frame */
  if (g_last_progress == 0) g_last_progress = now_tick();
  /* #291: prove the thread itself got scheduled, before it ever sleeps. */
  wd290_log("[wd291] watchdog thread running (state snapshots every %llus, max %d)\n",
            (unsigned long long)(DIAG_STATE_NS / 1000000000ull), DIAG_STATE_DUMPS);
  int loops = 0;
  for (;;) {
    svcSleepThread(DIAG_POLL_NS);
    uint64_t now = now_tick();
    /* #292: proof the poll sleep returns. n stuck at 1 == the sleep never
     * came back; n climbing while nothing else logs == the game wedged but the
     * scheduler (and this thread) is alive. */
    loops++;
    if (loops <= 8 || (loops % 30) == 0)
      wd290_log("[wd292] awake n=%d frame=%d idle_ms=%llu\n", loops, g_frame,
                (unsigned long long)(tick_to_ns(now - g_last_progress) / 1000000ull));
    /* #291: unconditional early snapshots -- see DIAG_STATE_NS. */
    if (state_dumps < DIAG_STATE_DUMPS &&
        tick_to_ns(now - start) >= (uint64_t)(state_dumps + 1) * DIAG_STATE_NS) {
      state_dumps++;
      g_dump_periodic = 1;
      dump_threads(state_dumps, now);
      g_dump_periodic = 0;
      last_dump = now;
      continue;
    }
    uint64_t idle = now - g_last_progress;
    if (tick_to_ns(idle) >= DIAG_STALL_NS) {
      if (last_dump == 0 || tick_to_ns(now - last_dump) >= DIAG_REDUMP_NS) {
        dump_threads(++episode, now);
        last_dump = now;
      }
    } else {
      /* progress resumed: reset so a later stall dumps fresh */
      last_dump = 0;
    }
  }
}

/* #292 sentinel: an independent thread whose only job is to prove process
 * liveness. It never touches the log lock, the futex shims or diag state, so
 * its file going quiet means EVERYTHING stopped -- not just the watchdog. */
int diag_frame_now(void) { return g_frame; }

static void sentinel_main(void *unused) {
  (void)unused;
  int fd = open("sdmc:/switch/aota/sentinel.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
  if (fd < 0) return;
  ssize_t w0 = write(fd, "[s292] boot\n", 12); (void)w0;
  /* [b312] 250 ms instead of 1 s, and the frame index with it. Test #311's
   * sentinel stopped after `boot` and the watchdog after one 1 s tick, so the
   * run either died or wedged within a second of frame 0 -- which of the two
   * cannot be told apart from the log, because debugPrintf DROPS lines when
   * g_log_lock is contended (util.c #267). The frame counter separates them:
   * alive n climbing with frame frozen == wedged; alive stopping == the
   * process is gone. */
  for (int n = 1; n <= 2400; n++) {
    svcSleepThread(250ull * 1000ull * 1000ull);
    char buf[64];
    int len = snprintf(buf, sizeof buf, "[s292] alive n=%d frame=%d\n",
                       n, diag_frame_now());
    if (len > 0) { ssize_t w = write(fd, buf, (size_t)len); (void)w; }
  }
  close(fd);
}

/* Build #318: the #292 sentinel writes through newlib/fsdev -- the same fs
 * session behind every other log line. Test #317 went black with debug.log,
 * wd290.log AND sentinel.log all stopping within ~250 ms of each other, so
 * either the process ended (nothing left to write) or that fs session wedged
 * (every later write blocks forever); the logs cannot tell the two apart.
 * This third witness opens its own FsFile (a separate fs IPC session: no
 * newlib, no fsdev, no g_log_lock, no registry lock) and keeps ticking, which
 * separates the cases:
 *   alive.log keeps growing -> process alive, the fsdev/log path wedged
 *   alive.log stops too     -> the process itself is gone
 * It also carries the main engine thread's wait beacon and the #317 hook
 * counters (calls/anomalies), so a surviving channel still names the state. */
void nx_msg317_stats(uint64_t *calls, uint64_t *anom);   /* main.c */

static void alive2_main(void *unused) {
  (void)unused;
  FsFileSystem *fs = fsdevGetDeviceFileSystem("sdmc");
  if (!fs) return;
  (void)fsFsCreateFile(fs, "/switch/aota/alive.log", 0, 0);   /* EEXIST is fine */
  FsFile f;
  if (R_FAILED(fsFsOpenFile(fs, "/switch/aota/alive.log", FsOpenMode_Write, &f)))
    return;
  (void)fsFileSetSize(&f, 0);
  s64 off = 0;
  for (int n = 1; n <= 2400; n++) {
    svcSleepThread(250ull * 1000ull * 1000ull);
    uint64_t mtid = 0, mwait = 0;
    int mkind = -1;
    for (int i = 0; i < DIAG_MAX_THREADS; i++) {
      if (g_threads[i].in_use && g_threads[i].is_main_engine) {
        mtid  = g_threads[i].tid;
        mkind = g_threads[i].wait_kind;
        mwait = (uint64_t)(uintptr_t)g_threads[i].wait_obj;
        break;
      }
    }
    uint64_t c317 = 0, a317 = 0;
    nx_msg317_stats(&c317, &a317);
    char buf[176];
    int len = snprintf(buf, sizeof buf,
                       "[a318] n=%d frame=%d idle_ms=%llu main=%llu/%s/0x%llx c317=%llu/%llu\n",
                       n, diag_frame_now(),
                       (unsigned long long)(tick_to_ns(now_tick() - g_last_progress) / 1000000ull),
                       (unsigned long long)mtid, wait_kind_name(mkind),
                       (unsigned long long)mwait,
                       (unsigned long long)c317, (unsigned long long)a317);
    if (len <= 0) continue;
    if (R_FAILED(fsFileWrite(&f, off, buf, (size_t)len, FsWriteOption_Flush))) return;
    off += len;
  }
  fsFileClose(&f);
}

void diag_watchdog_start(void) {
  if (g_wd_started) return;
  g_wd_started = 1;
  nro_range_init();
  if (g_last_progress == 0) g_last_progress = now_tick();
  /* Build #265: probe the two userspace locks libnx threadCreate takes
   * before calling it. Test #264 proved the main thread stops between
   * [wd264] and the armed/FAILED print -- inside threadCreate (stack alloc
   * = heap lock, virtmemLock, svcMapMemory, svcCreateThread), in
   * threadStart, or in the armed print's g_log_lock. Each probe brackets
   * one suspect; the last probe line printed names the held lock. A
   * missing first probe line means g_log_lock was already wedged.
   * NOTE: aligned_alloc is deliberate -- it is exactly what
   * __libnx_aligned_alloc calls, and unlike malloc/memalign it is NOT
   * linker-wrapped by this codebase, so the probe tests the plain newlib
   * heap lock threadCreate's stack alloc takes. */
  debugPrintf("[wd265] probing heap lock\n");
  void *wd_probe = aligned_alloc(0x1000, 0x4000);
  if (wd_probe) free(wd_probe);
  debugPrintf("[wd265] heap lock free\n");
  debugPrintf("[wd265] probing virtmem lock\n");
  virtmemLock();
  virtmemUnlock();
  debugPrintf("[wd265] virtmem lock free\n");
  /* libnx thread: deliberately NOT via the pthread shim under test.
   * 16 KiB stack, priority 0x2C (same band as main), default core. */
  debugPrintf("[wd265] creating watchdog thread\n");
  Result rc = threadCreate(&g_wd_thread, watchdog_main, NULL, NULL, 0x4000, 0x2C, -2);
  debugPrintf("[wd265] threadCreate returned rc=0x%x\n", rc);
  if (R_SUCCEEDED(rc) && R_SUCCEEDED(threadStart(&g_wd_thread)))
    debugPrintf("[wd] watchdog armed (stall=%llus, poll=1s)\n",
                (unsigned long long)(DIAG_STALL_NS / 1000000000ull));
  else
    debugPrintf("[wd] watchdog FAILED to start rc=0x%x\n", rc);
  /* #292: second, independent liveness witness (own file, own thread). */
  { static Thread s_thr;
    Result src = threadCreate(&s_thr, sentinel_main, NULL, NULL, 0x4000, 0x2C, -2);
    debugPrintf("[wd292] sentinel threadCreate rc=0x%x\n", src);
    if (R_SUCCEEDED(src)) debugPrintf("[wd292] sentinel start rc=0x%x\n", threadStart(&s_thr)); }
  /* #318: third, session-independent witness (see alive2_main). */
  { static Thread a_thr;
    Result arc = threadCreate(&a_thr, alive2_main, NULL, NULL, 0x4000, 0x2C, -2);
    debugPrintf("[a318] alive2 threadCreate rc=0x%x\n", arc);
    if (R_SUCCEEDED(arc)) debugPrintf("[a318] alive2 start rc=0x%x\n", threadStart(&a_thr)); }
}
