/* util.c -- misc utility functions
 *
 * Copyright (C) 2021 fgsfds, Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <switch.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"
#include "config.h"

// Thread-safe, file-only logger. We open+flush+close on every call so the last
// lines survive a hard crash, and serialise with a mutex because the engine
// logs from several worker threads. No nxlink/socket: this must work on bare
// hardware. The log lands in the game dir (main() chdir()s there at startup).
#if DEBUG_LOG
static Mutex g_log_lock; // libnx Mutex: 0 == unlocked, no init needed
#endif

static int  g_log_fd = -1;
static char g_log_path[512];

/* #305: open debug.log WITHOUT the old lazily-inside-the-caller idiom.
 * b304's exception handler called open() on the fault path; open() allocates a
 * newlib FILE handle (malloc), newlib's heap lock is an rmutex, and the
 * faulting thread still held it -- libnx's deadlock detection fired svcBreak
 * and the crash report showed mutexLock instead of the real fault. The handler
 * now asks for this fd at boot, so its path never allocates. */
static int log_fd_open(void) {
#if DEBUG_LOG
  if (g_log_fd >= 0) return g_log_fd;
  {
    const char *p = LOG_NAME;   /* game_path(): rotating static, copy it */
    size_t pn = strlen(p);
    if (pn >= sizeof g_log_path) pn = sizeof g_log_path - 1;
    memcpy(g_log_path, p, pn);
    g_log_path[pn] = 0;
    g_log_fd = open(g_log_path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (g_log_fd >= 0) {
      // Build stamp: identifies which .nro produced this log (date + Vulkan).
      char hdr[160];
      int hn = snprintf(hdr, sizeof hdr, "[build] aota_nx built %s %s HAVE_NVK=%d\n",
                        __DATE__, __TIME__,
#ifdef HAVE_NVK
                        1
#else
                        0
#endif
                        );
      if (hn > 0) { ssize_t hw = write(g_log_fd, hdr, (size_t)hn); (void)hw; }
    }
  }
#endif
  return g_log_fd;
}

int debugLogFd(void) { return log_fd_open(); }

/* ---- build #328: producers never touch SD ----------------------------------
 * Test #327 finally sampled the main thread at the stall (#327 works):
 *
 *   [wd327] snap Unity Main Thread: paused for a context read (not in fs), resumed
 *   PC=NRO+0x90eb90  LR=NRO+0x8ffc84
 *   bt[0] NRO+0x90d7c8 (fsdev_write+0x48)   bt[4] libunity.so+0x10e81a0
 *
 * NRO+0x90eb90 is libnx's svcSendSyncRequest, so the main thread was parked
 * inside an SD write -- a debugPrintf line -- and it never came back: the
 * last debug.log line is an apk314 lseek, and the very next debugPrintf (the
 * matching "#N read" line) never appears. The game was making progress on
 * the APK reads; it was OUR log write that froze it. That run then died with
 * Atmosphere's User Break at aota_nx+0x90ebac (svcBreak), LR into
 * __libnx_exception_handler: an exception was raised, our own handler tried
 * to write its dump through write() -> _write_r -> fsdev_write, that faulted
 * too, and the handler recursed (the crash report's 4-frame cycle repeats 8x)
 * until svcBreak. Both halves of the report are the same fault line: a
 * synchronous newlib/fsdev write on a thread that must not block.
 *
 * So a producer now only memcpys the formatted line into a RAM ring and
 * returns; the single flusher thread below owns the fd and is the only code
 * that calls write() on it. If the FS service wedges (it did in #326 and in
 * #327, pause or no pause), the flusher is the only casualty: the ring fills,
 * lines are dropped and counted, and the game keeps running.
 *
 * The old #326 drop.log channel is gone with it: it existed because the log
 * lock could be held forever by a descheduled thread, and its fallback was
 * itself an SD write on the caller. #328 holds this lock only across a
 * memcpy (a few microseconds, no fs request inside), and never blocks on it:
 * a lock that cannot be taken within 100 yields just counts a dropped line. */
#if DEBUG_LOG
#define LOGRING_SIZE (1u << 17)   /* 128 KB of queued lines */

static char g_ring[LOGRING_SIZE];
static u32  g_ring_head;          /* bytes ever queued (mod LOGRING_SIZE) */
static u32  g_ring_tail;          /* bytes ever written out */
static u32  g_log_dropped;        /* lines lost: ring full or lock stuck */
static volatile unsigned long g_log_flush_seq;  /* completed SD writes (#329) */
static Thread g_log_thr;
static int    g_log_thr_ok;

/* Queue one already-formatted line. Never blocks, never touches SD. */
static int log_ring_push(const char *p, size_t n) {
  int got = 0;
  u32 h, t, off, first;
  if (n > LOGRING_SIZE) n = LOGRING_SIZE;
  for (int i = 0; i < 100; i++) {
    if (mutexTryLock(&g_log_lock)) { got = 1; break; }
    svcSleepThread(0);            /* yield: let the holder run */
  }
  if (!got) return 0;
  h = g_ring_head; t = g_ring_tail;
  if ((u32)(h - t) + (u32)n > LOGRING_SIZE) { mutexUnlock(&g_log_lock); return 0; }
  off = h % LOGRING_SIZE;
  first = LOGRING_SIZE - off;
  if (first > n) first = (u32)n;
  memcpy(g_ring + off, p, first);
  if (n > first) memcpy(g_ring, p + first, n - first);
  g_ring_head = h + (u32)n;
  mutexUnlock(&g_log_lock);
  return 1;
}

/* Move queued bytes to the fd. Tail advances only by what write() accepted,
 * so a failing/wedged FS keeps the data instead of losing it. */
static void log_drain_once(void) {
  static char chunk[4096];
  for (;;) {
    int got = 0;
    u32 n = 0, t = 0, off, first;
    ssize_t wrote;
    if (!mutexTryLock(&g_log_lock)) return;
    got = 1;
    t = g_ring_tail; n = g_ring_head - t;
    if (n > sizeof chunk) n = sizeof chunk;
    if (n) {
      off = t % LOGRING_SIZE;
      first = LOGRING_SIZE - off;
      if (first > n) first = n;
      memcpy(chunk, g_ring + off, first);
      if (n > first) memcpy(chunk + first, g_ring, n - first);
    }
    mutexUnlock(&g_log_lock);
    if (!got || !n) return;
    {
      int fd = log_fd_open();
      if (fd < 0) return;
      wrote = write(fd, chunk, (size_t)n);
    }
    if (wrote <= 0) return;      /* keep the bytes; try again next tick */
    g_log_flush_seq++;           /* #329: one completed write == fs is alive */
    mutexTryLock(&g_log_lock);   /* best effort, single consumer */
    g_ring_tail = t + (u32)wrote;
    mutexUnlock(&g_log_lock);
    if ((u32)wrote < n) return;
  }
}

static void log_flusher_main(void *arg) {
  (void)arg;
  int ticks = 0;
  for (;;) {
    log_drain_once();
    /* #329: a write into the fs devoptab is NOT on the SD card. Test #328's log
     * tail is therefore ambiguous: lines written a second before the freeze can
     * still be sitting in the FAT cache, so "last line" may be far behind "last
     * thing that ran". fsync once a second commits what we have; the flusher is
     * the only thread that pays for it, and only it can be delayed. */
    if (++ticks >= 20) {         /* 20 * 50 ms = 1 s */
      ticks = 0;
      int fd = log_fd_open();
      if (fd >= 0) { (void)fsync(fd); g_log_flush_seq++; }
    }
    /* 50 ms: short enough that a crash loses almost nothing, long enough that
     * the SD sees a handful of writes per second instead of one per line. */
    svcSleepThread(50000000ULL);
  }
}
#endif

void log_init(void) {
#if DEBUG_LOG
  if (g_log_thr_ok) return;
  (void)log_fd_open();          /* open on a healthy process, not in a producer */
  if (R_FAILED(threadCreate(&g_log_thr, log_flusher_main, NULL, NULL,
                            0x4000, 0x2C, -2)))
    return;
  if (R_FAILED(threadStart(&g_log_thr))) return;
  g_log_thr_ok = 1;
  debugPrintf("[log328] queued logging: ring %u KB, flusher running\n",
              (unsigned)(LOGRING_SIZE / 1024));
  debugPrintf("[log329] flusher fsyncs every 1s so the log tail is really on the SD\n");
#endif
}

unsigned long log_flush_seq(void) {
#if DEBUG_LOG
  return g_log_flush_seq;
#else
  return 0;
#endif
}
unsigned long log_ring_queued(void) {
#if DEBUG_LOG
  return (unsigned long)g_ring_head;
#else
  return 0;
#endif
}
unsigned long log_dropped_lines(void) {
#if DEBUG_LOG
  return (unsigned long)g_log_dropped;
#else
  return 0;
#endif
}

int debugPrintf(char *text, ...) {
#if DEBUG_LOG
  va_list list;
  /* #328: the caller only formats and queues. log_ring_push() takes
   * g_log_lock with the #267 bounded yield-spin and gives up (counting the
   * line as dropped) if it cannot have it, so no thread can ever park here on
   * another thread's lock -- and, unlike every build up to #327, nothing on
   * this path issues an fs request: the SD write belongs to the flusher
   * thread alone. */
  {
    char buf[1024];
    va_start(list, text);
    int n = vsnprintf(buf, sizeof buf, text, list);
    va_end(list);
    if (n > 0) {
      if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;  /* truncated line */
      if (!log_ring_push(buf, (size_t)n)) g_log_dropped++;
    }
  }
#else
  (void)text;
#endif
  return 0;
}

/* #270: lock-free gtid record. Test #269 proved debugPrintf drops the
 * gtid lines at contended moments (ENTRY RAN + [tls269] both dropped
 * despite being reached, so the probe answered nothing). Same idiom as
 * futex266_wake_log in libc_shim.c: raw open/write, no stdio/malloc/
 * g_log_lock, hand-formatted, one write per line. One line per call:
 *   [gtid270] <tag> id=0x................ gtid=<decimal> tp=0x................
 * tag: "worker" (id = job arg), "main" (id = 0), "pthread" (id =
 * entry). gtid is decimal to match the mutex179 holder / snoop ltid
 * readings (33279). Safe on a raw kernel thread (game TLS installed).
 * #272: tp is the caller's tpidrro_el0 (TLS base pointer), read here --
 * same thread as the caller. Test #271 proved TLS[0x1e4] (gtid) is a
 * process-global (33279 for every game thread), so tp is the registry
 * that maps holder/waiter tpidrro values back to threads. */
static int gtid270_fd = -1;
static int gtid270_open(void) {
  if (gtid270_fd < 0) {
    gtid270_fd = open("sdmc:/switch/aota/gtid.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (gtid270_fd < 0) return -1;
    const char *hdr = "[gtid270] boot\n";
    ssize_t hw = write(gtid270_fd, hdr, sizeof("[gtid270] boot\n") - 1);
    (void)hw;
  }
  return gtid270_fd;
}
/* append 16 lowercase hex digits of v at buf[n]; returns new n. */
static int hex16(char *buf, int n, uintptr_t v) {
  for (int i = 15; i >= 0; i--) {
    unsigned d = (unsigned)((v >> (i * 4)) & 0xF);
    buf[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
  }
  return n;
}
void gtid270_log(const char *tag, uintptr_t id, unsigned gtid) {
  uintptr_t tp;
  __asm__ volatile ("mrs %0, tpidrro_el0" : "=r" (tp));
  if (gtid270_open() < 0) return;
  char buf[128];
  int n = 0;
  const char *pre = "[gtid270] ";
  for (int i = 0; pre[i]; i++) buf[n++] = pre[i];
  for (int i = 0; tag[i]; i++) buf[n++] = tag[i];
  const char *mid = " id=0x";
  for (int i = 0; mid[i]; i++) buf[n++] = mid[i];
  for (int i = 15; i >= 0; i--) {
    unsigned d = (unsigned)((id >> (i * 4)) & 0xF);
    buf[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
  }
  const char *mid2 = " gtid=";
  for (int i = 0; mid2[i]; i++) buf[n++] = mid2[i];
  /* decimal, no sprintf: reverse the digits, then copy them out */
  char rev[10];
  int nd = 0;
  unsigned v = gtid;
  do { rev[nd++] = (char)('0' + (v % 10)); v /= 10; } while (v);
  for (int i = nd - 1; i >= 0; i--) buf[n++] = rev[i];
  const char *mid3 = " tp=0x";
  for (int i = 0; mid3[i]; i++) buf[n++] = mid3[i];
  n = hex16(buf, n, tp);
  buf[n++] = '\n';
  /* Single write: best-effort, ignore short/failed writes. */
  ssize_t w = write(gtid270_fd, buf, (size_t)n);
  (void)w;
}

/* #272: lock-free lock-wait record, same file/fd as gtid270_log (shared
 * gtid270_open; the [gtid270] boot header is written once on first open
 * by whichever function runs first). One line per contended wait:
 *   [lock272] wait mutex=0x................ holder_gtid=<dec> waiter_tp=0x................ holder_tp=0x................
 * holder_tp == 0 means the mutex was not in the holder table (acquired
 * before lock272_arm ran, or evicted by a table collision). Called from
 * mutex179_log_wait, on the waiter thread; raw write only. */
void lock272_log_wait(uintptr_t mutex, unsigned holder_gtid, uintptr_t waiter_tp, uintptr_t holder_tp) {
  if (gtid270_open() < 0) return;
  char buf[160];
  int n = 0;
  const char *pre = "[lock272] wait mutex=0x";
  for (int i = 0; pre[i]; i++) buf[n++] = pre[i];
  n = hex16(buf, n, mutex);
  const char *mid = " holder_gtid=";
  for (int i = 0; mid[i]; i++) buf[n++] = mid[i];
  char rev[10];
  int nd = 0;
  unsigned v = holder_gtid;
  do { rev[nd++] = (char)('0' + (v % 10)); v /= 10; } while (v);
  for (int i = nd - 1; i >= 0; i--) buf[n++] = rev[i];
  const char *mid2 = " waiter_tp=0x";
  for (int i = 0; mid2[i]; i++) buf[n++] = mid2[i];
  n = hex16(buf, n, waiter_tp);
  const char *mid3 = " holder_tp=0x";
  for (int i = 0; mid3[i]; i++) buf[n++] = mid3[i];
  n = hex16(buf, n, holder_tp);
  buf[n++] = '\n';
  ssize_t w = write(gtid270_fd, buf, (size_t)n);
  (void)w;
}

// Per-thread bionic TLS. The engine reads its stack canary from tpidr_el0+0x28;
// every thread that runs engine code needs its OWN zeroed block here. A single
// shared block races: one thread's TLS writes (including the guard slot) corrupt
// another thread's in-flight canary, tripping a false __stack_chk_fail. `buf`
// must outlive the thread (TPIDR_EL0 points into it until the thread exits).
void install_bionic_tls(void *buf) {
  memset(buf, 0, BIONIC_TLS_SIZE);
  armSetTlsRw((uint8_t *)buf + BIONIC_TLS_TP_OFFSET);
}

// boost the CPU to 1785MHz while loading
void cpu_boost(int on) {
  appletSetCpuBoostMode(on ? ApmCpuBoostMode_FastLoad : ApmCpuBoostMode_Normal);
}

int ret0(void) { return 0; }

int retm1(void) { return -1; }
