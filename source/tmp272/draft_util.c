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

int debugPrintf(char *text, ...) {
#if DEBUG_LOG
  static FILE *f = NULL;
  va_list list;
  /* Build #267: NON-BLOCKING log lock. Test #266 proved the waiter
   * completes its futex wait (wake.log) but then blocks forever inside
   * the FAKEWAKE debugPrintf: g_log_lock was wedged by a thread that
   * descheduled mid-print while holding it, and every later print
   * blocks on mutexLock. Logging must never stop the game: try the
   * lock with a bounded yield-spin (100 tries -- under normal
   * contention a few yields suffice), and DROP the line if the lock
   * never frees. A dropped line costs far less than a parked game;
   * the lock-free channels (wake.log, snoop.log) keep reporting. */
  {
    int got = 0;
    for (int i = 0; i < 100; i++) {
      if (mutexTryLock(&g_log_lock)) { got = 1; break; }
      svcSleepThread(0);  /* yield: let the holder run */
    }
    if (!got) return 0;  /* lock wedged: drop this line, keep running */
  }
  if (!f) {
    f = fopen(LOG_NAME, "a");   // open once, keep open (SD fopen/close per line is very slow)
    if (f) {
      // Build stamp: identifies which .nro produced this log (date + Vulkan).
      fprintf(f, "[build] aota_nx built %s %s HAVE_NVK=%d\n", __DATE__, __TIME__,
#ifdef HAVE_NVK
              1
#else
              0
#endif
              );
      fflush(f);
    }
  }
  if (f) {
    va_start(list, text);
    vfprintf(f, text, list);
    va_end(list);
    fflush(f); // push each line to disk so we don't lose it if we crash next
  }
  mutexUnlock(&g_log_lock);
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
