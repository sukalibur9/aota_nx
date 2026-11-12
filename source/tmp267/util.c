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
