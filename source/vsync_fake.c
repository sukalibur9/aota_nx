/* vsync_fake.c -- Unity 6 Android vsync counter emulation for Switch.
 *
 * Unity 6's WaitVSync(long) blocks in:
 *   lock(mutex);
 *   while (counter < target) cond_wait(cv, mutex);
 * waiting for a display presentation that never happens on Switch, because
 * nothing on this platform advances the counter. This is the first-real-frame
 * hang: load frames complete, then nativeRender never returns.
 *
 * Solution (ported from cloverpit_nx): a background thread bumps the counter
 * once per 16.6ms of wall time (~60Hz), which lets the waiter through.
 *
 * The counter address is discovered at runtime: when Unity enters the vsync
 * wait pattern (mutex_lock on the vsync mutex), we capture the mutex address.
 * From the Unity 6000.0.58f2 reference disassembly:
 *   mutex = page + 0xc0
 *   counter = page + 280 (0x118)
 *   counter - mutex = 0x58
 * The counter lives in .bss (writable).
 *
 * MIT.
 */

#include <switch.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>

#include "util.h"  /* debugPrintf */

/* Vsync counter state */
static volatile uint64_t *g_vsync_counter = NULL;
static volatile bool g_vsync_thread_run = false;
static Thread g_vsync_thread;

#define VSYNC_PERIOD_NS 16666667ULL  /* ~60 Hz */

/* Called from the futex wait path when we detect the vsync wait pattern.
 * The mutex address is captured, counter is at mutex + 0x58. */
void vsync_bind_counter(uintptr_t mutex_addr) {
  if (g_vsync_counter != NULL) return;  /* already bound */
  
  /* Counter is at mutex + 0x58 (from reference disassembly) */
  uintptr_t counter_addr = mutex_addr + 0x58;
  
  /* Sanity check: counter should be in writable memory, not in .text */
  /* We can't easily check sections here, so we just verify it's not obviously wrong */
  if (counter_addr < 0x100000) return;
  
  g_vsync_counter = (volatile uint64_t *)counter_addr;
  debugPrintf("[vsync] counter bound @ %p (mutex %p + 0x58), bumping at ~60Hz\n",
              (void *)g_vsync_counter, (void *)mutex_addr);
}

/* Background thread: bump the vsync counter at ~60Hz */
static void vsync_thread_fn(void *arg) {
  (void)arg;
  
  uint64_t last_ns = 0;
  
  while (g_vsync_thread_run) {
    svcSleepThread(VSYNC_PERIOD_NS);
    
    if (g_vsync_counter) {
      uint64_t now;
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
      
      if (last_ns == 0) last_ns = now;
      
      /* Bump counter for each elapsed vsync period (catch-up, but time-based) */
      while ((int64_t)(now - last_ns) >= (int64_t)VSYNC_PERIOD_NS) {
        __atomic_add_fetch(g_vsync_counter, 1, __ATOMIC_RELAXED);
        last_ns += VSYNC_PERIOD_NS;
      }
    }
  }
}

/* Start the vsync thread. Called during init. */
void vsync_start(void) {
  if (g_vsync_thread_run) return;
  
  g_vsync_thread_run = true;
  
  /* Stack 16KB, priority 0x2C, core -2 (any) */
  Result rc = threadCreate(&g_vsync_thread, vsync_thread_fn, NULL,
                           NULL, 0x4000, 0x2C, -2);
  if (R_SUCCEEDED(rc)) {
    threadStart(&g_vsync_thread);
    debugPrintf("[vsync] thread started (counter not yet bound)\n");
  } else {
    g_vsync_thread_run = false;
    debugPrintf("[vsync] thread FAILED to start (rc=0x%x) -- engine may hang on vsync\n",
                (unsigned)rc);
  }
}

/* Stop the vsync thread. Called during shutdown. */
void vsync_stop(void) {
  if (!g_vsync_thread_run) return;
  g_vsync_thread_run = false;
  threadWaitForExit(&g_vsync_thread);
  threadClose(&g_vsync_thread);
  debugPrintf("[vsync] thread stopped\n");
}

/* Get the bound counter address (for debugging) */
volatile uint64_t *vsync_get_counter(void) {
  return g_vsync_counter;
}
