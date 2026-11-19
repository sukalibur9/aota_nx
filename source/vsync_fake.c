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
 * Build #288 -- why the pacer alone never worked. Two defects, both visible in
 * the black-screen boot log as an endless
 *   [futex] FAKEWAKE ua=<mutex> val=0 after ~10ms
 *   [futex] SLOT-WAIT ua=<mutex> ... val=0
 * livelock:
 *   1. A bump with no WAKE is invisible to the waiter unless it re-checks the
 *      counter it knows about. Unity parked in a FUTEX_WAIT on the vsync mutex
 *      word, so the pacer must also PULSE that exact futex address. It bumps
 *      the counter FIRST and pulses second, so a woken waiter always re-reads
 *      the new value and never re-waits on a stale one.
 *   2. The pacer paced itself with svcSleepThread(16.6ms), and on this port a
 *      millisecond sleep inside a thread never returns (the #265/#266 finding
 *      in libc_shim.c: the 1ms futex poll parked forever while
 *      svcSleepThread(0) yielded fine). The pacer bumped once at most, then
 *      slept for good. It now paces off armGetSystemTick() and yields, the
 *      same clock the futex poll uses, so no timer wakeup can be lost.
 *
 * MIT.
 */

#include <switch.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>

#include "util.h"        /* debugPrintf */
#include "vsync_fake.h"

/* libc_shim.c: pulse the futex slot bound to `a` (bump its generation and
 * wake its waiters exactly like a FUTEX_WAKE). Returns 1 if a waiter was
 * attached, 0 if nobody waited -- then the pulse is lost, as on Linux. */
extern int futex_pulse_addr(uintptr_t a);

/* Vsync counter state */
static volatile uint64_t *g_vsync_counter = NULL;
static uintptr_t g_vsync_mutex = 0;   /* #288: futex word the waiter polls */
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

  g_vsync_mutex = mutex_addr;   /* #288: pulse target for the pacer */
  g_vsync_counter = (volatile uint64_t *)counter_addr;
  debugPrintf("[vsync] counter bound @ %p (mutex %p + 0x58), bumping at ~60Hz\n",
              (void *)g_vsync_counter, (void *)mutex_addr);
}

/* Background thread: bump the vsync counter at ~60Hz and pulse its waiters */
static void vsync_thread_fn(void *arg) {
  (void)arg;

  uint64_t next_ns = 0;
  unsigned bumps = 0, pulses = 0;
  unsigned g_next_log_bump = 60;

  while (g_vsync_thread_run) {
    /* #288: yield, never svcSleepThread(ms) -- see the file header. */
    svcSleepThread(0);

    volatile uint64_t *ctr = g_vsync_counter;
    if (!ctr) continue;

    const uint64_t now = armTicksToNs(armGetSystemTick());
    if (next_ns == 0) { next_ns = now + VSYNC_PERIOD_NS; continue; }
    if (now < next_ns) continue;

    /* Advance the deadline period by period, but cap catch-up at 4 bumps and
     * then resynchronise: a long stall (SD write, load) must not turn into a
     * burst that races the counter far ahead of real time. */
    unsigned n = 0;
    while (next_ns <= now && n < 4) { next_ns += VSYNC_PERIOD_NS; n++; }
    if (next_ns <= now) next_ns = now + VSYNC_PERIOD_NS;

    for (unsigned i = 0; i < n; i++)
      __atomic_add_fetch(ctr, 1, __ATOMIC_SEQ_CST);

    /* #288: counter FIRST, wake second. A waiter woken before the increment
     * re-reads the old counter, fails its predicate and re-waits -- the
     * livelock in wake.log. */
    if (g_vsync_mutex)
      pulses += (unsigned)futex_pulse_addr(g_vsync_mutex);
    bumps += n;

    /* #308: per-second progress for the first 10 s, then per 10 s. The old
     * once-at-10 s line never reached a boot that hangs in frame 0, so a
     * pacer that was alive (or starved) both looked identical: silence. */
    if (bumps >= g_next_log_bump) {
      debugPrintf("[vsync] bumps=%u pulses=%u ctr=%llu waiters=%s\n",
                  bumps, pulses, (unsigned long long)*ctr,
                  pulses ? "seen" : "none");
      g_next_log_bump = bumps < 540 ? bumps + 60 : bumps + 600;
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
