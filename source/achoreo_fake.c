/* achoreo_fake.c -- fake NDK AChoreographer for the Switch wrapper.
 *
 * Why this exists (2026-10-12): Unity 6 drives its frame loop off Android's
 * Choreographer. Our libunity.so (6000.5.8f1) imports
 *   AChoreographer_getInstance        (strong)
 *   AChoreographer_postFrameCallback  (strong)
 *   AChoreographer_postFrameCallback64 (weak)
 * as undefined symbols, and the wrapper previously provided none of them, so
 * no frame callback could ever be delivered and UnityMain stalls waiting for
 * vsync/frame events that never arrive (black screen, no input response).
 *
 * This implements the NDK entry points directly: a 60 Hz ticker thread
 * invokes pending frame callbacks with CLOCK_MONOTONIC timestamps, which is
 * exactly what a real Choreographer delivers. No binary patching and no
 * per-version instruction fingerprints -- it works for any Unity 6.x that
 * takes the NDK choreographer path.
 *
 * WIRING (not done yet -- needs the user's pick): add to
 * unity_imports.c's unity_dynlib_functions[]:
 *   { "AChoreographer_getInstance",         (uintptr_t)&AChoreographer_getInstance },
 *   { "AChoreographer_postFrameCallback",   (uintptr_t)&AChoreographer_postFrameCallback },
 *   { "AChoreographer_postFrameCallback64", (uintptr_t)&AChoreographer_postFrameCallback64 },
 * and optionally the two Delayed variants below. Every .c under source/ is
 * compiled automatically (see Makefile), so this file needs no build edit.
 *
 * MIT.
 */

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <switch.h>

#include "util.h"   /* debugPrintf */

/* NDK <android/choreographer.h> (API 24+). `long` is 64-bit on LP64. */
typedef struct AChoreographer AChoreographer;
typedef void (*AChoreographer_frameCallback)(long frameTimeNanos, void *data);

/* ------------------------------------------------------------------ */
/* pending-callback queue                                              */
/* ------------------------------------------------------------------ */
#define CHOREO_MAX_CB 64

struct choreo_cb {
  AChoreographer_frameCallback cb;
  void *data;
  uint64_t due_ns;   /* earliest delivery time, CLOCK_MONOTONIC */
  int used;
};

struct AChoreographer {
  int dummy;  /* opaque handle; never NULL once getInstance runs */
};

static struct AChoreographer g_choreo;
static struct choreo_cb g_q[CHOREO_MAX_CB];
static Mutex g_q_lock;
static Thread g_ticker;
static int g_ticker_started = 0;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* 60 Hz ticker: fires every callback whose due time has passed. Callbacks run
 * WITHOUT the queue lock held -- a callback may post another callback. */
static void choreo_ticker_main(void *arg) {
  (void)arg;
  for (;;) {
    svcSleepThread(16666667ull);  /* 1/60 s */
    uint64_t now = now_ns();
    for (;;) {
      AChoreographer_frameCallback cb = NULL;
      void *data = NULL;
      mutexLock(&g_q_lock);
      for (int i = 0; i < CHOREO_MAX_CB; i++) {
        if (g_q[i].used && g_q[i].due_ns <= now) {
          cb = g_q[i].cb;
          data = g_q[i].data;
          g_q[i].used = 0;
          break;
        }
      }
      mutexUnlock(&g_q_lock);
      if (!cb) break;
      cb((long)now, data);
    }
  }
}

static void choreo_ensure(void) {
  static int lock_init = 0;
  if (!lock_init) { mutexInit(&g_q_lock); lock_init = 1; }
  mutexLock(&g_q_lock);
  int start = !g_ticker_started;
  if (start) g_ticker_started = 1;
  mutexUnlock(&g_q_lock);
  if (start) {
    /* Same shape as the wrapper's other pump threads (aaudio_shim.c). */
    if (R_SUCCEEDED(threadCreate(&g_ticker, choreo_ticker_main, NULL,
                                 NULL, 0x4000, 0x2C, -2))) {
      threadStart(&g_ticker);
      debugPrintf("[choreo] 60 Hz frame-callback ticker started\n");
    } else {
      debugPrintf("[choreo] ticker threadCreate FAILED\n");
      mutexLock(&g_q_lock);
      g_ticker_started = 0;
      mutexUnlock(&g_q_lock);
    }
  }
}

static void choreo_post(AChoreographer_frameCallback cb, void *data,
                        uint64_t delay_ns) {
  if (!cb) return;
  static int first_logged = 0;
  choreo_ensure();
  uint64_t due = now_ns() + delay_ns;
  mutexLock(&g_q_lock);
  int slot = -1;
  for (int i = 0; i < CHOREO_MAX_CB; i++) {
    if (!g_q[i].used) { slot = i; break; }
  }
  if (slot >= 0) {
    g_q[slot].cb = cb;
    g_q[slot].data = data;
    g_q[slot].due_ns = due;
    g_q[slot].used = 1;
  }
  mutexUnlock(&g_q_lock);
  if (slot < 0) {
    debugPrintf("[choreo] callback queue FULL -- dropped\n");
  } else if (!first_logged) {
    first_logged = 1;
    debugPrintf("[choreo] first frame callback posted (queue ok)\n");
  }
}

/* ------------------------------------------------------------------ */
/* NDK entry points                                                    */
/* ------------------------------------------------------------------ */
AChoreographer *AChoreographer_getInstance(void) {
  choreo_ensure();
  return &g_choreo;
}

void AChoreographer_postFrameCallback(AChoreographer *choreographer,
                                      AChoreographer_frameCallback callback,
                                      void *data) {
  (void)choreographer;
  choreo_post(callback, data, 0);
}

void AChoreographer_postFrameCallback64(AChoreographer *choreographer,
                                        AChoreographer_frameCallback callback,
                                        void *data) {
  (void)choreographer;
  choreo_post(callback, data, 0);
}

void AChoreographer_postFrameCallbackDelayed(AChoreographer *choreographer,
                                             AChoreographer_frameCallback callback,
                                             void *data, long delayMillis) {
  (void)choreographer;
  choreo_post(callback, data,
              delayMillis > 0 ? (uint64_t)delayMillis * 1000000ull : 0);
}

void AChoreographer_postFrameCallbackDelayed64(AChoreographer *choreographer,
                                               AChoreographer_frameCallback callback,
                                               void *data, long delayMillis) {
  (void)choreographer;
  choreo_post(callback, data,
              delayMillis > 0 ? (uint64_t)delayMillis * 1000000ull : 0);
}
