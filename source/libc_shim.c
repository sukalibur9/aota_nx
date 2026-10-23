/* libc_shim.c -- bionic-compatible libc wrappers for libcrx.so + libc++_shared
 *
 * The Android engine and its C++ runtime are linked against bionic. Where the
 * bionic and newlib ABIs differ (struct layouts, flag values, missing
 * functions) we provide converting wrappers here; everything that matches is
 * passed straight through from imports.c. Online/IPC functionality (sockets,
 * fork/exec, dlopen of system libs) is dead on Switch and stubbed to fail
 * cleanly so the engine falls back to offline behaviour.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>  /* strncasecmp */
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <malloc.h>
#include "config.h"    /* GAME_HOME for the case-test scratch path */
#include "nx_fonts.h"   /* Switch shared fonts served as /system/fonts */
#include "vulkan_shim.h" /* Vulkan WSI translation (mesa-switch NVK) */
#include <wchar.h>
#include <wctype.h>
#include <time.h>
#include <sys/stat.h>
#include <switch.h>
#include <EGL/egl.h>     /* eglGetProcAddress: resolve the full GLES API for dlsym */

#include "config.h"
#include "util.h"
#include "error.h"
#include "imports.h"   /* dynlib_find_export (dlsym shim lookup) */
#include "nx_patch_os.h"  /* OS_GC_* -- derived Boehm-GC bridge globals */
#include "asset_pack.h"     /* packed-asset VFS: every read path below checks it first */
#include "so_util.h"
#include "libc_shim.h"
#include "android_native_unity.h"
#include "diag.h"
#include "vsync_fake.h"  /* Unity 6 vsync counter binding */

// ---------------------------------------------------------------------------
// fortify (_chk) wrappers: ignore the object-size argument
// ---------------------------------------------------------------------------

void *__memcpy_chk_fake(void *dst, const void *src, size_t n, size_t dstlen) { (void)dstlen; return memcpy(dst, src, n); }
void *__memmove_chk_fake(void *dst, const void *src, size_t n, size_t dstlen) { (void)dstlen; return memmove(dst, src, n); }
void *__memset_chk_fake(void *dst, int c, size_t n, size_t dstlen) { (void)dstlen; return memset(dst, c, n); }
char *__strcat_chk_fake(char *dst, const char *src, size_t dstlen) { (void)dstlen; return strcat(dst, src); }
char *__strchr_chk_fake(const char *s, int c, size_t slen) { (void)slen; return strchr(s, c); }
char *__strcpy_chk_fake(char *dst, const char *src, size_t dstlen) { (void)dstlen; return strcpy(dst, src); }
size_t __strlen_chk_fake(const char *s, size_t slen) { (void)slen; return strlen(s); }
char *__strncat_chk_fake(char *dst, const char *src, size_t n, size_t dstlen) { (void)dstlen; return strncat(dst, src, n); }
char *__strncpy_chk_fake(char *dst, const char *src, size_t n, size_t dstlen) { (void)dstlen; return strncpy(dst, src, n); }
char *__strncpy_chk2_fake(char *dst, const char *src, size_t n, size_t dstlen, size_t srclen) { (void)dstlen; (void)srclen; return strncpy(dst, src, n); }
char *__strrchr_chk_fake(const char *s, int c, size_t slen) { (void)slen; return strrchr(s, c); }
int __vsnprintf_chk_fake(char *s, size_t maxlen, int flag, size_t slen, const char *fmt, va_list va) { (void)flag; (void)slen; return vsnprintf(s, maxlen, fmt, va); }
int __vsprintf_chk_fake(char *s, int flag, size_t slen, const char *fmt, va_list va) { (void)flag; (void)slen; return vsprintf(s, fmt, va); }

int __snprintf_chk_fake(char *s, size_t maxlen, int flag, size_t slen, const char *fmt, ...) {
  (void)flag; (void)slen;
  va_list va; va_start(va, fmt);
  int r = vsnprintf(s, maxlen, fmt, va);
  va_end(va);
  return r;
}
int __sprintf_chk_fake(char *s, int flag, size_t slen, const char *fmt, ...) {
  (void)flag; (void)slen;
  va_list va; va_start(va, fmt);
  int r = vsprintf(s, fmt, va);
  va_end(va);
  return r;
}

// fortified read helpers ignore the buffer-size guard
int   __open_2_fake(const char *path, int flags) { return open_fake(path, flags); }
long  __read_chk_fake(int fd, void *buf, size_t count, size_t buflen) { (void)buflen; return read(fd, buf, count); }
long  __pread_chk_fake(int fd, void *buf, size_t count, long off, size_t buflen) {
  (void)buflen;
  long cur = lseek(fd, 0, SEEK_CUR);
  if (cur < 0 || lseek(fd, off, SEEK_SET) < 0) return -1;
  long r = read(fd, buf, count);
  lseek(fd, cur, SEEK_SET);
  return r;
}
void  __FD_SET_chk_fake(int fd, void *set, size_t setlen) { (void)setlen; if (set && fd >= 0 && fd < 1024) ((unsigned long *)set)[fd / (8 * sizeof(long))] |= (1ul << (fd % (8 * sizeof(long)))); }
int   __FD_ISSET_chk_fake(int fd, const void *set, size_t setlen) { (void)setlen; if (set && fd >= 0 && fd < 1024) return (((const unsigned long *)set)[fd / (8 * sizeof(long))] >> (fd % (8 * sizeof(long)))) & 1; return 0; }

// ---------------------------------------------------------------------------
// misc bionic functions
// ---------------------------------------------------------------------------

// Native twin of the android.os.Build.* JNI fields. libunity calls this to
// detect API level / ABI / device; returning "" (the old stub) made it
// mis-detect the platform. Hand back Switch-sane values for the keys engines
// actually query; everything else stays empty (= property unset, the normal
// Android case). Return value is the value length, per bionic contract.
int __system_property_get_fake(const char *name, char *value) {
  if (!value) return 0;
  const char *v = "";
  if (name) {
    if      (!strcmp(name, "ro.build.version.sdk"))        v = "33";
    else if (!strcmp(name, "ro.build.version.release"))    v = "13";
    else if (!strcmp(name, "ro.build.version.codename"))   v = "REL";
    else if (!strcmp(name, "ro.product.cpu.abi"))          v = "arm64-v8a";
    else if (!strcmp(name, "ro.product.cpu.abilist"))      v = "arm64-v8a";
    else if (!strcmp(name, "ro.product.cpu.abilist64"))    v = "arm64-v8a";
    else if (!strcmp(name, "ro.product.cpu.abi2"))         v = "";
    else if (!strcmp(name, "ro.product.model"))            v = "Switch";
    else if (!strcmp(name, "ro.product.manufacturer"))     v = "Nintendo";
    else if (!strcmp(name, "ro.product.brand"))            v = "Nintendo";
    else if (!strcmp(name, "ro.product.name"))             v = "Switch";
    else if (!strcmp(name, "ro.product.device"))           v = "Switch";
    else if (!strcmp(name, "ro.product.board"))            v = "nx";
    else if (!strcmp(name, "ro.hardware"))                 v = "nx";
    else if (!strcmp(name, "ro.board.platform"))           v = "nx";
    else if (!strcmp(name, "ro.build.fingerprint"))        v = "Nintendo/Switch/Switch:13/REL/10007:user/release-keys";
    else if (!strcmp(name, "ro.build.characteristics"))    v = "default";
    else if (!strcmp(name, "ro.build.type"))               v = "user";
    else if (!strcmp(name, "ro.build.tags"))               v = "release-keys";
    else if (!strcmp(name, "ro.debuggable"))               v = "0";
    else if (!strcmp(name, "ro.secure"))                   v = "1";
    else if (!strcmp(name, "ro.kernel.qemu"))              v = "0";
    else if (!strcmp(name, "ro.opengles.version"))         v = "196610"; /* GLES 3.2 */
    else if (!strcmp(name, "dalvik.vm.heapsize"))          v = "512m";
    else if (!strcmp(name, "persist.sys.timezone"))        v = "UTC";
  }
  size_t n = strlen(v);
  if (n > 91) n = 91;            /* PROP_VALUE_MAX-1 */
  memcpy(value, v, n); value[n] = '\0';
  return (int)n;
}
unsigned long getauxval_fake(unsigned long type) { (void)type; return 0; }

int gettid_fake(void) {
  u64 tid = 1;
  if (R_SUCCEEDED(svcGetThreadId(&tid, CUR_THREAD_HANDLE)) && tid)
    return (int)(tid & 0x7fffffff);
  return 1;
}

#define ARM64_SYS_GETTID            178
#define ARM64_SYS_FUTEX             98
#define ARM64_SYS_SCHED_SETAFFINITY 122
#define ARM64_SYS_PROCESS_VM_READV  270
#define ARM64_SYS_PROCESS_VM_WRITEV 271

/* Build #74: newlib malloc locking. newlib wraps heap ops (malloc/free/realloc)
 * in __malloc_lock/__malloc_unlock. libnx 4.9.0 (pinned by wrapper) predates
 * the malloc-lock wiring added in ~4.11, so the default is a no-op stub --
 * meaning Unity's 30+ threads (main, UnityMain, AsyncRead, workers) do
 * concurrent malloc/free WITHOUT locking, causing timing-sensitive heap
 * corruption. The Instruction Abort post-vkAcquireNextImageKHR (corrupted
 * function pointer/return address, different address each run) fits this.
 * We define the strong symbols with a recursive RMutex (newlib docs say the
 * lock can be taken re-entrantly). If libnx ever provides its own, the
 * linker picks the strong wrapper symbol. Safe no-op if locks turn out
 * to already be present (just adds a tiny overhead). */
static RMutex g_malloc_rmutex;
static int g_malloc_rmutex_init = 0;
void __malloc_lock(struct _reent *reent) {
    (void)reent;
    if (!g_malloc_rmutex_init) {
        rmutexInit(&g_malloc_rmutex);
        g_malloc_rmutex_init = 1;
    }
    rmutexLock(&g_malloc_rmutex);
}
void __malloc_unlock(struct _reent *reent) {
    (void)reent;
    rmutexUnlock(&g_malloc_rmutex);
}

// futex(2) emulation for the il2cpp runtime, which synchronizes its GC,
// thread pool and locks with raw futex.
//
// Design (build #91): per-address wait slots.
//
// Unity 6000.5.8f1 uses a "pulse" wake pattern: FUTEX_WAKE issued WITHOUT
// changing *uaddr (observed 4x in the build #88 hardware test). Correct Linux
// futex semantics require futex_wait to return 0 when woken even while
// *uaddr == val still holds.
//
// Build #89 tried exactly that -- break out of the wait when
// condvarWaitTimeout reported success ("signaled") instead of re-checking the
// value. It unblocked the main thread (Unity reached asset loading), but then
// the Switch froze hard (error 2162-0004, 10 s force-shutdown, log tail was
// binary garbage = heap corruption).
//
// Root cause of the #89 freeze: the condvar it waited on is shared by EVERY
// futex address hashing to the same bucket (FUTEX_WAKE wakes the whole
// bucket). A wake issued for address X therefore also released waiters parked
// on unrelated address Y with a false "success". Those threads proceeded past
// waits whose condition was never satisfied -- e.g. entered a mutex critical
// section while the owner still held it -- corrupting the heap until the
// kernel aborted the process. The value re-check that #88 relied on is the
// only thing that made bucket-wide wakes safe; #89 dropped it on the wake
// path, turning cross-address wakes into silent data races.
//
// The fix: never share a wait queue between different addresses. Each waiter
// attaches to a slot keyed by its EXACT uaddr; FUTEX_WAKE signals only the
// slot of the address being woken. A "signaled" wake therefore provably means
// YOUR address was pulsed, and returning 0 without a value re-check is then
// correct Linux semantics. Each slot carries a generation counter bumped by
// the waker while holding the slot mutex; the waiter captures the generation
// while holding the same mutex and then sleeps atomically on the slot
// condvar, so a wake can be neither lost nor misattributed. (Verified against
// libnx 4.9.0: condvarWaitTimeout requires the mutex held, returns it held,
// returns 0 on signal and a 0xEA01-valued error on timeout.)
//
// Safety nets kept from #90: waits are chunked (16 ms); over-long timeouts
// (e.g. Unity's 49-day "infinite" 0xFFFFFFFF ms) are capped at 100 ms and then
// fake-woken (return 0) so a genuinely lost pulse can never hang forever;
// short timeouts still return a real ETIMEDOUT.
#define FUTEX_WAIT        0
#define FUTEX_WAKE        1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_CMD_MASK    0x7f  // strip FUTEX_PRIVATE_FLAG(128)/CLOCK_REALTIME(256)

#define FUTEX_SLOTS 1024  // distinct futex addresses ever waited on; Unity uses dozens
typedef struct {
  uintptr_t uaddr;  // exact waited-on address; 0 = free slot (sticky once bound)
  u64 gen;          // bumped under m on every FUTEX_WAKE for uaddr
  int refcount;     // waiters currently attached
  Mutex m;          // serializes the gen handshake against sleep/wake
  CondVar cv;       // signaled only for THIS uaddr
} futex_slot_t;
static futex_slot_t futex_slots[FUTEX_SLOTS];  // zero-init: all free
static Mutex futex_tab_lock;                   // guards uaddr/refcount allocation

// Attach to the slot for uaddr, creating it if needed. Returns NULL only if
// every slot is in use (practically unreachable at 1024); the caller then
// uses the legacy bucket fallback (value-check only, no pulse break).
static futex_slot_t *futex_slot_acquire(volatile int32_t *uaddr) {
  futex_slot_t *s = NULL;
  mutexLock(&futex_tab_lock);
  for (int i = 0; i < FUTEX_SLOTS; i++)
    if (futex_slots[i].uaddr == (uintptr_t)uaddr) { s = &futex_slots[i]; break; }
  if (!s)
    for (int i = 0; i < FUTEX_SLOTS; i++)
      if (futex_slots[i].uaddr == 0 && futex_slots[i].refcount == 0) {
        s = &futex_slots[i];
        s->uaddr = (uintptr_t)uaddr;
        s->gen = 0;  // safe: refcount==0 means no waiter can compare a stale gen
        break;
      }
  if (s) s->refcount++;
  mutexUnlock(&futex_tab_lock);
  return s;
}

static void futex_slot_release(futex_slot_t *s) {
  mutexLock(&futex_tab_lock);
  s->refcount--;
  // uaddr stays bound (sticky): a later waiter reuses the slot and captures a
  // fresh gen, so there is no stale-generation hazard; a waker arriving while
  // no one waits still finds the slot and signals an empty condvar (harmless).
  mutexUnlock(&futex_tab_lock);
}

// Find WITHOUT creating: the wake path must not allocate a slot for an
// address no one waits on (the pulse is then simply lost, as on Linux).
static futex_slot_t *futex_slot_find(volatile int32_t *uaddr) {
  futex_slot_t *s = NULL;
  mutexLock(&futex_tab_lock);
  for (int i = 0; i < FUTEX_SLOTS; i++)
    if (futex_slots[i].uaddr == (uintptr_t)uaddr) { s = &futex_slots[i]; break; }
  mutexUnlock(&futex_tab_lock);
  return s;
}

// Legacy bucket arrays -- kept ONLY for the slot-table-full fallback below.
/* Build #88: Increased from 256 to 4096 to reduce hash collisions.
 * REA analysis found cross-talk between unrelated futexes due to collisions. */
#define FUTEX_BUCKETS     4096

static Mutex   futex_lock[FUTEX_BUCKETS];   // libnx Mutex/CondVar are u32; 0 == ready
static CondVar futex_cond[FUTEX_BUCKETS];

// Fallback when the slot table is full: the build-#90 bucket wait,
// value-check only, no pulse break. Safe by construction (never returns
// success without *uaddr != val, except the 100 ms fake-wake safety net,
// same as #90).
// (fxown_* are defined just below; forward-declared for the fallback.)
static void fxown_spin(volatile int32_t *uaddr);
static void fxown_wake(volatile int32_t *uaddr);
static long futex_wait_bucket_fallback(volatile int32_t *uaddr, int val, const struct timespec *to) {
  const unsigned h = (unsigned)(((uintptr_t)uaddr >> 4) & (FUTEX_BUCKETS - 1));
  long ret = 0;
  debugPrintf("[futex] SLOT-TABLE FULL, bucket fallback ua=%p (should never happen)\n",
              (void *)uaddr);
  mutexLock(&futex_lock[h]);
  if (*uaddr != val) {
    errno = EAGAIN; ret = -1;
  } else if (to) {
    const u64 ns = (u64)to->tv_sec * 1000000000ULL + (u64)to->tv_nsec;
    const u64 CAP = 16000000ULL;
    const u64 MAX_WAIT_NS = 100000000ULL;
    const u64 eff_ns = ns <= MAX_WAIT_NS ? ns : MAX_WAIT_NS;
    const int capped = ns > MAX_WAIT_NS;
    u64 waited = 0;
    int woken = 0;
    while (waited < eff_ns) {
      u64 chunk = eff_ns - waited;
      if (chunk > CAP) chunk = CAP;
      diag_futex_spin((const void *)uaddr); fxown_spin(uaddr);
      condvarWaitTimeout(&futex_cond[h], &futex_lock[h], chunk);
      if (*uaddr != val) { woken = 1; break; }
      waited += chunk;
    }
    if (!woken) {
      if (capped) {
        ret = 0;  // fake wake, same as #90
      } else {
        errno = ETIMEDOUT; ret = -1;
      }
    }
  } else {
    int spins = 0;
    while (*uaddr == val && spins < 6) {
      diag_futex_spin((const void *)uaddr); fxown_spin(uaddr);
      condvarWaitTimeout(&futex_cond[h], &futex_lock[h], 16000000ULL);
      spins++;
    }
    ret = 0;  // fake wake, same as #90
  }
  mutexUnlock(&futex_lock[h]);
  return ret;
}
#define FXOWN_N 64
static uintptr_t fxown_a[FXOWN_N];
static unsigned  fxown_c[FXOWN_N];
static Mutex     fxown_lk;
static int fxown_slot(uintptr_t a) {
  int victim = 0; unsigned lo = ~0u;
  for (int i = 0; i < FXOWN_N; i++) {
    if (fxown_a[i] == a) return i;
    if (fxown_c[i] < lo) { lo = fxown_c[i]; victim = i; }
  }
  fxown_a[victim] = a; fxown_c[victim] = 0; return victim;
}
static void fxown_spin(volatile int32_t *uaddr) {
  uintptr_t a = (uintptr_t)uaddr;
  if (a < 0x2400000000ULL) return;            /* skip job/loader region */
  mutexLock(&fxown_lk);
  int s = fxown_slot(a); unsigned c = ++fxown_c[s];
  mutexUnlock(&fxown_lk);
  if (c == 300) {
    /* Unity 6000.5.8f1 mutex_lock (libunity.so+0x58a6dc) stores owner thread ID
     * at [mutex+64]. Dump it to identify who holds the mutex we're stuck on. */
    uint64_t owner = 0;
    __builtin_memcpy(&owner, (const void *)(a + 64), sizeof(owner));
    debugPrintf("[fxown] STUCK ua=%p tid=%d val=%08x owner_tid=%llx (300 re-polls ~5s)\n",
                (void *)uaddr, gettid_fake(), (unsigned)*uaddr,
                (unsigned long long)owner);
    /* Try to bind as vsync counter: if this is the Unity 6 vsync wait,
     * the counter is at mutex + 0x58. The vsync thread will start bumping it. */
    vsync_bind_counter(a);
  }
}
static void fxown_wake(volatile int32_t *uaddr) {
  uintptr_t a = (uintptr_t)uaddr;
  if (a < 0x2400000000ULL) return;
  unsigned c = 0;
  mutexLock(&fxown_lk);
  for (int i = 0; i < FXOWN_N; i++) if (fxown_a[i] == a) { c = fxown_c[i]; fxown_c[i] = 0; break; }
  mutexUnlock(&fxown_lk);
  if (c >= 300)
    debugPrintf("[fxown] WAKE ua=%p by tid=%d (was stuck %u re-polls)\n", (void *)uaddr, gettid_fake(), c);
}
static long futex_impl(volatile int32_t *uaddr, int op, int val, const struct timespec *to) {
  const int cmd = op & FUTEX_CMD_MASK;
  if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) {
    /* diagnostic: log each distinct waited-on address once (who waits for what) */
    {
      static uintptr_t seen_ua[128]; static int seen_n = 0;
      static Mutex seen_lk;
      int seen = 0;
      mutexLock(&seen_lk);
      for (int i = 0; i < seen_n; i++) if (seen_ua[i] == (uintptr_t)uaddr) { seen = 1; break; }
      if (!seen && seen_n < 128) { seen_ua[seen_n++] = (uintptr_t)uaddr; }
      mutexUnlock(&seen_lk);
      if (!seen) {
        u64 tns = 0;
        if (to) tns = (u64)to->tv_sec * 1000000000ULL + (u64)to->tv_nsec;
        /* Build #87: log caller address so we can identify which Unity
         * function is waiting on the futex (for REA analysis). */
        void *caller = __builtin_return_address(0);
        debugPrintf("[futex] WAIT ua=%p val=%d timeout=%llums tid=%d caller=%p\n",
                    (void *)uaddr, val, (unsigned long long)(tns / 1000000ULL),
                    gettid_fake(), caller);
      }
    }

    /* Build #91: per-address wait slot. The waiter holds the slot mutex from
     * the value check through the atomic sleep, and the waker must take the
     * same mutex to bump the generation and signal -- so a wake can neither
     * be lost nor delivered to the wrong address (the #89 freeze). */
    futex_slot_t *s = futex_slot_acquire(uaddr);
    if (!s) return futex_wait_bucket_fallback(uaddr, val, to);

    /* Build #95: diagnostic slot logging. Build #94 showed a deterministic
     * lost-wake: main thread WAITs (infinite) on an address, 4x FUTEX_WAKE
     * to that exact address are all lost, and the waiter never even gets a
     * FAKEWAKE (never completes 6x16ms spins). Log which slot the waiter
     * attaches to and what the waker finds, to distinguish slot-mismatch
     * from waiter-stuck-before-condvar.
     * Build #106: track value changes at waited addresses. Log the current
     * *uaddr value on each WAIT (deduplicated) to see if threads wait for
     * a value change that never happens. */
    {
      int slot_idx = (int)(s - futex_slots);
      static const volatile int *last_logged_ua = NULL;
      static int last_logged_val = 0;
      int cur_val = *uaddr;
      if (uaddr != last_logged_ua || cur_val != last_logged_val) {
        debugPrintf("[futex] SLOT-WAIT ua=%p slot=%d gen=%llu refcount=%d tid=%d caller=%p val=%d\n",
                    (void *)uaddr, slot_idx, (unsigned long long)s->gen,
                    s->refcount, gettid_fake(), __builtin_return_address(0), cur_val);
        last_logged_ua = uaddr;
        last_logged_val = cur_val;
      }
    }

    long ret = 0;
    mutexLock(&s->m);
    const u64 gen0 = s->gen;
    if (*uaddr != val) {
      errno = EAGAIN; ret = -1;
    } else if (to) {
      /* Timed wait, chunked so a missed wake still recovers, but honoring the
       * real deadline. Build #91 adds the pulse break: if OUR address was
       * woken (generation changed) we return 0 immediately even though
       * *uaddr == val -- correct Linux futex semantics for Unity's pulse
       * pattern. Safe now because the slot is keyed by exact address. */
      const u64 ns = (u64)to->tv_sec * 1000000000ULL + (u64)to->tv_nsec;
      const u64 CAP = 16000000ULL;
      /* Build #86: cap over-long waits (e.g. Unity's 49-day 0xFFFFFFFF ms
       * "infinite" timeout) at 100 ms, then fake-wake. */
      const u64 MAX_WAIT_NS = 100000000ULL;
      const u64 eff_ns = ns <= MAX_WAIT_NS ? ns : MAX_WAIT_NS;
      const int capped = ns > MAX_WAIT_NS;
      u64 waited = 0;
      int done = 0;
      while (!done && waited < eff_ns) {
        u64 chunk = eff_ns - waited;
        if (chunk > CAP) chunk = CAP;
        /* Build #96: fxown_spin/diag_futex_spin removed -- fxown_spin takes
         * fxown_lk while the waiter holds the slot mutex (lock-order hazard);
         * diag spin-counting is done by the watchdog from the wait state. */
        Result wrc = condvarWaitTimeout(&s->cv, &s->m, chunk);
        /* libnx contract: s->m is held again here, wake or timeout. */
        if (*uaddr != val) {
          done = 1;  /* standard wake: value changed */
        } else if (R_SUCCEEDED(wrc)) {
          /* Build #97: return 0 on ANY successful wake (pulse semantics,
           * same as the infinite-wait path above). Per-address slots make
           * this freeze-safe. */
          done = 1;
          if (s->gen != gen0) {
            /* Build #92: log 4-frame backtrace to identify the real Unity waiter.
             * __builtin_return_address(0) alone gives a stack artifact (0x127a57c);
             * we need the deeper call chain. */
            void *c0 = __builtin_return_address(0);
            void *c1 = __builtin_return_address(1);
            void *c2 = __builtin_return_address(2);
            void *c3 = __builtin_return_address(3);
            debugPrintf("[futex] PULSE ua=%p val=%d tid=%d callers=%p,%p,%p,%p\n",
                        (void *)uaddr, val, gettid_fake(), c0, c1, c2, c3);
          }
        }
        /* else: chunk timeout or spurious wake -- re-poll */
        waited += chunk;
      }
      if (!done) {
        if (capped) {
          /* Fake wake: return 0 (success) as if woken. Unity re-checks *uaddr. */
          void *caller = __builtin_return_address(0);
          debugPrintf("[futex] FAKEWAKE ua=%p val=%d after ~100ms tid=%d caller=%p (req %llums)\n",
                      (void *)uaddr, val, gettid_fake(), caller,
                      (unsigned long long)(ns / 1000000ULL));
          ret = 0;
        } else {
          errno = ETIMEDOUT; ret = -1;
        }
      }
    } else {
      /* Infinite wait: single 100ms pulse-aware wait, then the fake-wake
       * safety net.
       * Build #96: replaced the 6x16ms chunked loop. Build #95 proved main
       * hard-parks without ever completing 6 spins (no FAKEWAKE in 180+s),
       * so the chunked re-entry is where it gets stuck; fxown_spin takes
       * fxown_lk while holding the slot mutex (lock-order hazard), now
       * removed. A single 100ms condvar wait cannot get stuck re-entering. */
      int done = 0;
      Result wrc = condvarWaitTimeout(&s->cv, &s->m, 100000000ULL);
      if (*uaddr != val) {
        done = 1;
      } else if (R_SUCCEEDED(wrc)) {
        /* Build #97: return 0 on ANY successful condvar wake, without
         * re-checking value or generation. This restores build #89's pulse
         * semantics (Unity pulses = wake without changing *uaddr; Linux
         * futex_wait returns 0 when woken). Freeze-safe because #91's
         * per-address slots guarantee the wake was for THIS address --
         * #89's freeze came from shared-bucket false wakes, eliminated here.
         * The gen comparison below is only for the PULSE log label. */
        done = 1;
        if (s->gen != gen0) {
          /* Build #92: 4-frame backtrace for real waiter identification. */
          void *c0 = __builtin_return_address(0);
          void *c1 = __builtin_return_address(1);
          void *c2 = __builtin_return_address(2);
          void *c3 = __builtin_return_address(3);
          debugPrintf("[futex] PULSE ua=%p val=%d tid=%d callers=%p,%p,%p,%p (infinite wait)\n",
                      (void *)uaddr, val, gettid_fake(), c0, c1, c2, c3);
        }
      }
      if (!done) {
        void *caller = __builtin_return_address(0);
        debugPrintf("[futex] FAKEWAKE ua=%p val=%d after ~100ms tid=%d caller=%p (was infinite wait)\n",
                    (void *)uaddr, val, gettid_fake(), caller);
        ret = 0;  /* fake wake, not ETIMEDOUT */
      }
    }
    mutexUnlock(&s->m);
    futex_slot_release(s);
    return ret;
  }
  if (cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET) {
    /* Build #112: enhanced wake logging to diagnose worker starvation.
     * #111 proved main waits on a semaphore never posted; workers idle in
     * futex waits. Log ALL wakes (not just first 60) with caller to see if
     * Unity ever tries to wake workers. */
    {
      static int wake_logged = 0;
      wake_logged++;
      /* Log first 200, then only wakes to addresses with active waiters */
      futex_slot_t *chk = futex_slot_find(uaddr);
      if (wake_logged <= 200 || (chk && chk->refcount > 0)) {
        debugPrintf("[futex] WAKE#%d ua=%p n=%d tid=%d caller=%p %s\n",
                    wake_logged, (void *)uaddr, val, gettid_fake(),
                    __builtin_return_address(0),
                    (chk && chk->refcount > 0) ? "[HAS-WAITERS]" : "[no-waiters]");
      }
    }
    fxown_wake(uaddr);
    /* Build #91: signal ONLY the slot of this exact address, bumping its
     * generation under the slot mutex so no waiter can miss it or mistake
     * another address's wake for its own.
     * Build #95: diagnostic - log what the waker finds. */
    futex_slot_t *s = futex_slot_find(uaddr);
    if (s) {
      int slot_idx = (int)(s - futex_slots);
      mutexLock(&s->m);
      u64 gen_before = s->gen;
      s->gen++;
      condvarWakeAll(&s->cv);
      mutexUnlock(&s->m);
      debugPrintf("[futex] SLOT-WAKE ua=%p slot=%d gen %llu->%llu refcount=%d tid=%d\n",
                  (void *)uaddr, slot_idx,
                  (unsigned long long)gen_before, (unsigned long long)s->gen,
                  s->refcount, gettid_fake());
    } else {
      debugPrintf("[futex] SLOT-WAKE-MISS ua=%p (no slot bound) tid=%d\n",
                  (void *)uaddr, gettid_fake());
    }
    /* else: nobody waiting on this address -- pulse lost, same as Linux. */
    return val > 0 ? val : 0; // approximate count woken
  }
  errno = ENOSYS;
  return -1;
}
/* newlib has no <sys/uio.h>; the kernel iovec layout is just {ptr, len}. */
struct nx_iovec { void *iov_base; size_t iov_len; };

/* Validate that [addr, addr+len) is mapped and readable via svcQueryMemory, so a
 * self process_vm_readv can copy safely instead of risking a fault. */
static int nx_addr_readable(uintptr_t addr, size_t len) {
  uintptr_t a = addr, end = addr + len;
  while (a < end) {
    MemoryInfo mi; u32 pi;
    if (R_FAILED(svcQueryMemory(&mi, &pi, a))) return 0;
    if (mi.type == 0) return 0;                 /* MemType_Unmapped */
    if ((mi.perm & Perm_R) == 0) return 0;      /* not readable */
    uintptr_t be = (uintptr_t)mi.addr + mi.size;
    if (be <= a) return 0;
    a = be;
  }
  return 1;
}

/* Shared engine for process_vm_readv/writev, used by BOTH the syscall()
 * route below and the direct libc-symbol fakes (build #123). Self memory
 * copy used as a fault-safe read/write probe: validate each source range
 * with svcQueryMemory, then copy the readable parts. */
static ssize_t nx_process_vm_xfer(int writing, const struct nx_iovec *liov,
                                  unsigned long lcnt,
                                  const struct nx_iovec *riov,
                                  unsigned long rcnt, const char *tag,
                                  void *caller) {
  static int dbg_sys = 0, dbg_dir = 0;
  int *dbg = (tag[0] == 'v') ? &dbg_dir : &dbg_sys;
  if (*dbg < 5) {
    (*dbg)++;
    debugPrintf("[%s] %s lcnt=%lu rcnt=%lu remote0=%p rlen0=%zu caller=%p\n",
                tag, writing ? "vm_writev" : "vm_readv", lcnt, rcnt,
                rcnt ? riov[0].iov_base : NULL, rcnt ? riov[0].iov_len : 0,
                caller);
  }
  ssize_t total = 0;
  unsigned long li = 0, ri = 0; size_t lo = 0, ro = 0;
  while (li < lcnt && ri < rcnt) {
    char *lp = (char *)liov[li].iov_base + lo;
    char *rp = (char *)riov[ri].iov_base + ro;
    size_t lrem = liov[li].iov_len - lo, rrem = riov[ri].iov_len - ro;
    size_t n = lrem < rrem ? lrem : rrem;
    char *probe = writing ? lp : rp;   /* the side being read-from must be readable */
    if (!nx_addr_readable((uintptr_t)probe, n)) {
      if (total == 0) { errno = EFAULT; return -1; }
      return total;
    }
    if (writing) memcpy(rp, lp, n); else memcpy(lp, rp, n);
    total += (ssize_t)n; lo += n; ro += n;
    if (lo == liov[li].iov_len) { li++; lo = 0; }
    if (ro == riov[ri].iov_len) { ri++; ro = 0; }
  }
  return total;
}

long syscall_fake(long number, ...) {
  switch (number) {
    case ARM64_SYS_GETTID: return gettid_fake();
    case ARM64_SYS_FUTEX: {
      va_list va; va_start(va, number);
      volatile int32_t *uaddr = va_arg(va, volatile int32_t *);
      const int op  = va_arg(va, int);
      const int val = va_arg(va, int);
      const struct timespec *to = va_arg(va, const struct timespec *);
      va_end(va);
      return futex_impl(uaddr, op, val, to);
    }
    case ARM64_SYS_SCHED_SETAFFINITY:
      return 0; // affinity hints are advisory; pretend success
    case ARM64_SYS_PROCESS_VM_READV:
    case ARM64_SYS_PROCESS_VM_WRITEV: {
      /* Stubbing this to ENOSYS made the caller spin once per frame (a
       * process_vm_readv flood), wedging the boot path. */
      va_list va; va_start(va, number);
      long pid                   = va_arg(va, long); (void)pid;
      const struct nx_iovec *liov   = va_arg(va, const struct nx_iovec *);
      unsigned long lcnt         = va_arg(va, unsigned long);
      const struct nx_iovec *riov   = va_arg(va, const struct nx_iovec *);
      unsigned long rcnt         = va_arg(va, unsigned long);
      va_end(va);
      char tag[16];
      snprintf(tag, sizeof tag, "sys%ld", number);
      return nx_process_vm_xfer(number == ARM64_SYS_PROCESS_VM_WRITEV,
                                liov, lcnt, riov, rcnt, tag,
                                __builtin_return_address(0));
    }
  }
  debugPrintf("libc: syscall(%ld) -> ENOSYS\n", number);
  errno = ENOSYS;
  return -1;
}

/* Build #123: libunity also imports process_vm_readv as a DIRECT libc
 * symbol. In build #122 that import was unresolved, so the loader poisoned
 * its GOT slot with the slot's own offset (0x16eaf38) and the first call --
 * from libunity+0x1253e04, right after frame 0 -- jumped to the poison and
 * died (instruction abort, pc == 0x16eaf38). These fakes give the loader a
 * real target with the same validated self-copy semantics as the syscall
 * route. pid is the caller's own getpid() (our getpid_fake), i.e. self. */
long process_vm_readv_fake(int pid, const void *liov, unsigned long lcnt,
                           const void *riov, unsigned long rcnt,
                           unsigned long flags) {
  (void)pid; (void)flags;
  return nx_process_vm_xfer(0, (const struct nx_iovec *)liov, lcnt,
                            (const struct nx_iovec *)riov, rcnt,
                            "vm123", __builtin_return_address(0));
}
long process_vm_writev_fake(int pid, const void *liov, unsigned long lcnt,
                            const void *riov, unsigned long rcnt,
                            unsigned long flags) {
  (void)pid; (void)flags;
  return nx_process_vm_xfer(1, (const struct nx_iovec *)liov, lcnt,
                            (const struct nx_iovec *)riov, rcnt,
                            "vm123", __builtin_return_address(0));
}

/* GNU strerror_r (returns the message pointer), unlike the XSI variant
 * already registered as strerror_r_fake. Unresolved in BOTH libunity and
 * libil2cpp in the #122 log -- same poison trap, disarmed. */
char *gnu_strerror_r_fake(int errnum, char *buf, size_t buflen) {
  const char *s = strerror(errnum);
  if (!buf || buflen == 0) return (char *)s;
  strncpy(buf, s, buflen - 1);
  buf[buflen - 1] = 0;
  return buf;
}

/* Bionic's 64-bit stdio entry points; newlib's off_t is already 64-bit
 * here, so these forward to ftello/fseeko (the same functions the table
 * already registers under their plain names). */
long long ftello64_fake(void *f) { return (long long)ftello((FILE *)f); }
int fseeko64_fake(void *f, long long off, int whence) {
  return fseeko((FILE *)f, (off_t)off, whence);
}

void sincosf_fake(float x, float *s, float *c) { *s = sinf(x); *c = cosf(x); }
int sched_get_priority_max_fake(int policy) { (void)policy; return 0; }
int sched_get_priority_min_fake(int policy) { (void)policy; return 0; }
void android_set_abort_message_fake(const char *msg) { debugPrintf("abort message: %s\n", msg ? msg : "(null)"); }
size_t __ctype_get_mb_cur_max_fake(void) { return 1; }
int __register_atfork_fake(void) { return 0; }
int __cxa_thread_atexit_impl_fake(void (*fn)(void *), void *arg, void *dso) { (void)fn; (void)arg; (void)dso; return 0; }

#define BIONIC_SC_PAGESIZE 39
#define BIONIC_SC_PAGE_SIZE 40
#define BIONIC_SC_NPROCESSORS_CONF 96
#define BIONIC_SC_NPROCESSORS_ONLN 97
#define BIONIC_SC_PHYS_PAGES 98
/* Linux (glibc) values, in case Unity uses those instead of bionic's */
#define LINUX_SC_NPROCESSORS_CONF 83
#define LINUX_SC_NPROCESSORS_ONLN 84

long sysconf_fake(int name) {
  switch (name) {
    case BIONIC_SC_PAGESIZE:
    case BIONIC_SC_PAGE_SIZE: return 0x1000;
    case BIONIC_SC_NPROCESSORS_CONF:
    case BIONIC_SC_NPROCESSORS_ONLN:
    case LINUX_SC_NPROCESSORS_CONF:
    case LINUX_SC_NPROCESSORS_ONLN: {
      static int logged = 0;
      if (!logged) { logged = 1; debugPrintf("[sysconf] NPROCESSORS query name=%d -> 3\n", name); }
      return 3;
    }
    // Report 512 MB (matches synthetic /proc/meminfo MemTotal) to make Unity's
    // DynamicHeap reserve fewer 256MB regions; real backing (arena/OC) holds more.
    case BIONIC_SC_PHYS_PAGES: return (512ll * 1024 * 1024) / 0x1000;
    default: return -1;
  }
}
long pathconf_fake(const char *path, int name) { (void)path; (void)name; return -1; }

// ---------------------------------------------------------------------------
// open() flag translation (bionic/linux -> newlib)
// ---------------------------------------------------------------------------

#define LINUX_O_CREAT  0100
#define LINUX_O_EXCL   0200
#define LINUX_O_TRUNC  01000
#define LINUX_O_APPEND 02000

static int convert_open_flags(int flags) {
  int out = flags & 3;
  if (flags & LINUX_O_CREAT)  out |= O_CREAT;
  if (flags & LINUX_O_EXCL)   out |= O_EXCL;
  if (flags & LINUX_O_TRUNC)  out |= O_TRUNC;
  if (flags & LINUX_O_APPEND) out |= O_APPEND;
  return out;
}

// The engine addresses asset packs as "<packdir>/<file>.mvgl" but we ship the
// data flat in the game dir. If a read path with a subdirectory is missing,
// fall back to just its basename in the cwd (the game dir). Reads only -- never
// redirect a write -- and only when the basename actually exists.
static int basename_fallback(const char *path, char *out, size_t outsz) {
  const char *slash = strrchr(path, '/');
  if (!slash || !slash[1]) return 0;   // no subdir component to strip
  struct stat st;
  snprintf(out, outsz, "%s", slash + 1); // basename, resolved against the cwd
  return stat(out, &st) == 0;
}

// Create one directory, skipping paths newlib's mkdir() can't handle safely.
// A bare "device:" path (e.g. "sdmc:") makes newlib resolve to a device root
// with an empty in-device path and dereference a NULL devoptab -- a Data Abort
// reading devoptab->mkdir_r at +0x68. Refuse those (and null/empty).
static int safe_mkdir(const char *p) {
  if (!p || !*p) { errno = EINVAL; return -1; }
  const char *colon = strchr(p, ':');
  if (colon) {                       // has a "device:" prefix
    const char *in = colon + 1;      // the path inside the device
    while (*in == '/') in++;
    if (!*in) { errno = EEXIST; return 0; }  // "sdmc:" / "sdmc:/" -> root, skip
    // A single top-level component ("sdmc:/switch") also null-derefs newlib's
    // devoptab. Such dirs (the homebrew mount point) always pre-exist already.
    if (!strchr(in, '/')) { errno = EEXIST; return 0; }
  }
  return mkdir(p, 0777);
}

// mkdir -p: create `dir` and every missing parent. Save data lives in subdirs
// the engine only mkdir()s one level at a time, so a deeper missing parent left
// the whole chain (and the save write) failing.
//
// We must NOT try to create the game root or any ancestor of it ("sdmc:",
// "sdmc:/switch", "sdmc:/switch/aota"): they already exist, they aren't
// ours, and newlib's mkdir() of a *top-level* path (one component under the
// device, e.g. "sdmc:/switch") null-derefs its devoptab -> Data Abort at the
// mkdir_r slot (+0x68). So begin the parent walk *after* GAME_HOME.
static void mkdir_p_dir(const char *dir) {
  if (!dir || !*dir) return;
  char tmp[512];
  if (snprintf(tmp, sizeof(tmp), "%s", dir) <= 0) return;
  size_t skip;
  const size_t glen = strlen(GAME_HOME);
  if (strncmp(tmp, GAME_HOME, glen) == 0 && (tmp[glen] == '/' || tmp[glen] == '\0')) {
    skip = glen;                                  // only create *under* the game root
  } else {
    const char *colon = strchr(tmp, ':');         // unknown base: at least skip "device:"
    skip = colon ? (size_t)(colon + 1 - tmp) : 0;
  }
  for (char *p = tmp + skip + 1; *p; p++)
    if (*p == '/') { *p = '\0'; safe_mkdir(tmp); *p = '/'; }
  if (tmp[skip]) safe_mkdir(tmp);
}
// create the parent directory chain of a file path
static void mkdir_parents(const char *filepath) {
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s", filepath);
  char *last = strrchr(tmp, '/');
  if (!last || last == tmp) return;
  *last = '\0';
  mkdir_p_dir(tmp);
}

// mkdir wrapper: create the full chain and treat "already exists" as success
int mkdir_fake(const char *path, unsigned mode) {
  (void)mode;
  if (!path || !*path) { errno = EINVAL; return -1; }
  mkdir_p_dir(path);
  int r = safe_mkdir(path);
  if (r != 0 && errno == EEXIST) r = 0;
  return r;
}

int g_watch_fd = -1;   /* main archive fd: trace its reads/seeks to debug header load */
void watch_dump(const char *tag, int fd, long a, long b, const void *buf, long got) {
  if (fd != g_watch_fd) return;
  char h[64]; int n = (got > 16 ? 16 : (got < 0 ? 0 : (int)got));
  int p = 0; for (int i = 0; i < n; i++) p += snprintf(h + p, sizeof(h) - p, "%02x ", ((const unsigned char *)buf)[i]);
  h[p] = 0;
  debugPrintf("[io] %s fd=%d a=%ld b=%ld -> %ld  [%s]\n", tag, fd, a, b, got, h);
}

/* lseek for arm64: off_t is already 64-bit, so this also services lseek64.
 * lseek64 was previously stubbed to return 0 (no seek) -- that made libunity's
 * archive reader see the main archive as empty/mis-positioned ("Unable to read
 * header from archive file"), since it lseek64(SEEK_END)s to size the file. */
long z_lseek(int fd, long off, int whence) {
  if (asset_pack_fd_is(fd)) return asset_pack_lseek_fd(fd, off, whence);
  long r = lseek(fd, off, whence);
  if (fd == g_watch_fd) debugPrintf("[io] lseek fd=%d off=%ld whence=%d -> %ld\n", fd, off, whence, r);
  return r;
}

static const char *synthetic_proc(const char *path);  /* defined below */

// Serve /proc and /sys reads that arrive through raw open() (e.g.
// /proc/self/maps, which the engine opens to enumerate memory mappings).
// newlib's open() can't be memory-backed, so materialize the synthetic content
// into a small file under the game dir and hand back a real fd. Returns an fd,
// or -1 if `path` isn't a node we synthesize (caller proceeds normally).
static int synth_proc_open(const char *path) {
  if (!path) return -1;
  if (strncmp(path, "/proc/", 6) && strncmp(path, "/sys/", 5)) return -1;
  static char buf[16384];
  int len;
  if (!strcmp(path, "/proc/self/maps") || !strcmp(path, "/proc/self/smaps")) {
    len = so_dump_maps(buf, sizeof buf);
  } else {
    const char *s = synthetic_proc(path);
    if (!s) return -1;                                   // not /proc or /sys
    len = (int)strlen(s);
    if (len > (int)sizeof buf) len = (int)sizeof buf;
    memcpy(buf, s, (size_t)len);
  }
  char safe[160]; size_t j = 0;
  for (const char *p = path; *p && j < sizeof safe - 1; p++) safe[j++] = (*p == '/') ? '_' : *p;
  safe[j] = '\0';
  char tf[768];   /* GAME_HOME + "/.synth" + up to 160 bytes of `safe` */
  snprintf(tf, sizeof tf, "%s/.synth%s", GAME_HOME, safe);
  int wfd = open(tf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (wfd >= 0) { if (write(wfd, buf, (size_t)len) < 0) { /* best effort */ } close(wfd); }
  return open(tf, O_RDONLY);
}

/* Unity probes filesystem case-sensitivity on every boot: it creates
 * CASESENSITIVETEST<guid> (O_CREAT|O_EXCL) in the data root, re-opens it under
 * a different case, and never cleans up -- a fresh GUID name each launch, so
 * junk accumulates on the SD card. Redirect every such name (any case, any
 * guid) onto ONE fixed hidden scratch file. Different-case probes then hit the
 * same file, which is precisely the case-INSENSITIVE answer FAT gives anyway,
 * and main.c sweeps the scratch (plus any strays from older builds) at boot. */
static const char *casetest_redirect(const char *path) {
  const char *b = strrchr(path, '/');
  b = b ? b + 1 : path;
  if (strncasecmp(b, "CASESENSITIVETEST", 17) == 0)
    return game_path(".casetest");
  return path;
}

void rc_mark(int fd, int on);                    /* asset read cache (defined below) */
long rc_pread_pub(int fd, void *buf, size_t count, unsigned long long off);
int open_fake(const char *path, int flags, ...) {
  path = nx_fonts_resolve(path);   /* Switch system fonts as /system/fonts */
  path = casetest_redirect(path);
  int mode = 0666;
  if (flags & LINUX_O_CREAT) { va_list va; va_start(va, flags); mode = va_arg(va, int); va_end(va); }
  const int cvt = convert_open_flags(flags);
  const int writing = (flags & 3) != 0 || (flags & LINUX_O_CREAT);
  if (!writing) {
    // /dev/urandom + /dev/random: Switch has no /dev node, but Mono/.NET (RNG
    // seeds, Guid.NewGuid, hashtable randomization) and asset crypto open these.
    // A failing open (-1) leaves those paths without entropy and can stall the
    // scene/asset load. Materialize a buffer of real CSPRNG bytes (libnx
    // randomGet) into a file and hand back a real fd so read() just works.
    if (!strcmp(path, "/dev/urandom") || !strcmp(path, "/dev/random")) {
      static char rbuf[65536];
      randomGet(rbuf, sizeof rbuf);
      char tf[768];  /* GAME_HOME + "/.synth_dev_random" */
      snprintf(tf, sizeof tf, "%s/.synth_dev_random", GAME_HOME);
      int wfd = open(tf, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (wfd >= 0) { if (write(wfd, rbuf, sizeof rbuf) < 0) { /* best effort */ } close(wfd); }
      int rfd = open(tf, O_RDONLY);
      debugPrintf("[io] open(%s,0x%x) -> %d [urandom]\n", path, flags, rfd);
      return rfd;
    }
    // synthetic /proc, /sys (incl. self/maps)
    int sfd = synth_proc_open(path);
    if (sfd >= 0) { debugPrintf("[io] open(%s,0x%x) -> %d [synthetic]\n", path, flags, sfd); return sfd; }
  }
  if (!writing) {
    /* Packed assets win over the filesystem: after the first boot the loose
     * tree is gone and this is the only place the data exists. */
    int packed_fd = asset_pack_open_path(path);
    if (packed_fd >= 0) {
      debugPrintf("[io] open(%s,0x%x) -> %d [pack]\n", path, flags, packed_fd);
      return packed_fd;
    }
  }
  int fd = open(path, cvt, mode);
  if (fd < 0 && writing) {
    // save files: the target subdir may not exist yet -- create it and retry
    mkdir_parents(path);
    fd = open(path, cvt, mode);
  }
  if (fd < 0 && (flags & 3) == 0 && !(flags & LINUX_O_CREAT)) {
    char alt[320];
    if (basename_fallback(path, alt, sizeof(alt)))
      fd = open(alt, cvt, mode);
  }
  if (fd >= 0) {
    rc_mark(fd, ((flags & 3) == 0));      /* cache read-only files only */
    struct stat _st;
    if (fstat(fd, &_st) == 0)
      debugPrintf("[io] open(%s,0x%x) -> %d size=%lld\n", path, flags, fd, (long long)_st.st_size);
    else
      debugPrintf("[io] open(%s,0x%x) -> %d size=?\n", path, flags, fd);
#if TRACE_BUNDLE_IO
    if (strstr(path, "data.unity3d")) { g_watch_fd = fd; debugPrintf("[io] >>> watching fd=%d (data.unity3d)\n", fd); }
#endif
  } else {
    debugPrintf("[io] open(%s,0x%x) -> %d\n", path, flags, fd);
  }
  return fd;
}
int openat_fake(int dirfd, const char *path, int flags, ...) {
  (void)dirfd;
  int mode = 0666;
  if (flags & LINUX_O_CREAT) { va_list va; va_start(va, flags); mode = va_arg(va, int); va_end(va); }
  // Delegate to open_fake so /dev/urandom, synthetic /proc + /sys, save-dir
  // creation and basename fallback all apply (some libc paths route open->openat).
  return open_fake(path, flags, mode);
}
int unlinkat_fake(int dirfd, const char *path, int flags) { (void)dirfd; (void)flags; return unlink(path); }

// ---------------------------------------------------------------------------
// struct stat conversion (bionic aarch64 layout)
// ---------------------------------------------------------------------------

struct bionic_timespec { int64_t tv_sec; int64_t tv_nsec; };
struct bionic_stat {
  uint64_t st_dev; uint64_t st_ino; uint32_t st_mode; uint32_t st_nlink;
  uint32_t st_uid; uint32_t st_gid; uint64_t st_rdev; uint64_t __pad1;
  int64_t st_size; int32_t st_blksize; int32_t __pad2; int64_t st_blocks;
  struct bionic_timespec st_atim; struct bionic_timespec st_mtim; struct bionic_timespec st_ctim;
  uint32_t __unused4; uint32_t __unused5;
};

static void convert_stat(const struct stat *in, struct bionic_stat *out) {
  memset(out, 0, sizeof(*out));
  out->st_dev = in->st_dev; out->st_ino = in->st_ino; out->st_mode = in->st_mode;
  out->st_nlink = in->st_nlink; out->st_uid = in->st_uid; out->st_gid = in->st_gid;
  out->st_rdev = in->st_rdev; out->st_size = in->st_size; out->st_blksize = in->st_blksize;
  out->st_blocks = in->st_blocks;
  out->st_atim.tv_sec = in->st_atime; out->st_mtim.tv_sec = in->st_mtime; out->st_ctim.tv_sec = in->st_ctime;
}

int stat_fake(const char *path, struct bionic_stat *st) {
  path = nx_fonts_resolve(path);   /* Switch system fonts as /system/fonts */
  path = casetest_redirect(path);
  {
    uint64_t psz, pino; int pdir;
    if (asset_pack_stat_path_info(path, &psz, &pino, &pdir)) {
      struct stat real;
      memset(&real, 0, sizeof real);
      real.st_mode = pdir ? (S_IFDIR | 0555) : (S_IFREG | 0444);
      real.st_size = (off_t)psz;
      real.st_ino  = (ino_t)pino;
      real.st_nlink = 1;
      real.st_blksize = 4096;
      real.st_blocks = (blkcnt_t)((psz + 511) / 512);
      convert_stat(&real, st);
      return 0;
    }
  }
  struct stat real; int r = stat(path, &real);
  if (r != 0) {
    char alt[320];
    if (basename_fallback(path, alt, sizeof(alt))) r = stat(alt, &real);
  }
  if (r == 0) convert_stat(&real, st);
  return r;
}
int fstat_fake(int fd, struct bionic_stat *st) {
  {
    uint64_t psz, pino; int pdir;
    if (asset_pack_fstat_fd(fd, &psz, &pino, &pdir)) {
      struct stat real;
      memset(&real, 0, sizeof real);
      real.st_mode = pdir ? (S_IFDIR | 0555) : (S_IFREG | 0444);
      real.st_size = (off_t)psz;
      real.st_ino  = (ino_t)pino;
      real.st_nlink = 1;
      real.st_blksize = 4096;
      real.st_blocks = (blkcnt_t)((psz + 511) / 512);
      convert_stat(&real, st);
      return 0;
    }
  }
  struct stat real; const int r = fstat(fd, &real);
  if (r == 0) convert_stat(&real, st);
  return r;
}
int lstat_fake(const char *path, struct bionic_stat *st) { return stat_fake(path, st); }

// ---------------------------------------------------------------------------
// dirent conversion (bionic dirent64 layout)
// ---------------------------------------------------------------------------

struct bionic_dirent {
  uint64_t d_ino; int64_t d_off; uint16_t d_reclen; uint8_t d_type; char d_name[256];
};

void *opendir_fake(const char *path) {
  path = nx_fonts_resolve(path);   /* Switch system fonts as /system/fonts */
  void *pd = asset_pack_opendir_path(path);
  if (pd) return pd;
  return (void *)opendir(path);
}
int closedir_fake(void *dirp) {
  if (asset_pack_dir_is(dirp)) return asset_pack_closedir_path(dirp);
  return closedir((DIR *)dirp);
}
void *readdir_fake(void *dirp) {
  static struct bionic_dirent out; // not thread-safe (matches bionic readdir)
  if (asset_pack_dir_is(dirp)) {
    memset(&out, 0, sizeof(out));
    const char *nm = asset_pack_readdir_path(dirp, &out.d_type, &out.d_ino);
    if (!nm) return NULL;
    out.d_reclen = sizeof(out);
    snprintf(out.d_name, sizeof(out.d_name), "%s", nm);
    return &out;
  }
  struct dirent *e = readdir((DIR *)dirp);
  if (!e) return NULL;
  memset(&out, 0, sizeof(out));
  out.d_ino = e->d_ino;
  out.d_reclen = sizeof(out);
  out.d_type = e->d_type;
  snprintf(out.d_name, sizeof(out.d_name), "%s", e->d_name);
  return &out;
}

// ---------------------------------------------------------------------------
// locale: ignore the locale argument and use the C-locale versions
// ---------------------------------------------------------------------------

void *newlocale_fake(int mask, const char *locale, void *base) { (void)mask; (void)locale; (void)base; return (void *)1; }
void freelocale_fake(void *loc) { (void)loc; }
void *uselocale_fake(void *loc) { (void)loc; return (void *)1; }

#define WRAP_ISW_L(fn) int fn##_l_fake(int wc, void *loc) { (void)loc; return fn(wc); }
WRAP_ISW_L(iswalpha) WRAP_ISW_L(iswblank) WRAP_ISW_L(iswcntrl) WRAP_ISW_L(iswdigit)
WRAP_ISW_L(iswlower) WRAP_ISW_L(iswprint) WRAP_ISW_L(iswpunct) WRAP_ISW_L(iswspace)
WRAP_ISW_L(iswupper) WRAP_ISW_L(iswxdigit) WRAP_ISW_L(towlower) WRAP_ISW_L(towupper)

int strcoll_l_fake(const char *a, const char *b, void *loc) { (void)loc; return strcoll(a, b); }
size_t strxfrm_l_fake(char *dst, const char *src, size_t n, void *loc) { (void)loc; return strxfrm(dst, src, n); }
size_t strftime_l_fake(char *s, size_t max, const char *fmt, const void *tm, void *loc) { (void)loc; return strftime(s, max, fmt, (const struct tm *)tm); }
long double strtold_l_fake(const char *s, char **end, void *loc) { (void)loc; return strtold(s, end); }
long long strtoll_l_fake(const char *s, char **end, int base, void *loc) { (void)loc; return strtoll(s, end, base); }
unsigned long long strtoull_l_fake(const char *s, char **end, int base, void *loc) { (void)loc; return strtoull(s, end, base); }
int wcscoll_l_fake(const wchar_t *a, const wchar_t *b, void *loc) { (void)loc; return wcscoll(a, b); }
size_t wcsxfrm_l_fake(wchar_t *dst, const wchar_t *src, size_t n, void *loc) { (void)loc; return wcsxfrm(dst, src, n); }

size_t mbsnrtowcs_fake(wchar_t *dst, const char **src, size_t nms, size_t len, void *ps) {
  (void)ps;
  size_t i = 0; const char *s = *src;
  while (i < nms && s[i] && (!dst || i < len)) { if (dst) dst[i] = (unsigned char)s[i]; i++; }
  if (dst && i < len) { dst[i] = 0; *src = NULL; }
  return i;
}
size_t wcsnrtombs_fake(char *dst, const wchar_t **src, size_t nwc, size_t len, void *ps) {
  (void)ps;
  size_t i = 0; const wchar_t *s = *src;
  while (i < nwc && s[i] && (!dst || i < len)) { if (dst) dst[i] = (char)s[i]; i++; }
  if (dst && i < len) { dst[i] = 0; *src = NULL; }
  return i;
}

// ---------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------

int posix_memalign_fake(void **out, size_t align, size_t size) {
  void *p = memalign(align, size);
  if (!p) return ENOMEM;
  *out = p;
  return 0;
}

// --- anonymous mmap arena (page-granular; supports sub-range munmap) ----------
//
// Switch has no mmap. Unity reserves big *256MB-aligned* pools by over-mmapping a
// larger region then munmapping the unaligned head/tail to keep an aligned middle.
// A plain malloc/free-per-mmap frees the WHOLE block when the head is trimmed (the
// trim's addr == the registered base) and the kept aligned middle is then reused
// out from under the engine -> the TLSF allocator's free block reads back zeroed
// (next_free == NULL) and faults. So we manage a dedicated arena (carved 256MB-
// aligned in __libnx_initheap) with a per-page used-bitmap: mmap = find a free run
// of pages and mark them; munmap = clear exactly the pages of the sub-range. Big
// requests are handed back 256MB-aligned so Unity only ever trims the tail.
// File-backed maps (Unity streams BGM/SE this way) are served from the same arena.
// ------------------------------------------------------------------------------
extern void  *g_mmap_arena_base;   // set by __libnx_initheap (main.c)
extern size_t g_mmap_arena_size;
extern int    g_overcommit;        // 1 = alias-region on-demand commit
extern u64    g_alias_base, g_alias_size;

#define BIONIC_MAP_ANONYMOUS 0x20
#define BIONIC_MAP_FIXED     0x10
#define MMAP_PAGE       0x1000u
#define MMAP_BIG_ALIGN  MMAP_ARENA_ALIGN
/* Alignment Baselib_Memory_AllocatePages asks for after the libunity "region granularity
 * 256MB->64MB" patch. A reservation then looks like mmap(size + 64MB - 4KB). */
#ifndef MMAP_UNITY_ALIGN
#define MMAP_UNITY_ALIGN ((size_t)64 * 1024 * 1024)
#endif
/* Pages Unity keeps out of an over-map of `len` bytes: len = size + align - PAGE with
 * align == MMAP_UNITY_ALIGN. Any other length is NOT treated as an over-map (we then
 * assume the caller keeps all of it), so the "tail slot" trick below can never hand out
 * a slot that is smaller than what Unity will really use. */
static size_t mmap_overmap_kept_pages(size_t need_pages, size_t len) {
  const size_t ua = MMAP_UNITY_ALIGN / MMAP_PAGE;
  if (((len + MMAP_PAGE) % MMAP_UNITY_ALIGN) == 0 && len + MMAP_PAGE >= 2 * MMAP_UNITY_ALIGN)
    return need_pages + 1 - ua;
  return need_pages;
}
#define MMAP_BIG_THRESH ((size_t)64 * 1024 * 1024)
#define BIONIC_PROT_NONE 0x0
#define BIONIC_PROT_WRITE 0x2
#define BIONIC_MADV_DONTNEED 4

static uint8_t *mmap_arena;    // 256MB-aligned usable base (published last)
static size_t   mmap_usable;   // usable bytes
static size_t   mmap_pages;    // usable / page
static uint8_t *mmap_used;     // 1 byte/page bitmap: reserved (address space)
static uint8_t *mmap_committed;// 1 byte/page bitmap: physically committed (overcommit only)
static size_t   g_committed_pages;   // running count of committed pages
static size_t   g_commit_peak;       // high-water mark (pages)
static Mutex    g_mmap_lock;   // zero-init == valid unlocked libnx mutex

// --- overcommit commit/decommit (caller holds g_mmap_lock) -------------------
// svcMapPhysicalMemory zero-fills and draws from the freed physical limit; it
// FAILS on already-mapped pages, so we only ever commit pages we track as
// uncommitted, in contiguous runs. Out-of-physical is logged, not fatal.
static void arena_commit_locked(size_t first, size_t cnt) {
  size_t i = 0;
  while (i < cnt) {
    if (mmap_committed[first + i]) { i++; continue; }
    size_t run = 0;
    while (i + run < cnt && !mmap_committed[first + i + run]) run++;
    u64 a = (u64)(uintptr_t)(mmap_arena + (first + i) * MMAP_PAGE);
    Result rc = svcMapPhysicalMemory((void *)a, (u64)run * MMAP_PAGE);
    if (R_SUCCEEDED(rc)) {
      for (size_t k = 0; k < run; k++) mmap_committed[first + i + k] = 1;
      g_committed_pages += run;
      if (g_committed_pages > g_commit_peak) {
        size_t prev = g_commit_peak;
        g_commit_peak = g_committed_pages;
        if ((g_commit_peak >> 16) != (prev >> 16))   // new 256MB high-water mark
          debugPrintf("[mmap] committed peak %u MB (live %u MB)\n",
                      (unsigned)((g_commit_peak * MMAP_PAGE) >> 20),
                      (unsigned)((g_committed_pages * MMAP_PAGE) >> 20));
      }
    } else {
      debugPrintf("[mmap] COMMIT FAIL %u KB @ 0x%lx rc=0x%x (committed %u MB peak %u MB)\n",
                  (unsigned)((run * MMAP_PAGE) >> 10), (unsigned long)a, rc,
                  (unsigned)((g_committed_pages * MMAP_PAGE) >> 20),
                  (unsigned)((g_commit_peak * MMAP_PAGE) >> 20));
    }
    i += run ? run : 1;
  }
}

static void arena_decommit_locked(size_t first, size_t cnt) {
  size_t i = 0;
  while (i < cnt) {
    if (!mmap_committed[first + i]) { i++; continue; }
    size_t run = 0;
    while (i + run < cnt && mmap_committed[first + i + run]) run++;
    u64 a = (u64)(uintptr_t)(mmap_arena + (first + i) * MMAP_PAGE);
    if (R_SUCCEEDED(svcUnmapPhysicalMemory((void *)a, (u64)run * MMAP_PAGE))) {
      for (size_t k = 0; k < run; k++) mmap_committed[first + i + k] = 0;
      g_committed_pages -= run;
    }
    i += run ? run : 1;
  }
}

// translate [addr,addr+len) to a clamped page range within the arena; returns 0 if
// outside the arena (e.g. a newlib-fallback pointer), else 1 with *first/*cnt set.
static int arena_page_range(void *addr, size_t len, size_t *first, size_t *cnt) {
  if (!mmap_arena || (uint8_t *)addr < mmap_arena) return 0;
  size_t off = (uint8_t *)addr - mmap_arena;
  if (off >= mmap_usable) return 0;
  size_t f = off / MMAP_PAGE;
  size_t c = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (f + c > mmap_pages) c = mmap_pages - f;
  *first = f; *cnt = c;
  return 1;
}

// commit [addr,len) on demand (mprotect RW / anon mmap). no-op if not overcommit.
static void arena_commit_range(void *addr, size_t len) {
  if (!g_overcommit) return;
  size_t first, cnt;
  mutexLock(&g_mmap_lock);
  if (arena_page_range(addr, len, &first, &cnt)) arena_commit_locked(first, cnt);
  mutexUnlock(&g_mmap_lock);
}

// decommit [addr,len) (mprotect PROT_NONE / munmap). reclaims physical. Safe
// because re-use of a decommitted page goes through mprotect(RW) -> recommit.
static void arena_decommit_range(void *addr, size_t len) {
  if (!g_overcommit) return;
  size_t first, cnt;
  mutexLock(&g_mmap_lock);
  if (arena_page_range(addr, len, &first, &cnt)) arena_decommit_locked(first, cnt);
  mutexUnlock(&g_mmap_lock);
}

// madvise(MADV_DONTNEED): zero the committed pages but KEEP them committed. The
// Switch has no fault handler, so decommitting here would crash if the engine
// re-touches without an intervening mprotect(RW) (allowed on Linux). Zeroing
// preserves the "reads back as zero after DONTNEED" contract safely.
static void arena_dontneed_range(void *addr, size_t len) {
  if (!g_overcommit) return;
  size_t first, cnt;
  mutexLock(&g_mmap_lock);
  if (arena_page_range(addr, len, &first, &cnt)) {
    for (size_t i = 0; i < cnt; ) {
      if (!mmap_committed[first + i]) { i++; continue; }
      size_t run = 0;
      while (i + run < cnt && mmap_committed[first + i + run]) run++;
      memset(mmap_arena + (first + i) * MMAP_PAGE, 0, run * MMAP_PAGE);
      i += run;
    }
  }
  mutexUnlock(&g_mmap_lock);
}

// ===========================================================================
// Stack-region overcommit (OC) arena.
// Boot probe established: svcMapMemory can alias heap pages into the STACK
// region (the alias region is rejected, kernel err 0xdc01), and Unity reserves
// ~2.8GB of PROT_NONE blocks while committing only ~80MB via mprotect(RW) with
// ZERO decommits. So we satisfy the big PROT_NONE reservations from a cheap
// stack-region address window and alias a small bump-allocated heap commit-pool
// in on mprotect(RW). Tried BEFORE the heap-backed arena for big anon PROT_NONE
// maps; anything else (and overflow when the window fills) falls through to the
// heap-backed arena, so if OC setup fails the engine runs exactly as before.
// Because decommits are never observed, the pool is a no-reclaim bump allocator.
// ===========================================================================
#define OC_NWIN 6   /* was 2: extra stack-region holes can be added with oc_arena_add_window() */
#define OC_NOSRC 0xFFFFFFFFu
typedef struct {
  uint8_t  *base;               // window base (64MB-aligned)
  size_t    pages;              // size in pages
  uint8_t  *used;               // 1/page: reserved by an mmap
  uint8_t  *committed;          // 1/page: physically backed via svcMapMemory
  uint32_t *srcpg;              // 1/page: which pool page backs it (OC_NOSRC = none)
} OcWin;
static OcWin    oc_win[OC_NWIN];
static int      oc_nwin;        // 0 => OC disabled
static uint8_t *oc_pool;        // shared commit-pool base (heap, page-aligned)
static size_t   oc_pool_pages;  // pool capacity in pages
static size_t   oc_pool_bump;   // next never-used pool page (bump)
static uint32_t *oc_pool_next;  // free-list links, one per pool page
static uint32_t oc_pool_freehead = OC_NOSRC;   // recycled pool pages
static size_t   oc_pool_freecnt;
static size_t   oc_live_pages;  // committed pages (diagnostic)

// Called once from main() after the newlib heap exists. window = a reserved
// stack-region range; pool = a heap buffer. Returns 1 if OC is armed.
static int oc_add_window_locked(void *window, size_t bytes) {
  if (oc_nwin >= OC_NWIN || !window || !bytes) return 0;
  size_t wp = bytes / MMAP_PAGE;
  uint8_t *u = (uint8_t *)calloc(wp, 1);
  uint8_t *c = (uint8_t *)calloc(wp, 1);
  uint32_t *sp = (uint32_t *)malloc(wp * sizeof(uint32_t));
  if (!u || !c || !sp) { free(u); free(c); free(sp); return 0; }
  for (size_t k = 0; k < wp; k++) sp[k] = OC_NOSRC;
  oc_win[oc_nwin].base = (uint8_t *)window; oc_win[oc_nwin].pages = wp;
  oc_win[oc_nwin].used = u; oc_win[oc_nwin].committed = c;
  oc_win[oc_nwin].srcpg = sp;
  oc_nwin++;
  return 1;
}
int oc_arena_init(void *window, size_t window_bytes, void *pool, size_t pool_bytes) {
  if (!window || !pool || !window_bytes || !pool_bytes) return 0;
  mutexLock(&g_mmap_lock);
  int ok = oc_add_window_locked(window, window_bytes);
  if (ok) {
    oc_pool = (uint8_t *)pool; oc_pool_pages = pool_bytes / MMAP_PAGE;
    oc_pool_bump = 0; oc_live_pages = 0;
    oc_pool_next = (uint32_t *)malloc(oc_pool_pages * sizeof(uint32_t));
    oc_pool_freehead = OC_NOSRC; oc_pool_freecnt = 0;
    if (!oc_pool_next) ok = 0;   /* recycling is mandatory: without it the pool leaks */
  }
  mutexUnlock(&g_mmap_lock);
  return ok;
}
int oc_arena_add_window(void *window, size_t window_bytes) {   /* second hole */
  mutexLock(&g_mmap_lock);
  int ok = (oc_nwin > 0) && oc_add_window_locked(window, window_bytes);
  mutexUnlock(&g_mmap_lock);
  return ok;
}

static OcWin *oc_win_of(void *addr) {
  for (int w = 0; w < oc_nwin; w++)
    if ((uint8_t *)addr >= oc_win[w].base &&
        (uint8_t *)addr <  oc_win[w].base + oc_win[w].pages * MMAP_PAGE)
      return &oc_win[w];
  return NULL;
}
static int oc_contains(void *addr) { return oc_win_of(addr) != NULL; }

/* Build #126: phantom tails. An over-map request (320 MB for a 256 MB block)
 * is now served by reserving ONLY the pages the game keeps; the alignment
 * slack behind the kept block is recorded here instead of consuming window
 * VA. Baselib munmaps that slack immediately after the reserve; when the
 * trim arrives, oc_free_locked/mprotect_fake match it against this table
 * and treat it as a no-op, so the trim can never clear bitmap pages of a
 * newer reservation that reused the slack VA in the meantime. Entries are
 * dropped when their trim is consumed; a full table falls back to the old
 * full-length reservation for that request. */
#define OC_PHANTOM_MAX 32
static struct { uint8_t *base; size_t len; } oc_phantom_tab[OC_PHANTOM_MAX];
static int oc_phantom_add(uint8_t *base, size_t len) {
  for (int i = 0; i < OC_PHANTOM_MAX; i++)
    if (!oc_phantom_tab[i].len) {
      oc_phantom_tab[i].base = base; oc_phantom_tab[i].len = len;
      debugPrintf("[oc126] phantom tail %p +%zu MB (slot %d)\n",
                  (void *)base, len >> 20, i);
      return 1;
    }
  return 0;
}
/* 1 if [addr, addr+len) is (the bulk of) a live phantom tail. Baselib's
 * tail trim starts one page before our phantom span (its kept block is one
 * page shorter than the wrapper's kept count) and ends at most at the
 * span end. With consume=1 the entry is dropped once the trim reaches the
 * span end. A munmap swallowed by this match can only ever leak VA (if a
 * newer reservation had reused the slack), never free a live page. */
static int oc_phantom_match(void *addr, size_t len, int consume) {
  uint8_t *a = (uint8_t *)addr, *e = a + len;
  for (int i = 0; i < OC_PHANTOM_MAX; i++) {
    if (!oc_phantom_tab[i].len) continue;
    uint8_t *pb = oc_phantom_tab[i].base, *pe = pb + oc_phantom_tab[i].len;
    if (a >= pb - MMAP_PAGE && a < pe && e <= pe) {
      if (consume && e >= pe - MMAP_PAGE) oc_phantom_tab[i].len = 0;
      return 1;
    }
  }
  return 0;
}

// Reserve address space in the OC window. Mirrors mmap_arena_alloc_locked's
// 256MB-aligned tail-overflow so Unity's 511MB over-map nets one 256MB slot.
// caller holds g_mmap_lock.
static void *oc_alloc_locked(size_t len, size_t *got) {
  *got = 0;
  size_t need = (len + MMAP_PAGE - 1) / MMAP_PAGE; if (!need) need = 1;
  const size_t step = MMAP_BIG_ALIGN / MMAP_PAGE;
  /* 2026-10-14: was `need > step ? need - step : need` (assumed a 256MB alignment slack, so a
   * 319MB over-map "kept" only 64MB and a 100MB tail hole was accepted for a 256MB block). */
  size_t kept = mmap_overmap_kept_pages(need, len);
  /* Build #126: for an over-map-signature request, pass 1 reserves only the
   * kept pages (320 MB request -> 256 MB reserved); the 64 MB slack becomes
   * a phantom tail (see above). Non-over-map requests are unchanged. */
  size_t p1_need = (kept < need) ? kept : need;
  for (int w = 0; w < oc_nwin; w++) {                          // pass 1
    OcWin *W = &oc_win[w];
    for (size_t i = 0; i + p1_need <= W->pages; i += step) {
      size_t run = 0; while (run < p1_need && !W->used[i + run]) run++;
      if (run == p1_need) {
        if (p1_need < need &&
            !oc_phantom_add(W->base + (i + p1_need) * MMAP_PAGE,
                            (need - p1_need) * MMAP_PAGE)) {
          /* phantom table full: reserve the full over-map the old way */
          if (i + need > W->pages) continue;
          size_t frun = 0; while (frun < need && !W->used[i + frun]) frun++;
          if (frun < need) continue;
          for (size_t k = 0; k < need; k++) W->used[i + k] = 1;
          *got = need * MMAP_PAGE; return W->base + i * MMAP_PAGE;
        }
        for (size_t k = 0; k < p1_need; k++) W->used[i + k] = 1;
        *got = p1_need * MMAP_PAGE; return W->base + i * MMAP_PAGE;
      }
    }
  }
  for (int w = 0; w < oc_nwin; w++) {                          // pass 2: tail slot
    OcWin *W = &oc_win[w];
    for (size_t i = 0; i < W->pages; i += step) {
      if (i + need <= W->pages) continue;
      size_t avail = W->pages - i; if (avail < kept) continue;
      size_t run = 0; while (run < avail && !W->used[i + run]) run++;
      if (run == avail) {
        for (size_t k = 0; k < avail; k++) W->used[i + k] = 1;
        *got = avail * MMAP_PAGE; return W->base + i * MMAP_PAGE;
      }
    }
  }
  /* Build #125 diagnostic: on failure, dump per-window used + largest free
   * run so a log shows whether "full" means truly reserved out or merely
   * fragmented below the 320 MB over-map contiguity this caller needs. */
  {
    static unsigned alloc_fail_n = 0;
    if (alloc_fail_n++ < 24) {
      char buf[512]; int o = 0;
      size_t tot_used = 0;
      o += snprintf(buf + o, sizeof(buf) - o,
                    "[oc125] alloc fail #%u %zu MB:", alloc_fail_n,
                    (need * MMAP_PAGE) >> 20);
      for (int w = 0; w < oc_nwin && o < (int)sizeof(buf) - 64; w++) {
        OcWin *W = &oc_win[w];
        size_t u = 0, best = 0, cur = 0;
        for (size_t i = 0; i < W->pages; i++) {
          if (W->used[i]) { u++; cur = 0; }
          else { cur++; if (cur > best) best = cur; }
        }
        tot_used += u;
        o += snprintf(buf + o, sizeof(buf) - o,
                      " w%d used %zu/%zu MB maxrun %zu MB |",
                      w, (u * MMAP_PAGE) >> 20, (W->pages * MMAP_PAGE) >> 20,
                      (best * MMAP_PAGE) >> 20);
      }
      debugPrintf("%s reserved-total %zu MB committed %zu MB\n", buf,
                  (tot_used * MMAP_PAGE) >> 20,
                  (oc_live_pages * MMAP_PAGE) >> 20);
    }
  }
  return NULL;
}

/* Build #130: map [first, first+run) of window W from fresh bump-pool pages.
 * Test #129 crashed because a svcMapMemory failure here was logged and then
 * IGNORED -- the mprotect that asked for the commit still returned success,
 * so the engine wrote into unmapped VA and took a data abort on first touch
 * (dst=0x2c001000, run=1565 pages, rc=0xd401 InvalidSize; the first such
 * failure in any recorded boot). A failed run is now split and retried, so
 * a range-level rejection can still place every placeable page; a page
 * that fails on its own is counted in *failed (its pool page is leaked,
 * never offered for a different destination) and the caller fails the
 * mprotect with ENOMEM instead of leaving the range silently unbacked.
 * The failing dst/src/rc and the kernel state of the destination are
 * logged so a recurrence names the real precondition. Returns pages
 * mapped. Caller holds g_mmap_lock. */
static size_t oc_map_fresh_locked(OcWin *W, size_t first, size_t run, size_t *failed) {
  if (!run) return 0;
  if (oc_pool_bump + run > oc_pool_pages) { *failed += run; return 0; }
  uint32_t srcpg = (uint32_t)oc_pool_bump;
  void *dst = W->base + first * MMAP_PAGE;
  void *src = oc_pool + (size_t)srcpg * MMAP_PAGE;
  Result rc = svcMapMemory(dst, src, (u64)run * MMAP_PAGE);
  if (R_FAILED(rc)) {
    static unsigned fail_n = 0;
    if (fail_n < 8) {
      MemoryInfo mi; u32 pi;
      Result qrc = svcQueryMemory(&mi, &pi, (u64)(uintptr_t)dst);
      debugPrintf("[oc130] svcMapMemory FAIL dst=%p src=%p run=%zu rc=0x%x | query rc=0x%x type=0x%x span=%llu MB (fail #%u)\n",
                  dst, src, run, rc, qrc, mi.type,
                  (unsigned long long)(mi.size >> 20), fail_n + 1);
    }
    fail_n++;
    if (run == 1) {
      *failed += 1;
      oc_pool_bump++;   /* leak the source page: never offer it elsewhere */
      return 0;
    }
    size_t half = run / 2;
    return oc_map_fresh_locked(W, first, half, failed) +
           oc_map_fresh_locked(W, first + half, run - half, failed);
  }
  memset(dst, 0, run * MMAP_PAGE);   // freshly committed anon must read as zero
  for (size_t k = 0; k < run; k++) {
    W->committed[first + k] = 1;
    W->srcpg[first + k] = srcpg + (uint32_t)k;
  }
  oc_pool_bump += run;
  oc_live_pages += run;
  if (((oc_live_pages * MMAP_PAGE) >> 24) != (((oc_live_pages - run) * MMAP_PAGE) >> 24))
    debugPrintf("[oc] committed %zu MB (pool %zu/%zu MB, recycled %zu MB free)\n",
                (oc_live_pages * MMAP_PAGE) >> 20,
                (oc_pool_bump * MMAP_PAGE) >> 20, (oc_pool_pages * MMAP_PAGE) >> 20,
                (oc_pool_freecnt * MMAP_PAGE) >> 20);
  return run;
}

// Commit [addr,len): alias contiguous bump-pool runs into the reserved OC range
// via svcMapMemory (which remaps the pool source away -- we only access via the
// OC address). Already-committed pages are skipped. Build #130: returns the
// number of pages that could NOT be committed (0 = full success); the old
// void version swallowed both svcMapMemory failures and pool exhaustion.
// caller holds g_mmap_lock.
static int oc_commit_locked(void *addr, size_t len) {
  OcWin *W = oc_win_of(addr);
  if (!W) return 0;
  size_t first = ((uint8_t *)addr - W->base) / MMAP_PAGE;
  size_t cnt   = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (first + cnt > W->pages) cnt = W->pages - first;
  size_t failed = 0;
  size_t i = 0;
  while (i < cnt) {
    if (W->committed[first + i]) { i++; continue; }
    size_t run = 0;
    while (i + run < cnt && !W->committed[first + i + run]) run++;
    if (oc_pool_bump + run > oc_pool_pages && oc_pool_freecnt == 0) {
      /* not enough never-used pages and nothing recycled */
      debugPrintf("[oc] commit-pool EXHAUSTED: need %zu pages, %zu bump + %zu free "
                  "(live %zu MB)\n", run, oc_pool_pages - oc_pool_bump,
                  oc_pool_freecnt, (oc_live_pages * MMAP_PAGE) >> 20);
      failed += run;
      break;
    }
    if (run == 1 && oc_pool_freehead != OC_NOSRC) {
      /* recycled page: sources are not contiguous, one at a time (as before) */
      uint32_t srcpg = oc_pool_freehead;
      oc_pool_freehead = oc_pool_next[srcpg];
      oc_pool_freecnt--;
      void *dst = W->base + (first + i) * MMAP_PAGE;
      void *src = oc_pool + (size_t)srcpg * MMAP_PAGE;
      Result rc = svcMapMemory(dst, src, (u64)MMAP_PAGE);
      if (R_FAILED(rc)) {
        debugPrintf("[oc130] svcMapMemory FAIL (recycled) dst=%p src=%p rc=0x%x\n",
                    dst, src, rc);
        oc_pool_next[srcpg] = oc_pool_freehead; oc_pool_freehead = srcpg; oc_pool_freecnt++;
        failed++;
        i++;
        continue;
      }
      memset(dst, 0, MMAP_PAGE);
      W->committed[first + i] = 1;
      W->srcpg[first + i] = srcpg;
      oc_live_pages++;
      i++;
      continue;
    }
    if (oc_pool_bump + run > oc_pool_pages) {
      /* bump fits only part of the run (recycled pages exist but the old
       * one-at-a-time degradation no longer applies to a multi-page run):
       * map what fits and count the rest as failed. */
      size_t fit = oc_pool_pages - oc_pool_bump;
      if (fit) oc_map_fresh_locked(W, first + i, fit, &failed);
      failed += run - fit;
      i += run;
      continue;
    }
    oc_map_fresh_locked(W, first + i, run, &failed);
    i += run;
  }
  return (int)failed;
}

// munmap of an OC range: reclaim only UNCOMMITTED pages (the tail-overflow slack
// Unity trims after each over-map). Committed pages stay reserved+mapped (a small
// bounded leak) so a later reservation can't collide with a live alias.
/* Unmap committed pages and hand their pool pages back for reuse. */
static void oc_decommit_locked(void *addr, size_t len) {
  OcWin *W = oc_win_of(addr);
  if (!W || !oc_pool_next) return;
  size_t off   = (size_t)((uint8_t *)addr - W->base);
  size_t first = (off + MMAP_PAGE - 1) / MMAP_PAGE;   /* partial head page stays */
  size_t lastx = (off + len) / MMAP_PAGE;
  if (lastx > W->pages) lastx = W->pages;
  size_t i = first;
  while (i < lastx) {
    if (!W->committed[i]) { i++; continue; }
    size_t run = 1;                                   /* batch contiguous dst+src */
    while (i + run < lastx && W->committed[i + run] &&
           W->srcpg[i + run] == W->srcpg[i] + run) run++;
    void *dst = W->base + i * MMAP_PAGE;
    void *src = oc_pool + (size_t)W->srcpg[i] * MMAP_PAGE;
    Result urc = svcUnmapMemory(dst, src, (u64)run * MMAP_PAGE);
    if (R_SUCCEEDED(urc)) {
      for (size_t k = 0; k < run; k++) {
        uint32_t sp = W->srcpg[i + k];
        oc_pool_next[sp] = oc_pool_freehead; oc_pool_freehead = sp; oc_pool_freecnt++;
        W->committed[i + k] = 0; W->srcpg[i + k] = OC_NOSRC;
        if (oc_live_pages) oc_live_pages--;
      }
    } else {
      /* Build #125 diagnostic: decommit failures were silently swallowed --
       * a failed unmap leaves the pages committed AND the VA reserved
       * forever, which is one candidate mechanism for the reserve churn
       * OOM seen in tests #123/#124. Log the first few verbatim. */
      static unsigned unmap_fail_n = 0;
      if (unmap_fail_n++ < 12)
        debugPrintf("[oc125] svcUnmapMemory FAIL dst=%p src=%p run=%zu pages rc=0x%x (fail #%u)\n",
                    dst, src, run, urc, unmap_fail_n);
    }
    i += run;
  }
}
/* Build #125 diagnostic counters: does the game actually release its kept
 * 256 MB blocks via munmap, and does oc_free hand the VA back? */
static size_t   g_oc125_freed_pages  = 0;   /* VA pages returned to free pool */
static size_t   g_oc125_zombie_pages = 0;   /* pages still committed post-free */
static unsigned g_oc125_free_calls   = 0;
static void oc_free_locked(void *addr, size_t len) {
  /* Build #126: a munmap that is a phantom tail trim is a no-op -- the VA
   * was never bitmap-reserved, and clearing bits here could free pages of
   * a newer reservation that reused the slack. */
  if (oc_phantom_match(addr, len, 1)) {
    static unsigned ph_n = 0;
    if (ph_n++ < 12)
      debugPrintf("[oc126] phantom trim no-op %p +%zu KB\n", addr, len >> 10);
    return;
  }
  OcWin *W = oc_win_of(addr);
  if (!W) return;
  size_t first = ((uint8_t *)addr - W->base) / MMAP_PAGE;
  size_t cnt   = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (first + cnt > W->pages) cnt = W->pages - first;
  size_t was_used = 0, was_comm = 0;
  for (size_t i = 0; i < cnt; i++) {
    if (W->used[first + i]) was_used++;
    if (W->committed[first + i]) was_comm++;
  }
  oc_decommit_locked(addr, cnt * MMAP_PAGE);   /* recycle the backing pages */
  for (size_t i = 0; i < cnt; i++)
    if (!W->committed[first + i]) W->used[first + i] = 0;
  size_t still_used = 0, still_comm = 0;
  for (size_t i = 0; i < cnt; i++) {
    if (W->used[first + i]) still_used++;
    if (W->committed[first + i]) still_comm++;
  }
  size_t freed = was_used - still_used;
  g_oc125_freed_pages  += freed;
  g_oc125_zombie_pages += still_comm;
  g_oc125_free_calls++;
  if (still_comm || (g_oc125_free_calls % 16) == 0)
    debugPrintf("[oc125] free #%u %p +%zu MB: was-committed %zu MB, freed %zu MB, "
                "zombie +%zu MB (cum freed %zu MB, cum zombie %zu MB)\n",
                g_oc125_free_calls, addr, (cnt * MMAP_PAGE) >> 20,
                (was_comm * MMAP_PAGE) >> 20, (freed * MMAP_PAGE) >> 20,
                (still_comm * MMAP_PAGE) >> 20,
                (g_oc125_freed_pages * MMAP_PAGE) >> 20,
                (g_oc125_zombie_pages * MMAP_PAGE) >> 20);
}

// caller holds g_mmap_lock
static void mmap_arena_init_locked(void) {
  if (mmap_arena) return;
  uint8_t *base; size_t usable;
  if (g_mmap_arena_base) {
    base   = (uint8_t *)g_mmap_arena_base;   // dedicated, already 256MB-aligned
    usable = g_mmap_arena_size;
  } else {
    // fallback (small heap / applet): memalign a modest arena (< 2GB newlib limit)
    const size_t want = (size_t)768 * 1024 * 1024 + MMAP_BIG_ALIGN;
    uint8_t *raw = memalign(MMAP_PAGE, want);
    if (!raw) fatal_error("mmap arena alloc (%u MB) failed", (unsigned)(want >> 20));
    base   = (uint8_t *)(((uintptr_t)raw + (MMAP_BIG_ALIGN - 1)) & ~(MMAP_BIG_ALIGN - 1));
    usable = (size_t)768 * 1024 * 1024;
  }
  size_t pages  = usable / MMAP_PAGE;
  uint8_t *used = (uint8_t *)calloc(pages, 1);
  if (!used) fatal_error("mmap bitmap alloc failed");
  if (g_overcommit) {
    mmap_committed = (uint8_t *)calloc(pages, 1);
    if (!mmap_committed) fatal_error("mmap commit-bitmap alloc failed");
  }
  mmap_usable = usable; mmap_pages = pages; mmap_used = used;
  mmap_arena  = base;   // publish last (alloc/free key off this)
  debugPrintf("[mmap] arena: %u MB %s at %p\n", (unsigned)(usable >> 20),
              g_overcommit ? "virtual (alias, on-demand commit)" : "256MB-aligned heap-backed",
              base);
}

// caller holds g_mmap_lock.
// Returns the mapped base and writes the number of bytes ACTUALLY reserved
// (in-arena) to *got. For big alignment over-maps (Unity reserves block+align,
// then munmaps the unaligned head/tail), the request is much larger than the
// ~256MB block Unity actually keeps. Normally we reserve the whole over-map and
// let the tail-munmap give it back. But for the LAST 256MB slot the full over-map
// runs past the arena end, so a plain "need contiguous pages" search fails even
// though the kept block fits. In that case we reserve only [slot, arena_end) -- the
// kept block lives there; Unity's tail-munmap targets addresses beyond our arena
// and is a harmless no-op. This removes the transient peak so each block costs
// exactly its 256MB slot (floor(arena/256MB) blocks fit, no 2x headroom needed).
static void *mmap_arena_alloc_locked(size_t len, size_t *got) {
  size_t need = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  if (!need) need = 1;
  if (len >= MMAP_BIG_THRESH) {
    const size_t step = MMAP_BIG_ALIGN / MMAP_PAGE;   // 256MB in pages
    size_t kept = mmap_overmap_kept_pages(need, len); // pages Unity actually keeps (see above)
    // pass 1: full over-map fits within the arena (normal case for all but the last slot)
    for (size_t i = 0; i + need <= mmap_pages; i += step) {
      size_t run = 0;
      while (run < need && !mmap_used[i + run]) run++;
      if (run == need) {
        for (size_t k = 0; k < need; k++) mmap_used[i + k] = 1;
        *got = need * MMAP_PAGE;
        return mmap_arena + i * MMAP_PAGE;
      }
    }
    // pass 2: tail slot -- the over-map would spill past the arena end, but the kept
    // block fits in [slot, arena_end). Reserve only that; the spill is trimmed away.
    for (size_t i = 0; i < mmap_pages; i += step) {
      if (i + need <= mmap_pages) continue;          // handled by pass 1
      size_t avail = mmap_pages - i;
      if (avail < kept) continue;                    // kept block wouldn't fit
      size_t run = 0;
      while (run < avail && !mmap_used[i + run]) run++;
      if (run == avail) {
        for (size_t k = 0; k < avail; k++) mmap_used[i + k] = 1;
        *got = avail * MMAP_PAGE;                     // only the in-arena portion
        return mmap_arena + i * MMAP_PAGE;
      }
    }
  } else {
    for (size_t i = 0; i + need <= mmap_pages; ) {
      size_t run = 0;
      while (run < need && !mmap_used[i + run]) run++;
      if (run == need) {
        for (size_t k = 0; k < need; k++) mmap_used[i + k] = 1;
        *got = need * MMAP_PAGE;
        return mmap_arena + i * MMAP_PAGE;
      }
      i += run + 1;
    }
  }
  *got = 0;
  return NULL;
}

static void mmap_arena_free(void *addr, size_t len) {
  if (!mmap_arena || (uint8_t *)addr < mmap_arena) return;
  size_t off = (uint8_t *)addr - mmap_arena;
  if (off >= mmap_usable) return;
  size_t first = off / MMAP_PAGE;
  size_t cnt   = (len + MMAP_PAGE - 1) / MMAP_PAGE;
  mutexLock(&g_mmap_lock);
  for (size_t k = 0; k < cnt && first + k < mmap_pages; k++)
    mmap_used[first + k] = 0;
  mutexUnlock(&g_mmap_lock);
}

// ---------------------------------------------------------------------------
// Heap-backed fallback maps -- last resort when the OC windows and the arena are
// both full.
//
// 2026-10-14 FIX.  The old version handed each mmap to memalign() and free()d the
// WHOLE block on the first munmap whose address equalled the block base.  That is
// exactly what Baselib_Memory_AllocatePages does to every aligned reservation:
//     p = mmap(size + align - 4KB);   a = AlignUp(p, align);
//     munmap(p, a - p);               <- HEAD trim, addr == base  => whole block freed
//     munmap(a + size, tail);         <- TAIL trim
// Unity kept [a, a+size) while newlib handed the same bytes out again.  In debug.log
// four "fallback" maps (319/319/127/127 MB) all came back as 0x9469d6000, i.e. four
// Unity allocators owned the same region: zeroed TLSF free-list links and vtable
// pointers (the crashes at libunity+0x124400c / +0x1244014 / +0x122b004), and later a
// circular block list the main thread walks forever (libunity+0x122b1fc..0x122b218,
// "no frame progress").
//
// Rules now:
//  * a block stays allocated until EVERY page of it has been munmap'ed (page bitmap);
//  * big maps (>= MMAP_BIG_THRESH) are MMAP_UNITY_ALIGN-aligned, so Baselib has no head
//    to trim;
//  * a munmap'ed tail is handed back to newlib (realloc shrink, in place) so a 256MB
//    reservation only costs what Unity really keeps;
//  * MAP_FIXED on a fallback range is served in place.
// ---------------------------------------------------------------------------
#define MMAP_FALLBACK_MAX 4096
#ifndef MMAP_FB_SHRINK
#define MMAP_FB_SHRINK 0                      /* 2026-10-14: disabled for build #52.
                                                 realloc-shrink moved the block on hardware
                                                 (fatal in build #51 log). Keep the tail
                                                 allocated; wastes some RAM but safe. */
#endif
#define MMAP_FB_SHRINK_MIN ((size_t)1024 * 1024)   /* ignore smaller tails */

typedef struct {
  uint8_t  *ptr;    /* block start == address returned to the caller (memalign result) */
  size_t    len;    /* bytes still owned (page multiple; shrinks when a tail is released) */
  size_t    live;   /* pages not yet munmap'ed */
  uint32_t *dead;   /* 1 bit/page, set = munmap'ed; allocated at the first partial munmap */
} FbBlock;
static FbBlock g_fb[MMAP_FALLBACK_MAX];
static int     g_fb_n = 0;
static size_t  g_fb_bytes = 0;
static size_t  g_fb_peak = 0;
static Mutex   g_fb_lock;

static inline int fb_dead_get(const FbBlock *b, size_t pg) {
  return b->dead && ((b->dead[pg >> 5] >> (pg & 31)) & 1u);
}

// caller holds g_fb_lock. Frees block i (entry is replaced by the last one).
static void fb_release_locked(int i) {
  FbBlock *b = &g_fb[i];
  g_fb_bytes -= b->len;
  free(b->dead);
  free(b->ptr);
  *b = g_fb[--g_fb_n];
}

#if MMAP_FB_SHRINK
// caller holds g_fb_lock. If the block's last pages have all been munmap'ed, give
// them back to newlib. realloc() to a smaller size never moves a chunk in newlib;
// should it ever return another pointer the caller's addresses would be stale, so
// that is fatal instead of silent corruption.
static void fb_shrink_tail_locked(FbBlock *b) {
  size_t total = b->len / MMAP_PAGE, t = 0;
  while (t < total && fb_dead_get(b, total - 1 - t)) t++;
  if (t * MMAP_PAGE < MMAP_FB_SHRINK_MIN || t >= total) return;
  size_t newlen = (total - t) * MMAP_PAGE;
  uint8_t *np = (uint8_t *)realloc(b->ptr, newlen);
  if (!np) return;                                   /* shrink refused: keep the block as is */
  if (np != b->ptr) fatal_error("mmap fallback: realloc(%p, shrink) moved to %p", (void *)b->ptr, (void *)np);
  g_fb_bytes -= b->len - newlen;
  b->len = newlen;
}
#endif

// Account for munmap(addr, length) on any fallback block it touches. Returns 1 if the
// range touched a fallback block (the part inside it is consumed), else 0.
static int fb_munmap(void *addr, size_t length) {
  uintptr_t a0 = (uintptr_t)addr, a1 = a0 + length;
  if (a1 < a0) a1 = UINTPTR_MAX;
  int hit = 0;
  mutexLock(&g_fb_lock);
  for (int i = 0; i < g_fb_n; ) {
    FbBlock *b = &g_fb[i];
    uintptr_t bs = (uintptr_t)b->ptr, be = bs + b->len;
    if (a1 <= bs || a0 >= be) { i++; continue; }
    hit = 1;
    uintptr_t s = a0 > bs ? a0 : bs, e = a1 < be ? a1 : be;
    size_t total = b->len / MMAP_PAGE;
    size_t p0 = (s - bs) / MMAP_PAGE;
    size_t p1 = (e - bs + MMAP_PAGE - 1) / MMAP_PAGE;
    if (p1 > total) p1 = total;
    if (p0 == 0 && p1 >= total) {                    /* the whole block is gone */
      fb_release_locked(i);
      continue;                                      /* slot i now holds another block */
    }
    if (!b->dead) {
      b->dead = (uint32_t *)calloc((total + 31) / 32, sizeof(uint32_t));
      if (!b->dead) {                                /* cannot track it: leak, never free early */
        debugPrintf("[mmap] fb: no memory for page map of %p; partial munmap ignored\n", (void *)b->ptr);
        i++; continue;
      }
    }
    for (size_t pg = p0; pg < p1; pg++) {
      if (!fb_dead_get(b, pg)) { b->dead[pg >> 5] |= 1u << (pg & 31); b->live--; }
    }
    static unsigned part_n = 0;
    if (part_n < 24)
      debugPrintf("[mmap] fb: munmap %p +%u KB inside block %p (%u KB): %zu/%zu pages live\n",
                  addr, (unsigned)(length >> 10), (void *)b->ptr, (unsigned)(b->len >> 10), b->live, total);
    part_n++;
    if (b->live == 0) { fb_release_locked(i); continue; }
#if MMAP_FB_SHRINK
    fb_shrink_tail_locked(b);
#endif
    i++;
  }
  mutexUnlock(&g_fb_lock);
  return hit;
}

// MAP_FIXED|MAP_ANONYMOUS inside a fallback block: re-map in place (zero-filled when
// readable), as bionic would. Returns 1 if the range was inside a block.
static int fb_fixed(void *addr, size_t length, int prot) {
  uintptr_t a0 = (uintptr_t)addr, a1 = a0 + length;
  int hit = 0;
  mutexLock(&g_fb_lock);
  for (int i = 0; i < g_fb_n; i++) {
    FbBlock *b = &g_fb[i];
    uintptr_t bs = (uintptr_t)b->ptr, be = bs + b->len;
    if (a0 < bs || a1 > be) continue;               /* must lie completely inside */
    hit = 1;
    size_t p0 = (a0 - bs) / MMAP_PAGE, p1 = (a1 - bs + MMAP_PAGE - 1) / MMAP_PAGE;
    for (size_t pg = p0; pg < p1; pg++)
      if (fb_dead_get(b, pg)) { b->dead[pg >> 5] &= ~(1u << (pg & 31)); b->live++; }
    break;
  }
  mutexUnlock(&g_fb_lock);
  if (hit && prot != BIONIC_PROT_NONE) memset(addr, 0, length);
  return hit;
}

/* Build #129: phantom tails for the heap-backed fallback, mirroring the OC
 * phantom table (#126). Tests #128 (two boots) died at the fatal edge of this
 * fallback: Unity's ~2.8 GB of PROT_NONE reserves exceed the lazy VA (stack
 * windows + 192 MB arena), the spillover reserves were memalign'ed at FULL
 * length (319 MB of real heap each, 4 blocks = 1279 MB), the heap ran dry,
 * and the next reserve returned NULL into a path Unity dereferences
 * (Loading.PreloadManager, libunity+0xf8c8a0 -- same site as test #124).
 * An over-map reserve served here now allocates only the pages Unity keeps
 * (256 MB); the 64 MB alignment slack becomes a phantom tail, exactly as in
 * the OC path. The tail trim, when it arrives, is swallowed by
 * munmap_fake/mmap_fake via fb_phantom_match and can never touch a later
 * allocation that reused the slack VA. A full table leaves the tail
 * unrecorded; every consumer path still guards by range, so an unrecorded
 * trim degrades to a VA no-op. */
#define FB_PHANTOM_MAX 32
static struct { uint8_t *base; size_t len; } fb_phantom_tab[FB_PHANTOM_MAX];
static int fb_phantom_add(uint8_t *base, size_t len) {
  for (int i = 0; i < FB_PHANTOM_MAX; i++)
    if (!fb_phantom_tab[i].len) {
      fb_phantom_tab[i].base = base; fb_phantom_tab[i].len = len;
      debugPrintf("[fb129] phantom tail %p +%zu MB (slot %d)\n",
                  (void *)base, len >> 20, i);
      return 1;
    }
  return 0;
}
/* 1 if [addr, addr+len) is (the bulk of) a live phantom tail; same matching
 * rules as oc_phantom_match (the trim starts at most one page early and
 * ends at most at the span end; consume drops the entry at the span end). */
static int fb_phantom_match(void *addr, size_t len, int consume) {
  uint8_t *a = (uint8_t *)addr, *e = a + len;
  for (int i = 0; i < FB_PHANTOM_MAX; i++) {
    if (!fb_phantom_tab[i].len) continue;
    uint8_t *pb = fb_phantom_tab[i].base, *pe = pb + fb_phantom_tab[i].len;
    if (a >= pb - MMAP_PAGE && a < pe && e <= pe) {
      if (consume && e >= pe - MMAP_PAGE) fb_phantom_tab[i].len = 0;
      return 1;
    }
  }
  return 0;
}

static void *mmap_fallback(size_t length, int prot, int flags, int fd, long offset) {
  const size_t len = (length + MMAP_PAGE - 1) & ~(size_t)(MMAP_PAGE - 1);
  /* Build #129: kept-only allocation for Baselib over-map reserves (see the
   * phantom table above). PROT_NONE anon reserves only -- RW maps and file
   * maps may use their full length and are unchanged. */
  size_t alloc = len;
  if (prot == BIONIC_PROT_NONE && (flags & BIONIC_MAP_ANONYMOUS) && fd < 0) {
    size_t needp = (length + MMAP_PAGE - 1) / MMAP_PAGE;
    size_t keptp = mmap_overmap_kept_pages(needp, length);
    if (keptp < needp) alloc = keptp * MMAP_PAGE;
  }
  void *q = NULL;
  int aligned = 0;
  if (alloc >= MMAP_BIG_THRESH) {       /* Baselib aligns these -> hand out an aligned base */
    q = memalign(MMAP_UNITY_ALIGN, alloc);
    aligned = (q != NULL);
  }
  if (!q) q = memalign(MMAP_PAGE, alloc);
  if (!q) return NULL;
  if (alloc < len) {
    if (fb_phantom_add((uint8_t *)q + alloc, len - alloc))
      debugPrintf("[fb129] kept-only fallback: %u KB request -> %u KB allocated (+%u MB phantom)\n",
                  (unsigned)(length >> 10), (unsigned)(alloc >> 10),
                  (unsigned)((len - alloc) >> 20));
    else
      debugPrintf("[fb129] phantom table full: %p tail +%zu MB unrecorded\n",
                  q, (len - alloc) >> 20);
  }
  long got = 0;
  if (flags & BIONIC_MAP_ANONYMOUS) {
    /* 2026-10-12: DIAG sentinel REMOVED. The 0xAB fill was causing Unity to
     * treat uninitialized structs as initialized (non-NULL garbage pointers).
     * Anonymous mmap is already zero-filled by the kernel; keep it zero. */
    memset(q, 0x00, alloc);
  } else {
    if (fd >= 0) {
      long cur = lseek(fd, 0, SEEK_CUR);
      if (lseek(fd, offset, SEEK_SET) >= 0)
        while ((size_t)got < length) { long r = read(fd, (char *)q + got, length - got); if (r <= 0) break; got += r; }
      if (cur >= 0) lseek(fd, cur, SEEK_SET);
    }
    if ((size_t)got < len) memset((char *)q + got, 0, len - got);
  }
  mutexLock(&g_fb_lock);
  int tracked = 0;
  if (g_fb_n < MMAP_FALLBACK_MAX) {
    FbBlock *b = &g_fb[g_fb_n++];
    b->ptr = (uint8_t *)q; b->len = alloc; b->live = alloc / MMAP_PAGE; b->dead = NULL;
    g_fb_bytes += alloc;
    if (g_fb_bytes > g_fb_peak) g_fb_peak = g_fb_bytes;
    tracked = 1;
  }
  const size_t total = g_fb_bytes;
  const int nblk = g_fb_n;
  mutexUnlock(&g_fb_lock);
  if (!tracked)
    debugPrintf("[mmap] fb: block table full (%d) -- %p will never be released\n", MMAP_FALLBACK_MAX, q);
  debugPrintf("[mmap] fallback %u KB -> %p  anon=%d fd=%d off=0x%lx got=%ld aligned=%d (blocks %d, total %u MB)\n",
              (unsigned)(length >> 10), q, !!(flags & BIONIC_MAP_ANONYMOUS), fd, offset, got, aligned,
              nblk, (unsigned)(total >> 20));
  return q;
}

// ---------------------------------------------------------------------------
// Address-space ledger (diagnostic only, no behaviour change).
// Mirrors what Unity believes is mapped (maps >= 1 MB). A new map that overlaps a
// live one is the signature of the aliasing bug fixed above, whichever allocator (OC
// window, arena or fallback) handed it out -- it is reported once per occurrence in
// debug.log as "[mmap] !!! OVERLAP".
// ---------------------------------------------------------------------------
#ifndef MMAP_LEDGER
#define MMAP_LEDGER 1
#endif
#define MMAP_LEDGER_MIN ((size_t)1024 * 1024)
#define MMAP_LEDGER_MAX 512
typedef struct { uintptr_t s, e; const char *src; } LedRange;
static LedRange g_led[MMAP_LEDGER_MAX];
static int      g_led_n;
static unsigned g_led_overlaps, g_led_dropped;
static Mutex    g_led_lock;

static void ledger_add(const void *p, size_t len, const char *src) {
#if MMAP_LEDGER
  if (len < MMAP_LEDGER_MIN) return;
  uintptr_t s = (uintptr_t)p, e = s + len;
  mutexLock(&g_led_lock);
  for (int i = 0; i < g_led_n; i++) {
    if (s < g_led[i].e && e > g_led[i].s) {
      g_led_overlaps++;
      if (g_led_overlaps <= 16)
        debugPrintf("[mmap] !!! OVERLAP: new %s [%p,%p) intersects live %s [%p,%p)\n",
                    src, (void *)s, (void *)e, g_led[i].src, (void *)g_led[i].s, (void *)g_led[i].e);
    }
  }
  if (g_led_n < MMAP_LEDGER_MAX) { g_led[g_led_n].s = s; g_led[g_led_n].e = e; g_led[g_led_n].src = src; g_led_n++; }
  else g_led_dropped++;
  mutexUnlock(&g_led_lock);
#else
  (void)p; (void)len; (void)src;
#endif
}

static void ledger_del(const void *p, size_t len) {
#if MMAP_LEDGER
  uintptr_t s = (uintptr_t)p, e = s + len;
  if (e < s) e = UINTPTR_MAX;
  mutexLock(&g_led_lock);
  for (int i = 0; i < g_led_n; ) {
    LedRange *r = &g_led[i];
    if (e <= r->s || s >= r->e) { i++; continue; }
    if (s <= r->s && e >= r->e) { *r = g_led[--g_led_n]; continue; }      /* fully covered */
    if (s <= r->s) { r->s = e; i++; continue; }                            /* head cut */
    if (e >= r->e) { r->e = s; i++; continue; }                            /* tail cut */
    if (g_led_n < MMAP_LEDGER_MAX) {                                       /* hole: split */
      g_led[g_led_n].s = e; g_led[g_led_n].e = r->e; g_led[g_led_n].src = r->src; g_led_n++;
    } else g_led_dropped++;
    r->e = s; i++;
  }
  mutexUnlock(&g_led_lock);
#else
  (void)p; (void)len;
#endif
}

// One-line memory summary for the watchdog dump / boot log. Declare it in libc_shim.h
// (`void mmap_dump_stats(void);`) and call it from the [wd] stall dump.
void mmap_dump_stats(void) {
  size_t oc_used = 0, oc_comm = 0, oc_tot = 0, ar_used = 0, ar_tot = 0;
  int ok = mutexTryLock(&g_mmap_lock);
  if (ok) {
    for (int w = 0; w < oc_nwin; w++) {
      oc_tot += oc_win[w].pages;
      for (size_t i = 0; i < oc_win[w].pages; i++) { oc_used += oc_win[w].used[i]; oc_comm += oc_win[w].committed[i]; }
    }
    if (mmap_used) { ar_tot = mmap_pages; for (size_t i = 0; i < mmap_pages; i++) ar_used += mmap_used[i]; }
    mutexUnlock(&g_mmap_lock);
  }
  mutexLock(&g_fb_lock);
  int fbn = g_fb_n; size_t fbb = g_fb_bytes, fbp = g_fb_peak;
  mutexUnlock(&g_fb_lock);
  struct mallinfo mi = mallinfo();
  debugPrintf("[mmapstat] OC reserved %zu/%zu MB committed %zu MB%s | arena %zu/%zu MB | fallback %d blocks %zu MB (peak %zu MB)"
              " | ledger %d ranges, %u overlaps | newlib used %u MB free %u MB\n",
              (oc_used * MMAP_PAGE) >> 20, (oc_tot * MMAP_PAGE) >> 20, (oc_comm * MMAP_PAGE) >> 20, ok ? "" : " (busy)",
              (ar_used * MMAP_PAGE) >> 20, (ar_tot * MMAP_PAGE) >> 20, fbn, fbb >> 20, fbp >> 20,
              g_led_n, g_led_overlaps, (unsigned)((unsigned)mi.uordblks >> 20), (unsigned)((unsigned)mi.fordblks >> 20));
}

/* Build #117: forward decls -- the wb registry lives by munmap_fake below,
 * but mmap_fake (above it in this file) registers writable file maps. */
static void wb_register(void *addr, size_t len, int fd, long off);
static void wb_flush(void *addr, size_t length);

void *mmap_fake(void *addr, size_t length, int prot, int flags, int fd, long offset) {
  (void)addr; (void)prot;
  if (length == 0) length = 1;

  if ((flags & BIONIC_MAP_FIXED) && addr && (flags & BIONIC_MAP_ANONYMOUS)) {
    static unsigned fixed_n = 0;
    /* Build #126: MAP_FIXED inside a phantom tail: nothing is reserved
     * there; never commit/memset over a possible reuser of the slack. */
    if (oc_contains(addr) && oc_phantom_match(addr, length, 0)) return addr;
    /* Build #129: same for a heap-backed fallback phantom tail. */
    if (fb_phantom_match(addr, length, 0)) return addr;
    if (oc_contains(addr)) {
      mutexLock(&g_mmap_lock);
      int oc_failed = 0;
      if (prot != BIONIC_PROT_NONE) oc_failed = oc_commit_locked(addr, length);
      else                          oc_decommit_locked(addr, length);  /* recycle */
      mutexUnlock(&g_mmap_lock);
      if (oc_failed) {
        /* Build #130: never present an unbacked FIXED range as mapped --
         * the memset below would fault inside the wrapper, and the caller
         * would write into unmapped VA. Fail like a real mmap instead. */
        debugPrintf("[oc130] MAP_FIXED commit failed for %d pages @ %p -- returning MAP_FAILED\n",
                    oc_failed, addr);
        errno = ENOMEM; return (void *)-1;
      }
      if (prot != BIONIC_PROT_NONE)
        memset(addr, 0, length);          /* FIXED anon: whole range reads zero */
      if (fixed_n < 3)
        debugPrintf("[mmap] MAP_FIXED %s %u KB @ %p (OC)\n",
                    prot == BIONIC_PROT_NONE ? "decommit" : "commit",
                    (unsigned)(length >> 10), addr);
      fixed_n++;
      return addr;                        /* bionic: FIXED returns addr */
    }
    if (g_mmap_arena_base &&
        (uint8_t *)addr >= (uint8_t *)g_mmap_arena_base &&
        (uint8_t *)addr + length <= (uint8_t *)g_mmap_arena_base + g_mmap_arena_size) {
      if (prot != BIONIC_PROT_NONE) memset(addr, 0, length);   /* arena is committed */
      if (fixed_n < 3)
        debugPrintf("[mmap] MAP_FIXED %u KB @ %p (arena) -> in place\n", (unsigned)(length >> 10), addr);
      fixed_n++;
      return addr;
    }
    if (fb_fixed(addr, length, prot)) {      /* heap-backed fallback block: in place */
      if (fixed_n < 3)
        debugPrintf("[mmap] MAP_FIXED %u KB @ %p (fallback) -> in place\n", (unsigned)(length >> 10), addr);
      fixed_n++;
      return addr;
    }
    debugPrintf("[mmap] MAP_FIXED %u KB @ %p prot=0x%x UNOWNED -> legacy path\n",
                (unsigned)(length >> 10), addr, prot);
  }

  // Big anonymous PROT_NONE reservations -> stack-region OC arena: cheap address
  // space now, physical aliased in on the later mprotect(RW). On a full window we
  // fall through to the heap-backed arena below (no behaviour change there).
  if (oc_nwin && length >= MMAP_BIG_THRESH &&
      (flags & BIONIC_MAP_ANONYMOUS) && prot == BIONIC_PROT_NONE) {
    size_t ocres = 0;
    mutexLock(&g_mmap_lock);
    void *op = oc_alloc_locked(length, &ocres);
    mutexUnlock(&g_mmap_lock);
    if (op) {
      debugPrintf("[mmap] %u MB (prot=0x0 anon=1) -> %p  [OC reserve %u MB]\n",
                  (unsigned)(length >> 20), op, (unsigned)(ocres >> 20));
      ledger_add(op, ocres < length ? ocres : length, "oc");
      return op;   // reserved-only; committed lazily via mprotect_fake
    }
    debugPrintf("[mmap] OC window full for %u MB -> heap-backed arena\n",
                (unsigned)(length >> 20));
  }

  size_t reserved = 0;
  mutexLock(&g_mmap_lock);
  mmap_arena_init_locked();
  void *p = mmap_arena_alloc_locked(length, &reserved);
  mutexUnlock(&g_mmap_lock);
  if (length >= MMAP_BIG_THRESH)
    debugPrintf("[mmap] %u MB (prot=0x%x anon=%d) -> %p  [reserved %u MB]\n",
                (unsigned)(length >> 20), prot, !!(flags & BIONIC_MAP_ANONYMOUS), p,
                (unsigned)(reserved >> 20));
  /* A file-backed map must be contiguous and fully readable. When the arena can
   * only give a tail-overflow reservation (reserved < length) we'd read just
   * `fill` bytes and leave the tail unfilled -- silently truncating the file in
   * RAM. For global-metadata.dat that nulls out System.Object (Class::Init NULL).
   * Hand any short-reserved file map to newlib, which backs the whole length. */
  if (p && !(flags & BIONIC_MAP_ANONYMOUS) && fd >= 0 && reserved < length) {
    mutexLock(&g_mmap_lock);
    mmap_arena_free(p, length);
    mutexUnlock(&g_mmap_lock);
    debugPrintf("[mmap] file fd=%d len=%zu: arena tail-overflow (reserved=%zu) -> newlib\n",
                fd, length, reserved);
    p = NULL;
  }
  if (!p) {
    // Arena exhausted (Unity's 9 pools fill it). Route the request to newlib's free
    // heap regardless of size -- il2cpp's resource-extraction maps can exceed 64MB,
    // and rejecting them is what NULL-derefs the engine. Only a genuinely huge map
    // (> newlib free) will fail, and we log that distinctly.
    void *q = mmap_fallback(length, prot, flags, fd, offset);
    if (q) {
      ledger_add(q, length, "fallback");
      if (!(flags & BIONIC_MAP_ANONYMOUS) && fd >= 0 && (prot & BIONIC_PROT_WRITE))
        wb_register(q, length, fd, offset);
      return q;
    }
    debugPrintf("[mmap] arena FULL and newlib fallback FAILED for %u MB (out of RAM)\n",
                (unsigned)(length >> 20));
    errno = ENOMEM; return (void *)-1;
  }

  // Never touch beyond what we actually reserved in-arena (tail over-maps reserve
  // less than the requested length; the spill lives past the arena and is trimmed).
  size_t fill = length < reserved ? length : reserved;
  ledger_add(p, fill, "arena");

  if (g_overcommit) {
    // PROT_NONE reservation: address space only, no physical -- the whole point.
    // The engine commits the sub-ranges it uses later via mprotect(RW).
    if (prot == BIONIC_PROT_NONE) return p;
    // Otherwise commit now (anon RW, file maps): svcMapPhysicalMemory zero-fills,
    // so anon needs no memset; file maps read their contents over the zeros.
    arena_commit_range(p, fill);
    if (!(flags & BIONIC_MAP_ANONYMOUS) && fd >= 0) {
      long got = 0, cur = lseek(fd, 0, SEEK_CUR);
      if (lseek(fd, offset, SEEK_SET) >= 0)
        while ((size_t)got < fill) { long r = read(fd, (char *)p + got, fill - got); if (r <= 0) break; got += r; }
      if (cur >= 0) lseek(fd, cur, SEEK_SET);
      if (prot & BIONIC_PROT_WRITE) wb_register(p, fill, fd, offset);
    }
    return p;
  }

  if (flags & BIONIC_MAP_ANONYMOUS) {
    memset(p, 0, fill);   // anonymous memory must read back as zero
  } else {
    // File-backed mapping: pull [offset, offset+fill) into RAM (no real mmap).
    long got = 0;
    if (fd >= 0) {
      long cur = lseek(fd, 0, SEEK_CUR);
      if (lseek(fd, offset, SEEK_SET) >= 0) {
        while ((size_t)got < fill) {
          long r = read(fd, (char *)p + got, fill - (size_t)got);
          if (r <= 0) break;
          got += r;
        }
      }
      if (cur >= 0) lseek(fd, cur, SEEK_SET);
    }
    if ((size_t)got < fill) memset((char *)p + got, 0, fill - (size_t)got);
    if (fd >= 0)
      debugPrintf("[mmap] file map fd=%d len=%zu reserved=%zu fill=%zu got=%ld%s\n",
                  fd, length, reserved, fill, got,
                  ((size_t)got < length) ? "  *** TRUNCATED ***" : "");
    if (fd >= 0 && (prot & BIONIC_PROT_WRITE)) wb_register(p, fill, fd, offset);
  }
  return p;
}

/* Build #117: writable file-backed mmap write-back. Our mmap is a RAM copy:
 * file bytes are read in at mmap time and writes to the mapping never reach
 * the file, so files produced through a writable mapping (il2cpp's extracted
 * global-metadata.dat) land truncated on disk -- the reason main.c used to
 * force a full re-extract every boot. Track writable file maps and write
 * their contents back on munmap so the extracted files persist intact. */
#define WB_MAX 64
typedef struct { void *addr; size_t len; int fd; long off; int duped; } WbMap;
static WbMap g_wb[WB_MAX];
static int g_wb_n = 0;

static void wb_register(void *addr, size_t len, int fd, long off) {
  int d = dup(fd);
  mutexLock(&g_mmap_lock);
  if (g_wb_n < WB_MAX) {
    WbMap *w = &g_wb[g_wb_n++];
    w->addr = addr; w->len = len; w->fd = (d >= 0 ? d : fd);
    w->off = off; w->duped = (d >= 0);
    debugPrintf("[mmap] wb-track %p len=%zu fd=%d off=%ld\n", addr, len, w->fd, off);
  } else {
    if (d >= 0) close(d);
    debugPrintf("[mmap] wb table FULL: %p not tracked (no write-back)\n", addr);
  }
  mutexUnlock(&g_mmap_lock);
}

static void wb_flush(void *addr, size_t length) {
  for (;;) {
    WbMap w; int found = 0;
    mutexLock(&g_mmap_lock);
    for (int i = 0; i < g_wb_n; i++) {
      uint8_t *a0 = (uint8_t *)g_wb[i].addr, *a1 = a0 + g_wb[i].len;
      uint8_t *b0 = (uint8_t *)addr,        *b1 = b0 + length;
      if (b0 < a1 && b1 > a0) { w = g_wb[i]; found = 1; break; }
    }
    mutexUnlock(&g_mmap_lock);
    if (!found) return;
    uint8_t *rs = (uint8_t *)w.addr, *re = rs + w.len;
    uint8_t *us = (uint8_t *)addr,   *ue = us + length;
    uint8_t *s = us > rs ? us : rs;
    uint8_t *e = ue < re ? ue : re;
    long foff = w.off + (long)(s - rs);
    size_t n = (size_t)(e - s), done = 0;
    if (lseek(w.fd, foff, SEEK_SET) >= 0)
      while (done < n) { long r = write(w.fd, s + done, n - done); if (r <= 0) break; done += (size_t)r; }
    debugPrintf("[mmap] wb-flush %p +%zu -> fd=%d off=%ld wrote=%zu%s\n",
                (void *)s, n, w.fd, foff, done, done < n ? "  *** SHORT ***" : "");
    if (us <= rs && ue >= re) {
      /* fully unmapped: drop the record */
      mutexLock(&g_mmap_lock);
      for (int i = 0; i < g_wb_n; i++)
        if (g_wb[i].addr == w.addr && g_wb[i].len == w.len) {
          if (g_wb[i].duped) close(g_wb[i].fd);
          g_wb[i] = g_wb[--g_wb_n];
          break;
        }
      mutexUnlock(&g_mmap_lock);
    } else {
      return;  /* partial munmap: keep the record for the rest */
    }
  }
}

int munmap_fake(void *addr, size_t length) {
  /* Build #129: a fallback phantom-tail trim is a no-op -- the VA was never
   * allocated, and letting it reach the per-block accounting could free
   * pages of a newer allocation that reused the slack in the meantime. */
  if (fb_phantom_match(addr, length, 1)) return 0;
  wb_flush(addr, length);   /* Build #117: persist writable file maps first */
  /* Heap-backed fallback block(s): per-page accounting. A HEAD/TAIL trim of an aligned
   * reservation (Baselib_Memory_AllocatePages) must NOT free the block -- the middle is
   * still live (see the FIX note above mmap_fallback). */
  ledger_del(addr, length);
  if (fb_munmap(addr, length)) return 0;
  if (oc_contains(addr)) {                   // stack-region OC reservation
    mutexLock(&g_mmap_lock);
    oc_free_locked(addr, length);
    mutexUnlock(&g_mmap_lock);
    return 0;
  }
  arena_decommit_range(addr, length);       // reclaim physical (overcommit only)
  mmap_arena_free(addr, length);            // unreserve address space
  return 0;
}

// In overcommit mode mprotect drives commit/decommit: RW/R commits physical at
// the alias address, PROT_NONE decommits it (safe -- reuse re-mprotects to RW).
// In heap-backed mode the arena is always RW so this is a no-op.
int mprotect_fake(void *addr, size_t len, int prot) {
  /* Diagnostic (fires even heap-backed): measure Unity's commit pattern so we can
   * confirm it commits PROT_NONE reservations via mprotect(RW) and size the
   * overcommit commit-pool. Tracks cumulative RW-commit vs PROT_NONE-decommit
   * bytes that fall inside the mmap arena (= Unity's live committed footprint). */
  {
    static size_t rw_b = 0, none_b = 0;
    static unsigned rw_n = 0, none_n = 0, oth_n = 0;
    int in_arena = g_mmap_arena_base &&
                   (uint8_t *)addr >= (uint8_t *)g_mmap_arena_base &&
                   (uint8_t *)addr <  (uint8_t *)g_mmap_arena_base + g_mmap_arena_size;
    if (prot == BIONIC_PROT_NONE)       { none_n++; if (in_arena) none_b += len; }
    else if (prot & BIONIC_PROT_WRITE)  { rw_n++;   if (in_arena) rw_b   += len; }
    else                                  oth_n++;
    if (TRACE_MPROT && (len >= 4u * 1024 * 1024 || ((rw_n + none_n) & 0x7F) == 0))
      debugPrintf("[mprot] addr=%p len=%zuKB prot=0x%x arena=%d | RW %u/%zuMB NONE %u/%zuMB oth %u  net=%zdMB\n",
                  addr, len >> 10, prot, in_arena, rw_n, rw_b >> 20, none_n, none_b >> 20, oth_n,
                  (ssize_t)(rw_b - none_b) >> 20);
  }
  /* Build #126: protection changes inside a phantom tail are no-ops --
   * nothing is bitmap-reserved there, and committing would alias pool
   * pages over whatever reservation later reused the slack. */
  if (oc_contains(addr) && oc_phantom_match(addr, len, 0)) return 0;
  if (oc_contains(addr)) {
    // OC reservation being committed/decommitted. PROT_NONE releases the backing
    // pool page for reuse (see oc_decommit_locked); RW commits it.
    {
      mutexLock(&g_mmap_lock);
      if (prot == BIONIC_PROT_NONE) oc_decommit_locked(addr, len);   /* recycle */
      else if (oc_commit_locked(addr, len)) {
        mutexUnlock(&g_mmap_lock);
        /* Build #130: a commit that could not be backed must fail the
         * mprotect (Linux semantics) so the allocator's own error path
         * engages, instead of the previous silent success that left the
         * range unmapped and crashed on first touch (test #129). */
        errno = ENOMEM;
        return -1;
      }
      mutexUnlock(&g_mmap_lock);
    }
    return 0;
  }
  if (!g_overcommit) return 0;
  if (prot == BIONIC_PROT_NONE) arena_decommit_range(addr, len);
  else                          arena_commit_range(addr, len);
  return 0;
}
// madvise(MADV_DONTNEED): overcommit zeroes-but-keeps (see arena_dontneed_range);
// heap-backed leaves pages as-is (always RW-backed).
int madvise_fake(void *addr, size_t len, int advice) {
  if (g_overcommit && advice == BIONIC_MADV_DONTNEED) arena_dontneed_range(addr, len);
  return 0;
}

// ---------------------------------------------------------------------------
// filesystem odds and ends
// ---------------------------------------------------------------------------

char *realpath_fake(const char *path, char *resolved) {
  if (!path) return NULL;          /* POSIX: realpath(NULL,..) is an error, not a crash */
  if (!resolved) resolved = malloc(0x1000);
  strcpy(resolved, path);
  return resolved;
}
int strerror_r_fake(int err, char *buf, size_t len) { snprintf(buf, len, "%s", strerror(err)); return 0; }
int statvfs_fake(const char *path, void *buf) { (void)path; memset(buf, 0, 0x70); return 0; }
int statfs_fake(const char *path, void *buf) { (void)path; memset(buf, 0, 0x78); return 0; }

// Synthetic /proc and /sys files. Unity reads /proc/meminfo (MemTotal) to size
// its allocator reservations and /proc/cpuinfo + /sys cpu range to count cores
// for the job system. We report ~1 GB (NOT the real ~3 GB) so the engine's big
// 256MB-block dynamic-heap reservations stay within our mmap arena -- the arena
// is the real backing and has headroom, but Unity must not try to reserve 3 GB
// of address space up front. 3 cores (homebrew gets 0-2).
static const char *synthetic_proc(const char *path) {
  if (!path) return NULL;
  if (!strcmp(path, "/proc/meminfo"))
    return "MemTotal:        524288 kB\n"
           "MemFree:         393216 kB\n"
           "MemAvailable:    393216 kB\n"
           "Buffers:              0 kB\n"
           "Cached:               0 kB\n"
           "SwapTotal:            0 kB\n"
           "SwapFree:             0 kB\n";
  if (!strcmp(path, "/proc/cpuinfo"))
    return "processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\n"
           "Features\t: fp asimd aes pmull sha1 sha2 crc32\n"
           "CPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x1\n"
           "CPU part\t: 0xd07\nCPU revision\t: 1\n";
  if (strstr(path, "cpu_capacity")) return "1024\n";
  if (strstr(path, "cpuinfo_max_freq") || strstr(path, "scaling_max_freq")) return "1785000\n";
  if (strstr(path, "cpuinfo_min_freq") || strstr(path, "scaling_min_freq")) return "1020000\n";
  if (strstr(path, "/cpu/possible") || strstr(path, "/cpu/present") || strstr(path, "/cpu/online"))
    return "0-2\n";
  if (!strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 5)) return ""; // empty for the rest
  return NULL;
}

// ---------------------------------------------------------------------------
// Locked open/close. newlib's FILE table is shared process-wide, and the engine
// opens and closes bundle files from several worker threads at once. Anything
// ELSE in the port that touches that table -- nx_pointer writing pointer.cfg
// from the render thread, for one -- has to serialise against them, so both
// sides funnel through this one mutex. fopen/fclose are SD round-trips measured
// in milliseconds, so the lock costs nothing measurable.
//
// Exported (see the declarations in android_native_unity.c) for non-engine
// callers; fopen_fake/fclose_fake below are the engine's own entry points.
// ---------------------------------------------------------------------------
static Mutex g_stdio_lock;   // libnx Mutex: 0 == unlocked, no init needed

FILE *nx_fopen_locked(const char *path, const char *mode) {
  mutexLock(&g_stdio_lock);
  FILE *f = fopen(path, mode);
  mutexUnlock(&g_stdio_lock);
  return f;
}

int nx_fclose_locked(FILE *f) {
  mutexLock(&g_stdio_lock);
  int r = fclose(f);
  mutexUnlock(&g_stdio_lock);
  return r;
}

static FILE *fmemopen_locked(void *buf, size_t n, const char *mode) {
  mutexLock(&g_stdio_lock);
  FILE *f = fmemopen(buf, n, mode);
  mutexUnlock(&g_stdio_lock);
  return f;
}

// a buffered fopen for the big .mvgl archives: the engine issues many small
// reads/seeks and the fsdev round-trips dominate without a large buffer.
FILE *fopen_fake(const char *path, const char *mode) {
  path = nx_fonts_resolve(path);   /* Switch system fonts as /system/fonts */
  path = casetest_redirect(path);
  const char *synth = synthetic_proc(path);
  if (synth) {
    size_t n = strlen(synth);
    return fmemopen_locked((void *)strdup(synth), n ? n : 1, "r");
  }
  const int writing = strpbrk(mode, "wa+") != NULL;
  if (!writing) {
    void *data = NULL; size_t size = 0;
    if (asset_pack_read_all_path(path, &data, &size)) {
      FILE *pf = fmemopen_locked(data, size ? size : 1, "r");
      if (pf) { debugPrintf("[io] fopen(%s,%s) -> %p [pack]\n", path, mode, (void *)pf); return pf; }
      free(data);
    }
  }
  FILE *f = nx_fopen_locked(path, mode);
  if (!f && writing) {            // save file: create the subdir and retry
    mkdir_parents(path);
    f = nx_fopen_locked(path, mode);
  }
  if (!f && !writing && strchr(mode, 'r')) {
    char alt[320];
    if (basename_fallback(path, alt, sizeof(alt)))
      f = nx_fopen_locked(alt, mode);
  }
  if (!f)
    return NULL;
  debugPrintf("[io] fopen(%s,%s) -> %p\n", path, mode, (void *)f);
  if (strchr(mode, 'r')) {
    const char *ext = strrchr(path, '.');
    if (ext && strcasecmp(ext, ".mvgl") == 0)
      setvbuf(f, NULL, _IOFBF, 256 * 1024);
  }
  return f;
}

// ---------------------------------------------------------------------------
// stdio over the fake bionic __sF (stdin/stdout/stderr). libc++_shared wires
// std::cout/cerr/cin to &__sF[1]/[2]/[0]; these wrappers absorb writes to those
// fake FILEs and forward everything else to newlib.
// ---------------------------------------------------------------------------

uint8_t fake_sF[3][0x100]; // referenced by imports.c (__sF / std{in,out,err})

static int is_fake_file(const void *f) {
  const uint8_t *p = f;
  const uint8_t *base = (const uint8_t *)fake_sF;
  return p >= base && p < base + sizeof(fake_sF);
}

size_t fwrite_fake(const void *ptr, size_t size, size_t n, FILE *f) {
  if (is_fake_file(f)) {
#if DEBUG_LOG
    static char buf[0x400];
    const size_t total = size * n < sizeof(buf) - 1 ? size * n : sizeof(buf) - 1;
    memcpy(buf, ptr, total); buf[total] = '\0';
    debugPrintf("stdio: %s", buf);
#endif
    return n;
  }
  return fwrite(ptr, size, n, f);
}
size_t fread_fake(void *ptr, size_t size, size_t n, FILE *f) {
  if (is_fake_file(f)) return 0;
  return fread(ptr, size, n, f);
}
int fputc_fake(int c, FILE *f) { if (is_fake_file(f)) return c; return fputc(c, f); }
int fputs_fake(const char *s, FILE *f) { if (is_fake_file(f)) { debugPrintf("stdio: %s", s); return 0; } return fputs(s, f); }
int fflush_fake(FILE *f) { if (is_fake_file(f) || f == NULL) return 0; return fflush(f); }
int fclose_fake(FILE *f) { if (is_fake_file(f)) return 0; return nx_fclose_locked(f); }
int ferror_fake(FILE *f) { if (is_fake_file(f)) return 0; return ferror(f); }
int feof_fake(FILE *f) { if (is_fake_file(f)) return 1; return feof(f); }
int fileno_fake(FILE *f) { if (is_fake_file(f)) return ((const uint8_t *)f - &fake_sF[0][0]) / 0x100; return fileno(f); }
int fseek_fake(FILE *f, long off, int whence) { if (is_fake_file(f)) return -1; return fseek(f, off, whence); }
long ftell_fake(FILE *f) { if (is_fake_file(f)) return -1; return ftell(f); }
int getc_fake(FILE *f) { if (is_fake_file(f)) return -1; return getc(f); }
int fgetc_fake(FILE *f) { if (is_fake_file(f)) return -1; return fgetc(f); }
char *fgets_fake(char *s, int n, FILE *f) { if (is_fake_file(f)) return NULL; return fgets(s, n, f); }
int ungetc_fake(int c, FILE *f) { if (is_fake_file(f)) return -1; return ungetc(c, f); }
void setbuf_fake(FILE *f, char *buf) { if (is_fake_file(f)) return; setbuf(f, buf); }

int fprintf_fake(FILE *f, const char *fmt, ...) {
  va_list va; va_start(va, fmt);
  int ret;
  if (is_fake_file(f)) {
#if DEBUG_LOG
    static char buf[0x400];
    ret = vsnprintf(buf, sizeof(buf), fmt, va);
    debugPrintf("stdio: %s", buf);
#else
    ret = 0;
#endif
  } else {
    ret = vfprintf(f, fmt, va);
  }
  va_end(va);
  return ret;
}
int vfprintf_fake(FILE *f, const char *fmt, va_list va) {
  if (is_fake_file(f)) {
#if DEBUG_LOG
    static char buf[0x400];
    int ret = vsnprintf(buf, sizeof(buf), fmt, va);
    debugPrintf("stdio: %s", buf);
    return ret;
#else
    return 0;
#endif
  }
  return vfprintf(f, fmt, va);
}

// ---------------------------------------------------------------------------
// fd routing: the native_app_glue command pipe lives in the fake-fd layer
// (android_native.c). Real files (small fds from open()) pass through to newlib.
// ---------------------------------------------------------------------------

/* ---------------- asset read cache ---------------- */
#define RC_BLOCK   (64u * 1024)
#define RC_NBLOCK  384u                 /* 384 * 64K = 24 MB */
#define RC_MAXFD   64
typedef struct { int fd; uint64_t blk; uint32_t len; } RcTag;
static RcTag    rc_tag[RC_NBLOCK];
static uint8_t *rc_data;
static Mutex    rc_lock;
static int      rc_state;               /* 0=untried 1=ready -1=disabled */
static uint8_t  rc_cacheable[RC_MAXFD];
static unsigned long rc_hits, rc_fills;
void rc_mark(int fd, int on) {           /* called from open_fake/close_fake */
  if (fd < 0 || fd >= RC_MAXFD) return;
  mutexLock(&rc_lock);
  rc_cacheable[fd] = on ? 1 : 0;
  if (rc_state == 1)                     /* fd numbers get reused: drop stale blocks */
    for (unsigned i = 0; i < RC_NBLOCK; i++) if (rc_tag[i].fd == fd) rc_tag[i].fd = -1;
  mutexUnlock(&rc_lock);
}
static void rc_init(void) {
  if (rc_state) return;
  mutexLock(&rc_lock);
  if (!rc_state) {
    rc_data = (uint8_t *)malloc((size_t)RC_NBLOCK * RC_BLOCK);
    if (rc_data) {
      for (unsigned i = 0; i < RC_NBLOCK; i++) rc_tag[i].fd = -1;
      rc_state = 1;
      debugPrintf("[rc] asset read cache armed: %u blocks x %u KB = %u MB\n",
                  RC_NBLOCK, RC_BLOCK >> 10, (RC_NBLOCK * RC_BLOCK) >> 20);
    } else {
      rc_state = -1;
      debugPrintf("[rc] asset read cache DISABLED (alloc failed)\n");
    }
  }
  mutexUnlock(&rc_lock);
}
/* Serve `count` bytes at absolute `off`. Returns bytes served, or -1 to say
 * "not cacheable, caller should do it the plain way". */
static long rc_pread(int fd, void *buf, size_t count, uint64_t off) {
  /* Pack handles carry their own cache, and their fds are outside the rc_*
   * table's range assumptions -- serve them directly. */
  if (asset_pack_fd_is(fd)) return asset_pack_pread_fd(fd, buf, count, (long)off);
  if (fd < 0 || fd >= RC_MAXFD) return -1;
  rc_init();
  if (rc_state != 1 || !rc_cacheable[fd] || count == 0) return -1;
  size_t done = 0;
  mutexLock(&rc_lock);
  while (done < count) {
    uint64_t abs = off + done;
    uint64_t blk = abs / RC_BLOCK;
    unsigned idx = (unsigned)(((blk * 2654435761ull) ^ (unsigned)fd) % RC_NBLOCK);
    uint8_t *slot = rc_data + (size_t)idx * RC_BLOCK;
    if (rc_tag[idx].fd != fd || rc_tag[idx].blk != blk) {   /* miss -> fill one block */
      if (lseek(fd, (long)(blk * RC_BLOCK), SEEK_SET) < 0) break;
      size_t got = 0;
      while (got < RC_BLOCK) {
        long r = read(fd, slot + got, RC_BLOCK - got);
        if (r <= 0) break;
        got += (size_t)r;
      }
      rc_tag[idx].fd = fd; rc_tag[idx].blk = blk; rc_tag[idx].len = (uint32_t)got;
      rc_fills++;
    } else rc_hits++;
    uint32_t blen  = rc_tag[idx].len;
    uint32_t inblk = (uint32_t)(abs - blk * RC_BLOCK);
    if (inblk >= blen) break;                    /* EOF inside this block */
    size_t n = blen - inblk;
    if (n > count - done) n = count - done;
    memcpy((char *)buf + done, slot + inblk, n);
    done += n;
    if (blen < RC_BLOCK) break;                  /* short block == EOF */
  }
  if (0)
    debugPrintf("[rc] hits=%lu fills=%lu\n", rc_hits, rc_fills);
  mutexUnlock(&rc_lock);
  return (long)done;
}

long rc_pread_pub(int fd, void *buf, size_t count, unsigned long long off) {
  return rc_pread(fd, buf, count, (uint64_t)off);
}
long read_fake(int fd, void *buf, size_t count) {
  if (asset_pack_fd_is(fd)) return asset_pack_read_fd(fd, buf, count);
  if (fakefd_is_fake(fd)) return fakefd_read(fd, buf, count);
  /* fsdev can return fewer bytes than requested for a large read; il2cpp's
   * global-metadata.dat loader (and others) assume a single read() fills the
   * buffer. Loop until `count` is satisfied or we hit EOF/error so the metadata
   * is never silently truncated (a short read leaves System.Object et al.
   * unresolvable -> Class::Init(NULL)). */
  {   /* cached path: keeps read()'s file-position semantics intact */
    long cur = lseek(fd, 0, SEEK_CUR);
    if (cur >= 0) {
      long got = rc_pread(fd, buf, count, (uint64_t)cur);
      if (got >= 0) { lseek(fd, cur + got, SEEK_SET); return got; }
    }
  }
  size_t total = 0;
  while (total < count) {
    long r = read(fd, (char *)buf + total, count - total);
    if (r < 0) { if (total) break; return -1; }
    if (r == 0) break; /* EOF */
    total += (size_t)r;
  }
  if (count >= (1u << 20))
    debugPrintf("[io] read(fd=%d, %zu) -> %zu%s\n", fd, count, total,
                total < count ? "  *** SHORT READ ***" : "");
  watch_dump("read", fd, (long)count, 0, buf, (long)total);
  return (long)total;
}
long write_fake(int fd, const void *buf, size_t count) {
  if (fakefd_is_fake(fd)) return fakefd_write(fd, buf, count);
  /* Build #115: trace real-fd writes. Unity's write-all loop (libunity
   * 0x113dc2c) blocked forever inside fsdev_write in runs #113/#114.
   * Log BEFORE and AFTER: if a write blocks, the last [wr] line has no
   * matching result line and names the exact fd+count. */
  debugPrintf("[wr] fd=%d count=%zu ...\n", fd, count);
  long r = write(fd, buf, count);
  debugPrintf("[wr] fd=%d -> %ld\n", fd, r);
  return r;
}
int close_fake(int fd) {
  if (asset_pack_fd_is(fd)) return asset_pack_close_fd(fd);
  rc_mark(fd, 0);                          /* fd numbers are reused: drop its blocks */
  if (fd == g_watch_fd) { debugPrintf("[io] <<< close watched fd=%d\n", fd); g_watch_fd = -1; }
  if (fakefd_is_fake(fd)) return fakefd_close(fd);
  return close(fd);
}
int pipe_fake(int fds[2]) { return fakefd_pipe(fds); }
int poll_fake(void *fds, unsigned long nfds, int timeout) { (void)fds; (void)nfds; (void)timeout; return 0; }
int select_fake(int n, void *r, void *w, void *e, void *t) { (void)n; (void)r; (void)w; (void)e; (void)t; return 0; }

// ---------------------------------------------------------------------------
// networking: online play (Mobage / Silicon Studio servers) is dead. Stub the
// socket layer so connections fail and the engine stays in offline mode.
// ---------------------------------------------------------------------------

int socket_fake(int d, int t, int p) { (void)d; (void)t; (void)p; errno = EAFNOSUPPORT; return -1; }
int connect_fake(int s, const void *a, unsigned l) { (void)s; (void)a; (void)l; errno = ECONNREFUSED; return -1; }
int bind_fake(int s, const void *a, unsigned l) { (void)s; (void)a; (void)l; errno = EACCES; return -1; }
int listen_fake(int s, int b) { (void)s; (void)b; return -1; }
int accept_fake(int s, void *a, void *l) { (void)s; (void)a; (void)l; errno = EINVAL; return -1; }
long send_fake(int s, const void *b, size_t l, int f) { (void)s; (void)b; (void)l; (void)f; errno = EPIPE; return -1; }
long recv_fake(int s, void *b, size_t l, int f) { (void)s; (void)b; (void)l; (void)f; return 0; }
long sendto_fake(int s, const void *b, size_t l, int f, const void *a, unsigned al) { (void)s; (void)b; (void)l; (void)f; (void)a; (void)al; errno = EPIPE; return -1; }
long recvfrom_fake(int s, void *b, size_t l, int f, void *a, void *al) { (void)s; (void)b; (void)l; (void)f; (void)a; (void)al; return 0; }
int shutdown_fake(int s, int how) { (void)s; (void)how; return 0; }
int setsockopt_fake(int s, int lv, int n, const void *v, unsigned l) { (void)s; (void)lv; (void)n; (void)v; (void)l; return 0; }
int getsockopt_fake(int s, int lv, int n, void *v, void *l) { (void)s; (void)lv; (void)n; (void)v; (void)l; return -1; }
int getsockname_fake(int s, void *a, void *l) { (void)s; (void)a; (void)l; return -1; }
int getpeername_fake(int s, void *a, void *l) { (void)s; (void)a; (void)l; return -1; }
int getaddrinfo_fake(const char *node, const char *svc, const void *hints, void **res) { (void)node; (void)svc; (void)hints; if (res) *res = NULL; return -2 /* EAI_NONAME */; }
void freeaddrinfo_fake(void *res) { (void)res; }
int getnameinfo_fake(const void *a, unsigned al, char *h, unsigned hl, char *s, unsigned sl, int f) { (void)a; (void)al; (void)f; if (h && hl) h[0] = 0; if (s && sl) s[0] = 0; return -1; }
int gethostname_fake(char *name, size_t len) { if (name && len) snprintf(name, len, "switch"); return 0; }
void *getservbyname_fake(const char *n, const char *p) { (void)n; (void)p; return NULL; }
unsigned if_nametoindex_fake(const char *n) { (void)n; return 0; }
char *if_indextoname_fake(unsigned i, char *buf) { (void)i; if (buf) buf[0] = 0; return buf; }
static volatile int g_h_errno = 0;
int *__get_h_errno_fake(void) { return (int *)&g_h_errno; }

// ---------------------------------------------------------------------------
// process control: fork/exec/etc. are unavailable; report failure.
// ---------------------------------------------------------------------------

int fork_fake(void) { errno = ENOSYS; return -1; }
int execvp_fake(const char *f, char *const argv[]) { (void)f; (void)argv; errno = ENOSYS; return -1; }
int waitpid_fake(int pid, int *status, int opts) { (void)pid; (void)opts; if (status) *status = 0; errno = ECHILD; return -1; }
int kill_fake(int pid, int sig) { (void)pid; (void)sig; return 0; }
int getpid_fake(void) { return 1; }
int sched_yield_fake(void) { svcSleepThread(0); return 0; }
/* Build #110: usleep wrapper to diagnose main-thread spin-wait. The #107
 * watchdog showed main parked in usleep()->svcSleepThread() for 3+ minutes,
 * called from libil2cpp.so. Log the usec argument and caller to see the
 * sleep pattern (spin-wait with usleep(0)? long sleep?). */
int usleep_fake(unsigned int usec) {
  /* Only log from the main thread to avoid spam; workers don't hit this. */
  static __thread int log_count = 0;
  if (log_count < 50) {
    log_count++;
    debugPrintf("[sleep] usleep(%u) caller=%p tid=%d\n",
                usec, __builtin_return_address(0), gettid_fake());
  }
  return usleep(usec);
}
// bionic struct passwd layout (pw_dir at +0x20, as the engine derefs).
struct bionic_passwd {
  char *pw_name;     /* 0x00 */
  char *pw_passwd;   /* 0x08 */
  uint32_t pw_uid;   /* 0x10 */
  uint32_t pw_gid;   /* 0x14 */
  char *pw_gecos;    /* 0x18 */
  char *pw_dir;      /* 0x20 */
  char *pw_shell;    /* 0x28 */
};
void *getpwuid_fake(int uid) {
  (void)uid;
  static struct bionic_passwd pw;
  static char nm[] = "switch", sh[] = "/bin/sh", empty[] = "";
  /* pw_dir points straight at the resolved game root: it is a char[] with
   * static storage, so no copy is needed and it stays correct if the root is
   * ever re-resolved. (It cannot be a `char dir[] = GAME_HOME` initialiser
   * any more -- GAME_HOME is a runtime value, not a literal.) */
  pw.pw_name = nm; pw.pw_passwd = empty; pw.pw_uid = 0; pw.pw_gid = 0;
  pw.pw_gecos = empty; pw.pw_dir = g_game_root; pw.pw_shell = sh;
  return &pw;
}

// Unity computes its home/cache dir via getenv("HOME") (then getpwuid fallback).
// Serve the writable game root for HOME/TMPDIR; delegate everything else to newlib.
const char *managed_path(const char *p) {
  if (!p) return p;
  const char *c = strchr(p, ':');
  return (c && c[1] == '/') ? c + 1 : p;     // "sdmc:/switch/.." -> "/switch/.."
}
char *getenv_fake(const char *name) {
  if (name) {
    if (!strcmp(name, "HOME"))   return (char *)managed_path(GAME_HOME);
    if (!strcmp(name, "TMPDIR")) return (char *)managed_path(GAME_HOME);
  }
  return getenv(name);
}
// Report a Unix-rooted cwd ("/switch/aota", no "sdmc:") so managed Path
// APIs don't treat it as relative in Path.Combine. newlib's *internal* cwd is
// unchanged, so relative file resolution still works via the default device.
char *getcwd_fake(char *buf, size_t size) {
  char *r = getcwd(buf, size);
  if (!r) return r;
  const char *c = strchr(r, ':');
  if (c && c[1] == '/') memmove(r, c + 1, strlen(c + 1) + 1);  // drop "sdmc:"
  return r;
}
int getrusage_fake(int who, void *usage) { (void)who; if (usage) memset(usage, 0, 144); return 0; }

// ---------------------------------------------------------------------------
// dlopen/dlsym over the already-loaded modules (no real dynamic loading).
// dlsym lets the engine look up its own exports / our shims.
// ---------------------------------------------------------------------------

void *nx_dynload(const char *soname);   /* main.c [aud139] */

void *dlopen_fake(const char *name, int flags) {
  (void)flags;
  debugPrintf("dlopen(%s)\n", name ? name : "(self)");
  /* Build #82: return NULL for libswappywrapper to make Unity disable Swappy
   * gracefully. The binary patch to force-disable Swappy doesn't apply to
   * Unity 6000.5.8f1 (offset mismatch), and the stub causes a crash. */
  if (name && strstr(name, "swappy")) {
    debugPrintf("dlopen(%s) -> NULL [swappy-disabled]\n", name);
    return NULL;
  }
  /* [aud139] Really load game libraries that ship in the game root
   * (libfmod.so, libfmodstudio.so). Until now every dlopen returned the
   * dummy handle 0x1 and dlsym_fake searched only the three preloaded
   * modules, so FMOD's whole FMOD5_* surface resolved NULL: FMODUnity's
   * first P/Invoke (FMOD5_Memory_GetStats) threw EntryPointNotFound-
   * Exception, RuntimeManager init failed, and the game was totally
   * silent. nx_dynload() so_loads the file so its exports join
   * so_resolve_external's search list. Names arrive in several shapes
   * ("/fmod", "fmod", "libfmod.so"); normalise to the on-disk soname.
   * Anything without a matching file in the root keeps the old dummy
   * handle (libaaudio.so & friends are served from the shim table). */
  if (name && name[0]) {
    const char *base = strrchr(name, '/');
    base = base ? base + 1 : name;
    char soname[128];
    if (!strncmp(base, "lib", 3))
      snprintf(soname, sizeof soname, "%s", base);
    else
      snprintf(soname, sizeof soname, "lib%s", base);
    size_t L = strlen(soname);
    if (L < 3 || strcmp(soname + L - 3, ".so") != 0) {
      if (L + 3 < sizeof soname) strcat(soname, ".so");
    }
    void *h = nx_dynload(soname);
    if (h) {
      debugPrintf("dlopen(%s) -> %p [aud139 %s]\n", name, h, soname);
      return h;
    }
  }
  return (void *)0x1;
}
int dlclose_fake(void *h) { (void)h; return 0; }
const char *dlerror_fake(void) { return NULL; }

/* Build #79: log glGetString to see what Unity queries after eglMakeCurrent.
 * Unity likely checks GL_VERSION, GL_RENDERER, GL_EXTENSIONS. If mesa doesn't
 * provide what Unity expects, it may abort (the User Break we're seeing). */
static const unsigned char* (*real_glGetString)(unsigned int name) = NULL;
static const unsigned char* glGetString_log(unsigned int name) {
  if (!real_glGetString) {
    real_glGetString = (const unsigned char* (*)(unsigned int))eglGetProcAddress("glGetString");
  }
  const unsigned char* r = real_glGetString ? real_glGetString(name) : (const unsigned char*)"";
  const char* nstr = "UNKNOWN";
  if (name == 0x1F00) nstr = "GL_VENDOR";
  else if (name == 0x1F01) nstr = "GL_RENDERER";
  else if (name == 0x1F02) nstr = "GL_VERSION";
  else if (name == 0x1F03) nstr = "GL_EXTENSIONS";
  else if (name == 0x8B8C) nstr = "GL_SHADING_LANGUAGE_VERSION";
  debugPrintf("[gl] glGetString(%s=0x%x) -> \"%s\"\n", nstr, name, r ? (const char*)r : "(null)");
  return r;
}

/* Build #81: Swappy stub. Unity dlopen()s libswappywrapper and dlsym()s
 * UnitySwappyWrapperInit. If we return NULL, Unity may not handle it and
 * crash with null deref later (seen at libunity.so+0x11038d8, far=0xe8).
 * Provide a dummy init that returns a non-null handle. */
static void* UnitySwappyWrapperInit_stub(void) {
  debugPrintf("[swappy] UnitySwappyWrapperInit_stub called -> dummy handle\n");
  return (void*)0x5CA1AB1E;
}

void *dlsym_fake(void *handle, const char *symbol) {
  (void)handle;
  if (!symbol) return NULL;
  /* 1) a real export from a loaded module (il2cpp/unity/main) */
  void *p = so_resolve_external(symbol);
  if (p) return p;
  /* 2) one of our libc/GLES/EGL shims (the engine dlopen()s libGLESv2.so etc.
   *    and dlsym()s glGetString/glGetIntegerv, which are shims, not exports) */
  uintptr_t shim = dynlib_find_export(symbol);
  if (shim) { debugPrintf("dlsym(%s) -> %p [shim]\n", symbol, (void *)shim); return (void *)shim; }
  /* (The reference port had a Firebase SWIG stub resolver here. The Room Three
   *  ships no Firebase at all -- confirmed against global-metadata.dat, which
   *  contains no Firebase class literals and no FirebaseCpp P/Invoke names --
   *  so the whole path is gone rather than left as a dead branch.) */
  /* 3) the full GLES/EGL API (~150 entry points) lives in mesa, beyond our
   *    static table -- resolve any gl or egl symbol via eglGetProcAddress.
   *    Build #79: intercept glGetString for logging (Unity queries version/caps). */
  if (!strncmp(symbol, "gl", 2) || !strncmp(symbol, "egl", 3)) {
    if (strcmp(symbol, "glGetString") == 0) {
      debugPrintf("dlsym(%s) -> %p [gl-log-wrapper]\n", symbol, (void*)glGetString_log);
      return (void*)glGetString_log;
    }
    p = (void *)eglGetProcAddress(symbol);
    if (p) { debugPrintf("dlsym(%s) -> %p [egl]\n", symbol, p); return p; }
  }
  /* Build #81: Swappy stub - Unity expects libswappywrapper */
  if (strcmp(symbol, "UnitySwappyWrapperInit") == 0) {
    debugPrintf("dlsym(%s) -> %p [swappy-stub]\n", symbol, (void*)UnitySwappyWrapperInit_stub);
    return (void*)UnitySwappyWrapperInit_stub;
  }
  /* 4) Vulkan WSI translation (mesa-switch NVK): Unity (Android build) asks
   *    for VK_KHR_android_surface / vkCreateAndroidSurfaceKHR, but NVK
   *    provides VK_NN_vi_surface / vkCreateViSurfaceNN. The shim translates.
   *    (Requires libvulkan.a from mesa-switch SDK linked into the NRO.) */
  if (vulkan_shim_is_vulkan_symbol(symbol)) {
    p = vulkan_shim_resolve(symbol);
    if (p) { debugPrintf("dlsym(%s) -> %p [vulkan-shim]\n", symbol, p); return p; }
    /* Not handled by shim: honest NULL. */
  }
  debugPrintf("dlsym(%s) -> NULL\n", symbol);
  return NULL;
}

// ---------------------------------------------------------------------------
// pthread extras: rwlocks, semaphores, timed locks
// ---------------------------------------------------------------------------

typedef struct { RwLock lock; } FakeRwLock;

static FakeRwLock *get_rwlock(void **storage) {
  if (!*storage) { FakeRwLock *l = calloc(1, sizeof(*l)); rwlockInit(&l->lock); *storage = l; }
  return *storage;
}
int pthread_rwlock_rdlock_fake(void **rw) { RwLock *l=&get_rwlock(rw)->lock; diag_wait_enter(DIAG_W_RWLOCK,l); rwlockReadLock(l); diag_wait_exit(); return 0; }
int pthread_rwlock_wrlock_fake(void **rw) { RwLock *l=&get_rwlock(rw)->lock; diag_wait_enter(DIAG_W_RWLOCK,l); rwlockWriteLock(l); diag_wait_exit(); return 0; }
int pthread_rwlock_unlock_fake(void **rw) {
  FakeRwLock *l = get_rwlock(rw);
  if (rwlockIsWriteLockHeldByCurrentThread(&l->lock)) rwlockWriteUnlock(&l->lock);
  else rwlockReadUnlock(&l->lock);
  return 0;
}

typedef struct { Semaphore sem; } FakeSem;
int sem_init_fake(void **s, int pshared, unsigned int value) { (void)pshared; FakeSem *fs = calloc(1, sizeof(*fs)); semaphoreInit(&fs->sem, value); *s = fs; return 0; }
int sem_destroy_fake(void **s) { if (s && *s) { free(*s); *s = NULL; } return 0; }
int sem_post_fake(void **s) {
  /* Build #111: log sem_post to see if the semaphore main waits on ever gets signaled. */
  static int post_log_count = 0;
  if (s && *s) {
    if (post_log_count < 30) {
      post_log_count++;
      debugPrintf("[sem] post sem=%p count_before=%lld tid=%d caller=%p\n",
                  (void*)*s, (long long)((FakeSem *)*s)->sem.count,
                  gettid_fake(), __builtin_return_address(0));
    }
    semaphoreSignal(&((FakeSem *)*s)->sem);
  }
  return 0;
}
int sem_wait_fake(void **s) { if (s && *s) { Semaphore *sm=&((FakeSem *)*s)->sem; diag_wait_enter(DIAG_W_SEM,sm); semaphoreWait(sm); diag_wait_exit(); } return 0; }
int sem_trywait_fake(void **s) { if (s && *s && semaphoreTryWait(&((FakeSem *)*s)->sem)) return 0; errno = EAGAIN; return -1; }
int sem_getvalue_fake(void **s, int *val) {
  /* Build #111: log sem_getvalue to identify which semaphore main polls in its spin-wait loop. */
  static int getvalue_log_count = 0;
  int v = 0;
  if (s && *s) v = (int)((FakeSem *)*s)->sem.count;
  if (val) *val = v;
  if (getvalue_log_count < 30) {
    getvalue_log_count++;
    debugPrintf("[sem] getvalue sem=%p val=%d tid=%d caller=%p\n",
                s && *s ? (void*)*s : NULL, v,
                gettid_fake(), __builtin_return_address(0));
  }
  /* Build #113/#116: deadlock breaker. If main is stuck polling the
   * job-completion semaphore (libil2cpp job wait loop) and it never gets
   * posted, fake a post after many polls to unblock. Build #113 fired once
   * (unblocked flag) and main just hung on the NEXT wait; build #116 re-arms
   * after every fire so main keeps marching wait-to-wait -- this maps how
   * many sequential job waits block boot and whether anything lies beyond. */
  {
    static void *stuck_sem = NULL;
    static int poll_count = 0;
    static int fire_count = 0;
    if (s && *s && v == 0) {
      if (*s != stuck_sem) { stuck_sem = *s; poll_count = 0; }
      poll_count++;
      /* After ~5000 polls (~15 sec of usleep(3000)), fake unblock, re-arm. */
      if (poll_count >= 5000) {
        fire_count++;
        debugPrintf("[sem] >>> DEADLOCK BREAKER #%d: faking post to stuck sem %p after %d polls <<<\n",
                    fire_count, (void*)*s, poll_count);
        semaphoreSignal(&((FakeSem *)*s)->sem);
        /* Update the value that caller will see */
        v = (int)((FakeSem *)*s)->sem.count;
        if (val) *val = v;
        poll_count = 0;
      }
    } else {
      poll_count = 0;
    }
  }
  return 0;
}
// no native timed wait on libnx Semaphore; poll with a short backoff to the
// deadline. The engine uses it as a yield-with-timeout in its task scheduler.
int sem_timedwait_fake(void **s, const struct timespec *abs) {
  (void)abs;
  for (int i = 0; i < 1000; i++) {
    if (sem_trywait_fake(s) == 0) return 0;
    svcSleepThread(1000000ull); // 1 ms
  }
  errno = ETIMEDOUT;
  return -1;
}

/* --- Boehm GC stop-the-world bridge -------------------------------------
 * il2cpp's Boehm GC stops the world by sending every other thread a suspend
 * signal via pthread_kill; each target's signal handler sem_posts an ack and
 * parks in sigsuspend, and GC_stop_world / GC_start_world sem_wait on those
 * acks. POSIX signals are never delivered on Switch (pthread_kill is a no-op),
 * so the acks never arrive and the first collection hangs forever inside
 * GC_stop_world -- the verified boot wall.
 *
 * sem_post/sem_wait themselves work here (real libnx Semaphore underneath), so
 * we make pthread_kill itself post the ack that the never-delivered handler
 * would have posted. Every thread the GC suspends is already parked in our own
 * shim (idle worker / background waits), so not literally suspending them is
 * fine for the brief mark window.
 *
 * Build #122: the offsets below were RE-DERIVED for THIS libil2cpp
 * (capstone + FDE verified; report: aota_analysis/libil2cpp_jobs_analysis.md).
 * The previous values came from the template donor's libil2cpp and never
 * matched this binary -- the bridge compared pthread_kill's signal against
 * garbage and never fired once in builds <= #121 (zero sem_post process-wide
 * in every hardware log). Verified layout for this game:
 *   retry flag       = *(int*)(il2cpp + 0x66b23d8)  (.data, init 1;
 *                        GC_RETRY_SIGNALS env can clear it; our getenv
 *                        returns NULL so it stays on)
 *   suspend signal   = *(int*)(il2cpp + 0x66b23dc)  (.data, lazy -1 -> 30,
 *                        set by the stop-world initializer 0x2c5c3d0)
 *   restart signal   = *(int*)(il2cpp + 0x66b23e0)  (.data, lazy -1 -> 24)
 *   ack semaphore    =  (void**)(il2cpp + 0x68def70) (.bss sem_t; the GC
 *                        sem_init's it through our sem_init_fake, which
 *                        stores a FakeSem* there)
 * Protocol mirror of the real handler (0x2c5bf20): on suspend it posts the
 * ack once, then parks in sigsuspend; on wake (retry flag on) it posts the
 * ack AGAIN -- the restart ack that GC_start_world's wait consumes. So the
 * bridge posts on BOTH signals, the restart post gated on the retry flag,
 * exactly like the binary. Before GC init the signal globals read -1 (never
 * match a real signal) and the ack-sem storage is NULL (sem_post_fake
 * no-ops), so this is inert until the GC is actually up. */
uintptr_t g_il2cpp_base = 0;

/* Derived for THIS libil2cpp -- see nx_patch_os.h for the evidence. */
#define GC_SUSPEND_SIG_OFF OS_GC_SUSPEND_SIG_OFF
#define GC_RESTART_SIG_OFF OS_GC_RESTART_SIG_OFF
#define GC_RETRY_FLAG_OFF  OS_GC_RETRY_FLAG_OFF
#define GC_ACK_SEM_OFF     OS_GC_ACK_SEM_OFF

int pthread_kill_gc(pthread_t t, int sig) {
  uintptr_t b = g_il2cpp_base;
  if (b && sig > 0) {
    int suspend_sig = *(volatile int *)(b + GC_SUSPEND_SIG_OFF);
    int restart_sig = *(volatile int *)(b + GC_RESTART_SIG_OFF);
    void **ack_sem  = (void **)(b + GC_ACK_SEM_OFF);
    if (suspend_sig > 0 && sig == suspend_sig) {
      /* stop-the-world: post the suspend ack the handler would have posted */
      static unsigned cnt_s = 0;
      cnt_s++;
      if (cnt_s <= 4 || (cnt_s % 64) == 0)
        debugPrintf("[gc122] suspend kill #%u sig=%d target=%p ack_storage=%p sem=%p\n",
                    cnt_s, sig, (void *)t, (void *)ack_sem,
                    ack_sem ? *ack_sem : NULL);
      sem_post_fake(ack_sem);
      return 0;
    }
    if (restart_sig > 0 && sig == restart_sig) {
      /* start-the-world: the woken handler posts a restart ack iff the
       * retry flag is on (and GC_start_world only waits for it then) */
      static unsigned cnt_r = 0;
      cnt_r++;
      int retry = *(volatile int *)(b + GC_RETRY_FLAG_OFF);
      if (cnt_r <= 4 || (cnt_r % 64) == 0)
        debugPrintf("[gc122] restart kill #%u sig=%d target=%p retry=%d\n",
                    cnt_r, sig, (void *)t, retry);
      if (retry) sem_post_fake(ack_sem);
      return 0;
    }
  }
  return 0;   /* any other signal: no-op, as before */
}
