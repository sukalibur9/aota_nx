/* nx_exception_dump.c -- user exception handler: on any fault, dump symbolized
 * PC/LR + all GPRs + the faulting thread's stack frame, straight into debug.log.
 * Then break so Atmosphere's creport still fires. Every read is
 * svcQueryMemory-guarded.
 *
 * #274: every [xd] line is ALSO mirrored to sdmc:/switch/aota/xd.log via a
 * lock-free raw write (xd_print). Test #273's Sphaira crash lost its [xd]
 * dump entirely because debug.log's g_log_lock was already wedged when the
 * fault hit; the mirror survives that.
 *
 * Symbolization is dynamic (so_find_module_by_addr), so this is not tied to any
 * build: a fault anywhere in libunity/libil2cpp prints as "libX.so+0xOFFSET",
 * which is directly comparable against nx_patch_os.h and a disassembler.
 *
 * The extra [sp] slots dumped below were chosen by the reference port while
 * chasing a specific Unity UI job crash. They are harmless to dump on any
 * fault -- treat them as generic stack context rather than as meaningful field
 * names for this title.
 *
 * Build #305 (2026-11-19): THE FAULT PATH MUST NOT ALLOCATE OR LOCK.
 * Test #304's crash report was not the game's fault at all: the handler ran,
 * its first dump line went through the (correctly non-blocking) debugPrintf and
 * was dropped, and then xd_raw_write's lazy open() took the process down:
 *
 *   svcBreak  <- mutexLock <- rmutexLock <- _malloc_r <- _memalign_r
 *             <- __wrap_malloc <- __alloc_handle <- _open_r <- open
 *             <- xd_raw_write <- __libnx_exception_handler
 *
 * open() allocates a FILE/handle, newlib's heap lock is an rmutex, and the
 * faulting thread still held it (the fault itself was inside the allocator),
 * so libnx's same-thread deadlock detection fired svcBreak(0x1) and
 * Atmosphere reported mutexLock (result 0xCA8) instead of the real fault --
 * the second time this build lost its dump to its own diagnostics.
 * So from #305:
 *   1. xd.log's fd and debug.log's fd are opened at boot (xd_log_init), never
 *      from the handler;
 *   2. the whole dump is built in ONE static buffer with hand-rolled integer
 *      formatting -- no vsnprintf/snprintf (newlib's vfprintf can malloc);
 *   3. the buffer is handed to a pre-created dumper thread over a libnx Event
 *      and the handler waits for it with a 2 s bound, so a wedged FS service
 *      cannot park the faulting thread forever;
 *   4. a reentrancy guard makes a fault inside the handler emit one fixed
 *      line and stop, instead of recursing.
 */
#include <switch.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include "util.h"
#include "diag.h"
#include "so_util.h"

#define XD_BUF_SIZE 0x4000

/* The finished dump, built here by the handler and written by the dumper. */
static char xd_buf[XD_BUF_SIZE];
static size_t xd_len;
/* #319: bytes of xd_buf already handed to write(). The buffer is delivered in
 * one shot from xd_finish, but test #318 proved that shot can be lost: the
 * handler fired, xd.log kept only the two nested-fault lines, and no dump line
 * ever appeared -- the dumper thread never confirmed within the 2 s bound, and
 * the re-raised svcBreak killed the process before anything else ran. Whatever
 * prefix has been flushed is therefore never written twice. */
static size_t xd_flushed;
static volatile int xd_busy;   /* handler already running (reentrancy guard) */
static int xd_nested_breaks;   /* #331: breaks taken from the nested path */

static int xd_fd = -1;         /* sdmc:/switch/aota/xd.log, opened at boot */

/* #331: the fault path must not touch newlib AT ALL -- not just open(), also
 * write(). Test #330's creport shows exactly that failure mode: the handler ran
 * three times over, each pass entered xd_flush_pending -> xd_write_all ->
 * _write_r and died again, so the fault record never reached disk and the
 * report only contains the handler's own recursion:
 *
 *   svcBreak <- __libnx_exception_handler <- xd_flush_pending <- xd_write_all
 *            <- _write_r <- __libnx_exception_returnentry <- handler <- ... (x8)
 *
 * That is the #305 pattern (the fault is inside the allocator, so the faulting
 * thread still holds newlib's heap lock; every newlib call from the handler
 * re-deadlocks and libnx breaks again). The one channel that needs no newlib
 * and no fsdev lock is a raw FsFile opened at boot and written by offset: the
 * file handle is pre-created, fsFileWrite is plain IPC, and FsWriteOption_Flush
 * commits it. xdraw.log is a SEPARATE file from xd.log so the two channels
 * (newlib fd + raw handle) never fight over one file's offset. */
static FsFile xd_rf;
static int    xd_rf_ok;
static int    xd_rf_dead;
static s64    xd_rf_off;

static int xd_raw_ok(void) { return xd_rf_ok && !xd_rf_dead; }

/* 0 = delivered and flushed, -1 = unusable for the rest of the run */
static int xd_raw_write(const char *p, size_t n) {
  if (!xd_raw_ok() || !n) return xd_raw_ok() ? 0 : -1;
  if (R_FAILED(fsFileWrite(&xd_rf, xd_rf_off, p, n, FsWriteOption_Flush))) {
    xd_rf_dead = 1;
    return -1;
  }
  xd_rf_off += (s64)n;
  return 0;
}

static Thread xd_thr;
static Event  xd_evt;          /* "buffer ready" */
static Event  xd_evt_done;     /* "written" */
static int    xd_thr_ok;
static int    xd_evt_ok;       /* #307: both events really created */

/* ---- no-malloc formatting into xd_buf -------------------------------- */

static void bch(char c) {
  if (xd_len + 1 < sizeof xd_buf) xd_buf[xd_len++] = c;
}

static void bs(const char *s) {
  while (*s) bch(*s++);
}

/* lowercase hex; `digits` = minimum width, zero padded (0 = natural width) */
static void bhex(u64 v, int digits) {
  char d[16];
  int n = 0;
  if (!v) d[n++] = '0';
  while (v) {
    unsigned x = (unsigned)(v & 0xF);
    d[n++] = (char)(x < 10 ? '0' + x : 'a' + x - 10);
    v >>= 4;
  }
  for (int i = n; i < digits; i++) bch('0');
  while (n) bch(d[--n]);
}

/* decimal; width = minimum field width, `left` pads on the right */
static void bdec(long long v, int width, char pad, int plus, int left) {
  char d[24];
  int n = 0;
  unsigned long long u = v < 0 ? (unsigned long long)(-v) : (unsigned long long)v;
  do { d[n++] = (char)('0' + (u % 10)); u /= 10; } while (u);
  int sign = (v < 0) ? 1 : (plus ? 1 : 0);
  int total = n + sign;
  if (!left) for (int i = total; i < width; i++) bch(pad);
  if (v < 0) bch('-'); else if (plus) bch('+');
  while (n) bch(d[--n]);
  if (left) for (int i = total; i < width; i++) bch(' ');
}

/* ---- the dumper ------------------------------------------------------ */

static void xd_write_all(int fd, const char *p, size_t len) {
  while (len > 0) {
    ssize_t w = write(fd, p, len);
    if (w <= 0) return;
    p += w;
    len -= (size_t)w;
  }
}

/* #324: commit the bytes, do not just queue them. Test #323 crashed with the
 * handler's own svcBreak and xd.log holding ONLY the boot probes: not one
 * "[xd] USER EXCEPTION" line -- while #320's identical report kept the whole
 * dump. The dump is written to an fd that is never closed (the process breaks),
 * so on FAT the directory entry can still carry the old size and the tail is
 * lost with the cache. fsync after every flush makes the next crash readable. */
static void xd_sync(void) {
  int dbg = debugLogFd();
  if (xd_fd >= 0) fsync(xd_fd);
  if (dbg >= 0 && dbg != xd_fd) fsync(dbg);
}

/* #319: write the not-yet-delivered tail of xd_buf to both channels and mark it
 * delivered. Used by the dumper, by xd_finish's fallback, and by the nested-fault
 * path (which is the only place a partial dump can still be recovered). */
static void xd_flush_pending(void) {
  if (xd_len <= xd_flushed) return;
  size_t n = xd_len - xd_flushed;
  const char *p = xd_buf + xd_flushed;
  xd_flushed = xd_len;
  /* #331: prefer the raw handle -- it needs no newlib lock, so it still works
   * when the fault happened inside the allocator (the #330 case). Only when
   * that channel is genuinely unavailable do we fall back to the newlib fds. */
  if (xd_raw_write(p, n) == 0) return;
  int dbg = debugLogFd();
  if (xd_fd >= 0) xd_write_all(xd_fd, p, n);
  if (dbg >= 0 && dbg != xd_fd) xd_write_all(dbg, p, n);
  xd_sync();   /* #324: queue is not delivery -- commit before we break */
}

/* #306: boot probe. Test #305 died with debug.log stopped one line after
 * "[root] game root" and gtid.log stopped at its boot line, i.e. inside (or
 * immediately after) xd_log_init -- the very first thing main() does after the
 * root is resolved. Nothing else in that window changed between #304 and #305.
 * Each step of xd_log_init writes one raw tagged line here, with the Result of
 * the call, so one boot run names the call that never returns (or fails).
 * No lock, no malloc: only the already-open fds and write(). */
static void xd_probe(const char *tag, long v) {
  char b[96];
  size_t k = 0;
  char d[16];
  int n = 0;
  unsigned long long u = (unsigned long long)v;
  b[k++] = '['; b[k++] = 'x'; b[k++] = 'i'; b[k++] = ']'; b[k++] = ' ';
  while (*tag && k < sizeof b - 24) b[k++] = *tag++;
  b[k++] = ' '; b[k++] = '='; b[k++] = ' ';
  if (!u) d[n++] = '0';
  while (u) { unsigned x = (unsigned)(u & 0xF); d[n++] = (char)(x < 10 ? '0' + x : 'a' + x - 10); u >>= 4; }
  while (n) b[k++] = d[--n];
  b[k++] = '\n';
  int dbg = debugLogFd();
  if (dbg >= 0) xd_write_all(dbg, b, k);
  if (xd_fd >= 0 && xd_fd != dbg) xd_write_all(xd_fd, b, k);
  /* #307: the tail of test #306's debug.log was mangled ("[xi] tstart = 0"
   * missing, "done = 0" cut to "e = 0"): a hung process never closes the fds,
   * so FAT's directory entry keeps an older size than the data clusters.
   * Sync after every probe -- there are only a handful per boot -- so the last
   * line always names the real point of death. */
  if (dbg >= 0) fsync(dbg);
  if (xd_fd >= 0 && xd_fd != dbg) fsync(xd_fd);
}

/* #307: exported stage marker for main(). Same lock-free channel as the boot
 * probes; with the sync above, the last "stage" line is trustworthy even
 * after a hard power-off. */
void xd_stage(const char *tag) { xd_probe(tag, 0); }

/* #305: pre-created at boot (xd_log_init), so the fault path allocates nothing.
 * Writes the buffer to the mirror and to debug.log, then signals completion.
 * If libnx's FS service is wedged, this thread blocks -- never the handler. */
static void xd_dumper_main(void *arg) {
  (void)arg;
  xd_probe("dumper-alive", 0);        /* #306: the thread really started */
  for (;;) {
    /* #307: never spin. #306's eventCreate returned 0x10801 (a failure), so
     * this wait ran on a garbage handle and returned instantly: a 100%
     * busy-loop on a real game thread's core. Sleep before retrying. */
    if (R_FAILED(eventWait(&xd_evt, UINT64_MAX))) {
      svcSleepThread(20000000ULL);
      continue;
    }
    xd_flush_pending();
    eventFire(&xd_evt_done);
  }
}

/* Called from main() right after the game root is resolved: open both log
 * channels and start the dumper thread while the process is healthy. */
void xd_log_init(void) {
  xd_probe("enter", 0);
  if (xd_fd < 0)
    xd_fd = open("sdmc:/switch/aota/xd.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
  xd_probe("xdfd", xd_fd);
  (void)debugLogFd();          /* open debug.log now, not on the fault path */
  xd_probe("dbgfd", debugLogFd());
  /* #331: this build's dump channel -- opened here, on the healthy main
   * thread, so the fault path only ever calls fsFileWrite. */
  if (!xd_rf_ok) {
    FsFileSystem *fs = fsdevGetDeviceFileSystem("sdmc");
    if (fs) {
      (void)fsFsCreateFile(fs, "/switch/aota/xdraw.log", 0, 0);   /* EEXIST is fine */
      if (R_SUCCEEDED(fsFsOpenFile(fs, "/switch/aota/xdraw.log",
                                   (FsOpenMode)(FsOpenMode_Write | FsOpenMode_Append),
                                   &xd_rf))) {
        s64 sz = 0;
        if (R_SUCCEEDED(fsFileGetSize(&xd_rf, &sz)) && sz >= 0) xd_rf_off = sz;
        xd_rf_ok = 1;
      }
    }
    xd_probe("rawxd", xd_rf_ok);
  }
  if (xd_thr_ok) return;
  Result   rc = eventCreate(&xd_evt, true);        /* auto-clear: one fire, one write */
  xd_probe("evt", rc);
  if (R_SUCCEEDED(rc)) xd_evt_ok = 1;
  rc = eventCreate(&xd_evt_done, true);
  xd_probe("evtdone", rc);
  /* #307: #306 showed both eventCreate calls failing (0x10801) while the
   * thread started anyway. Without events the dumper can never be signalled,
   * so do not start it -- the handler's own pre-opened-fd path is the fallback
   * (xd_finish's else branch) and needs no thread at all. */
  if (R_FAILED(rc) || !xd_evt_ok) { xd_probe("no-events", 1); return; }
  rc = threadCreate(&xd_thr, xd_dumper_main, NULL, NULL, 0x4000, 0x2C, -2);
  xd_probe("tcreate", rc);
  if (R_SUCCEEDED(rc)) {
    rc = threadStart(&xd_thr);
    xd_probe("tstart", rc);
    if (R_SUCCEEDED(rc)) xd_thr_ok = 1;
  }
  xd_probe("done", xd_thr_ok);   /* last line before r3_seed_playerprefs */
}

static void xd_finish(void) {
  if (xd_thr_ok) {
    __sync_synchronize();
    eventFire(&xd_evt);
    /* Bounded: libnx's fs write can block behind a wedged FS session, and the
     * process must still reach svcBreak so creport fires. */
    if (R_SUCCEEDED(eventWait(&xd_evt_done, 2000000000ULL))) return;
    /* #319: Test #318 reached this point with the dumper never confirming --
     * most likely because the panic froze every other thread first -- and the
     * dump was thrown away with the process. The nested-fault lines DID reach
     * xd.log through this same fd from inside the handler, so the channel works
     * from here even when the dumper thread is gone: write it ourselves instead
     * of losing the only record of the fault. */
  }
  xd_flush_pending();
}

/* libnx user exception handling: providing these symbols + the handler enables it */
alignas(16) u8 __nx_exception_stack[0x8000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);

static int xd_readable(uintptr_t addr, size_t len) {
  if (!addr || addr < 0x1000) return 0;
  uintptr_t a = addr, end = addr + len;
  while (a < end) {
    MemoryInfo mi; u32 pi;
    if (R_FAILED(svcQueryMemory(&mi, &pi, a))) return 0;
    if (mi.type == MemType_Unmapped) return 0;
    if ((mi.perm & Perm_R) == 0) return 0;
    uintptr_t be = (uintptr_t)mi.addr + mi.size;
    if (be <= a) return 0;
    a = be;
  }
  return 1;
}

/* "libunity.so+0x1234" style annotation; falls back to raw hex.
 * #305: hand-formatted -- snprintf may allocate through vfprintf. */
static const char *xd_sym(u64 v, char *buf, size_t n) {
  so_module *m = so_find_module_by_addr((const void *)v);
  size_t k = 0;
  char d[16];
  int nd = 0;
  u64 rest;
  if (m) {
    for (const char *s = m->name; *s && k + 4 < n; s++) buf[k++] = *s;
    buf[k++] = '+'; buf[k++] = '0'; buf[k++] = 'x';
    rest = v - (uintptr_t)m->load_virtbase;
  } else {
    buf[k++] = '0'; buf[k++] = 'x';
    rest = v;
  }
  if (!rest) d[nd++] = '0';
  while (rest) {
    unsigned x = (unsigned)(rest & 0xF);
    d[nd++] = (char)(x < 10 ? '0' + x : 'a' + x - 10);
    rest >>= 4;
  }
  while (nd && k + 1 < n) buf[k++] = d[--nd];
  buf[k] = 0;
  return buf;
}

static void xd_dump_range(const char *tag, uintptr_t base, size_t bytes) {
  if (!xd_readable(base, bytes)) {
    bs("[xd] "); bs(tag); bs(" @0x"); bhex((u64)base, 0);
    bs(": UNREADABLE\n");
    return;
  }
  for (size_t off = 0; off < bytes; off += 0x20) {
    const u64 *q = (const u64 *)(base + off);
    bs("[xd] "); bs(tag); bs("+"); bhex((u64)off, 3); bs(": ");
    bhex(q[0], 16); bs(" "); bhex(q[1], 16); bs(" ");
    bhex(q[2], 16); bs(" "); bhex(q[3], 16); bs("\n");
  }
}

void __libnx_exception_handler(ThreadExceptionDump *ctx) {
  char b1[96], b2[96], b3[96];

  /* #329: the wedge catcher (diag.c) faults on purpose once the fs is dead and
   * the game is still in frame 0. Every other dump channel -- xd.log,
   * debug.log, wd290.log, sentinel.log, alive.log -- writes through the same fs
   * session that just died, so here we write NOTHING and re-raise at once:
   * Atmosphere's creport is a separate process and still produces the full
   * thread report (PC + stack for every thread), which is the only evidence
   * that survives. The catcher's registers (x0-x5) carry idle ms, flush seq,
   * frame, queued bytes and dropped lines. */
  if (g_wedge_break) {
    svcBreak(BreakReason_Panic, 0, 0);
    for (;;) svcSleepThread(1000000000ULL);
  }

  /* #305: a fault while dumping would recurse forever; say so once, raw.
   * #319: TWO ways to get here, and #318 could not tell them apart: a fault
   * inside the dump (the first pass died part-way), or the re-raised svcBreak
   * at the end of a completed dump coming back as a fresh user exception.
   * Deliver the partial buffer first -- the first pass never reaches xd_finish
   * on the fault path -- then name this pass's own context, so one run says
   * which of the two it was and where the handler stopped. */
  if (xd_busy) {
    /* #331: break ONCE, then park. Test #330 repeated the break, and every
     * break re-enters this handler, so the report showed eight copies of the
     * recursion instead of the fault. The record itself is on xdraw.log by
     * now (raw channel); one break is enough to make creport write the file. */
    if (xd_nested_breaks >= 1) {
      for (;;) svcSleepThread(1000000000ULL);
    }
    xd_nested_breaks++;
    if (xd_len > XD_BUF_SIZE - 192) xd_len = XD_BUF_SIZE - 192;
    if (xd_flushed > xd_len) xd_flushed = xd_len;
    size_t had = xd_len;
    bs("\n[xd] ==== nested exception inside handler ====\n");
    bs("[xd] nested desc=0x"); bhex((u64)ctx->error_desc, 0);
    bs(" pc="); bhex(ctx->pc.x, 16);
    bs(" lr="); bhex(ctx->lr.x, 16);
    bs(" far="); bhex(ctx->far.x, 16);
    bs(" esr="); bhex((u64)ctx->esr, 8);
    bs(" sp="); bhex(ctx->sp.x, 16);
    bs(" x0="); bhex(ctx->cpu_gprs[0].x, 16);
    bs(" dumped="); bdec((long long)had, 0, '0', 0, 0);
    bs(" raw="); bdec(xd_raw_ok() ? 1 : 0, 0, '0', 0, 0);
    bs("\n");
    xd_flush_pending();
    if (xd_raw_ok()) {         /* #331: only break when the record is on disk */
      svcBreak(BreakReason_Panic, 0, 0);
    }
    for (;;) svcSleepThread(1000000000ULL);
  }
  xd_busy = 1;
  xd_len = 0;
  xd_flushed = 0;

  u64 fault_tid = 0;
  svcGetThreadId(&fault_tid, CUR_THREAD_HANDLE);
  bs("[xd] ================= USER EXCEPTION =================\n");
  bs("[xd] faulting thread tid="); bdec((long long)fault_tid, 0, '0', 0, 0);
  bs("\n");
  bs("[xd] desc=0x"); bhex((u64)ctx->error_desc, 0);
  bs(" pc="); bs(xd_sym(ctx->pc.x, b1, sizeof b1));
  bs(" far="); bhex(ctx->far.x, 16);
  bs(" esr="); bhex((u64)ctx->esr, 8);
  bs("\n");
  bs("[xd] lr="); bs(xd_sym(ctx->lr.x, b2, sizeof b2));
  bs(" sp="); bhex(ctx->sp.x, 16);
  bs(" fp="); bhex(ctx->fp.x, 16);
  bs("\n");
  /* #324: deliver the beacon (tid/desc/pc/lr/far/esr/sp/fp) to disk BEFORE the
   * long dump. Test #323 lost the entire dump, so the fault identity must not
   * depend on the rest of this function or on the dumper thread surviving. */
  xd_flush_pending();
  for (int i = 0; i < 28; i += 4) {
    bs("[xd] x"); bdec(i, 2, ' ', 0, 1); bs(" ");
    bhex(ctx->cpu_gprs[i].x, 16);
    bs("  x"); bdec(i + 1, 2, ' ', 0, 1); bs(" ");
    bhex(ctx->cpu_gprs[i + 1].x, 16);
    bs("  x"); bdec(i + 2, 2, ' ', 0, 1); bs(" ");
    bhex(ctx->cpu_gprs[i + 2].x, 16);
    bs("  x"); bdec(i + 3, 2, ' ', 0, 1); bs(" ");
    bhex(ctx->cpu_gprs[i + 3].x, 16);
    bs("\n");
  }
  bs("[xd] x28 "); bhex(ctx->cpu_gprs[28].x, 16); bs("\n");

  /* Faulting instruction bytes (pc-16 .. pc+20): lets us decode the exact
   * access (base register, offset, width) without a disassembler on hand. */
  {
    u64 pcb = ctx->pc.x & ~3ull;
    if (pcb >= 16 && xd_readable(pcb - 16, 40)) {
      const u32 *w = (const u32 *)(pcb - 16);
      for (int i = 0; i < 10; i++) {
        bs("[xd] ins"); bdec((i - 4) * 4, 0, '0', 1, 0);
        bs(" "); bs(xd_sym(pcb - 16 + (u64)(i * 4), b3, sizeof b3));
        bs(": "); bhex((u64)w[i], 8); bs("\n");
      }
    } else {
      bs("[xd] ins: code bytes around pc UNREADABLE\n");
    }
  }

  /* frame-pointer backtrace (same walk as the watchdog) */
  uintptr_t fp = (uintptr_t)ctx->fp.x;
  for (int d = 0; d < 12 && fp; d++) {
    if (!xd_readable(fp, 16)) break;
    uintptr_t nfp = ((uintptr_t *)fp)[0];
    uintptr_t rlr = ((uintptr_t *)fp)[1];
    if (!rlr) break;
    bs("[xd]   bt["); bdec(d, 0, '0', 0, 0); bs("] ");
    bs(xd_sym(rlr, b3, sizeof b3)); bs("\n");
    if (nfp <= fp) break;
    fp = nfp;
  }

  /* the whole stack frame: every [sp+slot] the crash block reads */
  uintptr_t sp = (uintptr_t)ctx->sp.x;
  xd_dump_range("SP", sp, 0x200);

  /* #302: recover the caller chain without an unwinder. The x29 walk above
   * dies on the first frame that has no canonical frame pointer (Unity is
   * built -fomit-frame-pointer; b301's bt[0] came out as 0x9), so scan the
   * top 4 KB of the faulting stack for words pointing into a module's
   * EXECUTABLE segment instead. Every live return address is such a word. */
  {
    int printed = 0;
    for (size_t off = 0; off < 0x1000 && printed < 24; off += 8) {
      uintptr_t a = sp + off;
      if (!xd_readable(a, 8)) break;
      uintptr_t v = *(const uintptr_t *)a;
      if (v < 0x1000) continue;
      so_module *m = so_find_module_by_addr((const void *)v);
      if (!m) continue;
      int is_exec = 0;
      for (int i = 0; i < m->phnum; i++) {
        if (!(m->phdr[i].p_flags & PF_X)) continue;
        uintptr_t lo = (uintptr_t)m->load_virtbase + m->phdr[i].p_vaddr;
        if (v >= lo && v < lo + m->phdr[i].p_memsz) { is_exec = 1; break; }
      }
      if (!is_exec) continue;
      char b4[96];
      bs("[xd] stk+"); bhex((u64)off, 3); bs(" ");
      bs(xd_sym(v, b4, sizeof b4)); bs("\n");
      printed++;
    }
    if (!printed) bs("[xd] stk: no module code pointers in the top 4 KB\n");
  }

  /* dump the struct at x1 (for the 0x124400c list crash: x1 is the list head) */
  {
    uintptr_t x1 = (uintptr_t)ctx->cpu_gprs[1].x;
    if (xd_readable(x1, 0x40))
      xd_dump_range("X1", x1 - 0x20, 0x60);
  }

  /* UIGeometryJob specifics (harmless if this is a different crash):
   * [sp+0x48]=element base, [sp+0x50]=element index (stride 0x70),
   * [sp+0x28]=job data, [sp+0x10]=output base. */
  if (xd_readable(sp + 0x58, 8)) {
    uintptr_t elem_base = ((uintptr_t *)(sp + 0x48))[0];
    uintptr_t elem_idx  = ((uintptr_t *)(sp + 0x50))[0];
    uintptr_t jobdata   = ((uintptr_t *)(sp + 0x28))[0];
    uintptr_t outbase   = ((uintptr_t *)(sp + 0x10))[0];
    bs("[xd] elem_base="); bhex((u64)elem_base, 16);
    bs(" idx="); bdec((long long)elem_idx, 0, '0', 0, 0);
    bs(" jobdata="); bhex((u64)jobdata, 16);
    bs(" outbase="); bhex((u64)outbase, 16);
    bs("\n");
    if (elem_idx < 0x10000 && elem_base)
      xd_dump_range("ELEM", elem_base + elem_idx * 0x70, 0x70);
    if (jobdata) xd_dump_range("JOB", jobdata, 0x60);
  }
  /* #316: NULL-ish faults are a dereference through a pointer that read back
   * as zero; the object one hop away names the subsystem. Dump the pointees of
   * the registers that held live pointers, and their first field, so the log
   * shows which object had NULL at offset 0 without another build. */
  /* #317: also cover a small NEGATIVE far (data abort at base + (-8) with a
   * NULL base), which #316's `far < 0x10000` test skipped -- far is unsigned
   * here, so 0xfffffff8 never dumped anything. */
  if (ctx->far.x < 0x10000 || ctx->far.x >= (u64)-0x10000) {
    static const int regs[] = { 8, 9, 19, 20, 21, 22, 24, 25, 26, 27 };
    char tag[8];
    for (unsigned r = 0; r < sizeof regs / sizeof regs[0]; r++) {
      uintptr_t p = (uintptr_t)ctx->cpu_gprs[regs[r]].x;
      if (p < 0x1000 || !xd_readable(p, 8)) continue;
      tag[0] = 'R'; tag[1] = '0' + (char)(regs[r] / 10);
      tag[2] = '0' + (char)(regs[r] % 10); tag[3] = 0;
      xd_dump_range(tag, p, 0x40);
      uintptr_t q = *(const uintptr_t *)p;          /* one hop: field 0 */
      if (q >= 0x1000 && xd_readable(q, 8)) {
        tag[0] = 'R'; tag[1] = '>'; tag[2] = 0;
        bs("[xd] R"); bdec(regs[r], 0, '0', 0, 0); bs("->0x"); bhex((u64)q, 0); bs("\n");
        xd_dump_range(tag, q, 0x40);
      }
    }
  }
  /* #317: the libunity set() hook's record. Written by the trampoline into bss
   * without I/O, so it is here even when debug.log dropped the live line. */
  {
    typedef struct {
      uintptr_t calls, anom, idx, obj, a, b, caller, data, count, cap, data2, skip;
      uintptr_t first_idx[8], first_lr[8], first_n;
    } View317;
    extern const void *nx_msg317_rec_ptr(void);
    const View317 *v = (const View317 *)nx_msg317_rec_ptr();
    if (v && v->calls) {
      bs("[xd] msg317 calls="); bdec((long long)v->calls, 0, '0', 0, 0);
      bs(" skip="); bdec((long long)v->anom, 0, '0', 0, 0);
      bs(" idx=");  bdec((long long)v->idx, 0, '0', 0, 0);
      bs(" data="); bhex((u64)v->data, 16);
      bs(" count="); bdec((long long)v->count, 0, '0', 0, 0);
      bs(" cap=");  bdec((long long)v->cap, 0, '0', 0, 0);
      bs(" data2="); bhex((u64)v->data2, 16);
      bs(" obj=");  bhex((u64)v->obj, 16);
      bs(" a=");    bhex((u64)v->a, 16);
      bs(" b=");    bhex((u64)v->b, 16);
      bs(" lr=");   bhex((u64)v->caller, 16);
      bs("\n");
      for (uintptr_t i = 0; i < v->first_n && i < 8; i++) {
        bs("[xd] msg317 call"); bdec((long long)i, 0, '0', 0, 0);
        bs(" idx="); bdec((long long)v->first_idx[i], 0, '0', 0, 0);
        bs(" lr=");  bhex((u64)v->first_lr[i], 16);
        bs("\n");
      }
      if (v->obj && xd_readable(v->obj, 0x50)) xd_dump_range("L317", v->obj, 0x50);
      if (v->data && xd_readable(v->data, 0x40)) xd_dump_range("D317", v->data, 0x40);
    }
  }
  bs("[xd] ============== END EXCEPTION DUMP ==============\n");

  xd_finish();
  xd_sync();   /* #324: same reason -- the tail must exist before svcBreak */

  /* re-raise so the process still aborts and Atmosphere writes its report */
  svcBreak(BreakReason_Panic, 0, 0);
  for (;;) svcSleepThread(1000000000ULL);
}
