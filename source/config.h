/* config.h -- The Room: Old Sins Switch wrapper configuration
 * (forked from the The Room Three port, itself from the PvZ Fusion /
 *  Zookeeper DX / CR3 lineage.)
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

/* ============================ MEMORY LAYOUT ==============================
 * These are engine-fitting parameters, not game content -- identical to the
 * Zookeeper DX port because PvZ Fusion is the SAME Unity minor version
 * (2022.3.62) and we apply the SAME 256MB->64MB region-granularity patch
 * (see nx_patch_os.h). Do not change unless you know the allocator math.
 * ======================================================================== */

// The engine + libc++ + il2cpp heap need a generous newlib heap; the rest of
// system memory is handed to the .so loader (see __libnx_initheap).
#define MEMORY_MB 768

// Anonymous-mmap arena. Unity reserves big region-aligned pools by over-mmapping
// then munmapping the unaligned head/tail. We back anonymous mmaps from a
// dedicated, region-aligned arena with a per-page used-bitmap so sub-range
// munmap frees exactly the trimmed pages. Region granularity is 64MB to match
// the libunity patch.
#define MMAP_ARENA_ALIGN    ((size_t)64 * 1024 * 1024)
/* 64MB, matching the region granularity libunity is patched to in
 * nx_patch_os.h section 1 (22 sites, region shift 28 -> 26). These two
 * numbers are ONE decision -- if OS_PATCH_WORDS_N is ever set back to 0 this
 * must return to 256MB, and vice versa. A mismatch means the arena hands back
 * regions the allocator then overlaps; the reference port recorded exactly
 * that failure (16MB -> corrupted Dynamic Heap at init, null-prev free-list
 * crash), so 64MB is also the known-good floor -- do not go lower. */
#define MMAP_ARENA_RESERVE  ((size_t)0)   // Build #291: arena DISABLED. Census proves it serves NOTHING (arena=0 in #289 and #290) -- the 64 MB was pure heap overhead. With reserve 0, __libnx_initheap leaves g_mmap_arena_base NULL and the newlib heap gains 64 MB. WARNING: a NULL base used to trigger mmap_arena_init_locked's 768 MB memalign fallback -- #291 guards that in libc_shim.c (early return), so all mmaps fall through to mmap_fallback (newlib memalign per request).

// Stack-region overcommit (OC) arena (see libc_shim.c): PROT_NONE reservations
// held in a stack-region window, committed pages backed from a small heap pool.
#define OC_WINDOW_BYTES     ((size_t)2048 * 1024 * 1024)  // 32x64MB cheap PROT_NONE reservation. Was 1536; the window-finder clamps to the largest stack-region hole (min(this, hole)), so raising the cap lets a run use its full hole and spill fewer reservations into the (real-memory) arena.
// Commit-pool: real memory backing touched pages of the OC window. Unity is told it
// has 512 MB (libc_shim.c __sysconf PHYS_PAGES + dalvik.vm.heapsize), and it reserves
// its heaps as big PROT_NONE regions that route here, so this pool must be able to
// back the full 512 MB Unity believes it has -- at 256 MB the scene load exhausted it
// (~270 MB working set) and the next uncommitted page faulted -> hard OOM crash.
// #289: the measured peak is 329 MB (booting run #284), so 384 MB suffices -- the
// "full 512" claim above was conservative inheritance, superseded by the MEASURED
// note below.
// malloc. UPDATE 2: trimming the pool 1280->1024 + arena 1024->512 fixed the malloc
// OOM (malloc 1409 -> game pushed past the null-buffer crash) but 512 starved the
// arena (see above). Final balance within the ~2945 MB (newlib+arena) budget:
// pool 896 + arena 896 + malloc 1153. Each sits ~1.6-1.8x above its known failure
// point (pool live 551 / arena fail 512 / malloc fail 641). If one OOMs again the
// log names which knob to grow.
/* OC commit-pool (touched pages only). NO LONGER INHERITED TUNING -- MEASURED.
 *
 * Was 896 MB, carried over as 1.6x PvZ Fusion's 551 MB working set, with the
 * note that The Room Three "is a far smaller title, so this should be generous" and
 * that the value could only be settled on hardware. It has now been settled:
 * across three boots, including one that reached the title screen and menus,
 * the pool peaked at
 *
 *     218 MB, 218 MB, 240 MB   (of 896)
 *
 * so 896 was ~3.7x the real working set. 512 was 2.1x the observed peak --
 * still generous for a title whose peak moved only 22 MB between a short
 * boot and a long one -- and returned 384 MB to the newlib heap.
 *
 * Build #289: 512 -> 384. The later booting run (#284, title screen) peaked
 * at 329 MB committed, so 384 is 1.17x that peak -- 55 MB of headroom -- and
 * returns another 128 MB to the newlib heap, which together with the arena
 * shrink below funds one more 256 MB fallback block. The margin is thin by
 * design: the game stalls for lack of fallback blocks long before it would
 * commit past 329 MB, and if a future run's "[oc] committed" line ever
 * approaches this cap, raise it -- the log prints pool usage on every
 * commit, so it is directly observable.
 *
 * That matters because the pool is `memalign(0x1000, OC_POOL_BYTES)` out of the
 * SAME newlib heap the GPU arena reserves from, so this is the memory that
 * funds GPUA_BYTES at 1080p (imports_os_extra.c). If a future title stalls or
 * the "[oc] committed" line ever approaches this cap, raise it -- the log
 * prints pool usage on every commit, so it is directly observable. */
#define OC_POOL_BYTES       ((size_t)384 * 1024 * 1024)

/* Graphics-driver headroom, held back from the newlib heap.
 *
 * __libnx_initheap took everything except the stock 0x200000 (2 MB).
 * switch-mesa and the nouveau/nvidia layer allocate GPU memory from the SAME
 * process pool -- NOT from our GPU arena, which only ever sees what comes
 * through memalign. A single 1920x1080 RGBA swapchain buffer is ~8 MB, so a
 * 2 MB margin means the driver gets whatever happened to be left over.
 *
 * This is what killed 1080p. Our boot log reports
 *     [probe] mem total=3189 MB used=3185 MB free=3 MB
 * and the process then died INSIDE eglSwapBuffers on the first 1920x1080
 * present -- a driver allocation failing in the compositor path, which takes
 * the system down rather than returning an error we could see. The GPU arena
 * being 90% empty at the time was irrelevant: wrong pool.
 *
 *     1920x1080 = 7.9 MB/buffer  (23.7 MB triple-buffered)
 *     1280x720  = 3.5 MB/buffer  (10.5 MB triple-buffered)
 *
 * which is why 720p survived on scraps and 1080p did not.
 *
 * 192 MB covers a triple-buffered 1080p swapchain, the game's render textures,
 * GPU command buffers and texture staging, with margin. Taken straight from the
 * CloverPit port, which runs 1920x1080 in handheld on this exact value -- proof
 * that the compositor downscales a 1080p buffer to the 720p panel quite happily
 * once the driver can actually allocate it.
 *
 * If the game later OOMs on the MANAGED side instead, this is the knob to trade
 * back. Note we also freed 384 MB by right-sizing OC_POOL_BYTES above, so newlib
 * is still ahead of where it was. */
/* THE ROOM THREE: raised 192 -> 256 (INHERITED -- see note below).
 *
 * 192 was the Deus Ex GO value and it is already the post-fix number -- the
 * "stopped claiming memory" change is INHERITED here, not something still to
 * do. If 1080p still fails on this title, the driver simply needs more than
 * DXGO did, which is plausible: this game ships ~1.19 GB of assets against
 * DXGO's ~300 MB, so more is resident at any moment, and 1080p costs 2.25x the
 * pixels of 720p across the swapchain and every render target.
 *
 * Budget at 1080p, for the allocations that come from the PROCESS POOL rather
 * than the GPU arena:
 *     triple-buffered swapchain   1920*1080*4*3  = 23.7 MB
 *     depth/stencil               1920*1080*4    =  8.3 MB
 *     engine render targets                      ~ 8-20 MB
 *     nvmap handles, command buffers, staging    ~ tens of MB
 * 256 MB leaves comfortable headroom over that without being reckless.
 *
 * COST: newlib loses 64 MB. That is affordable here -- right-sizing
 * OC_POOL_BYTES from 896 to 512 already returned 384 MB, so newlib is still
 * well ahead of where it was before either change.
 *
 * IF THIS IS THE WRONG POOL, the log says so plainly; do not guess, the DXGO
 * port lost three rounds to exactly that:
 *   [probe] mem total=.. used=.. free=N MB   <- N is what the driver may use.
 *                                              Small N (single/low double
 *                                              digits) => raise this constant.
 *                                              Healthy N => the fault is
 *                                              elsewhere, leave it alone.
 *   [gpua] GPU arena reserved: X MB (asked 1152 MB)
 *                                           <- X < asked means newlib could not
 *                                              hand over a contiguous block:
 *                                              this constant is now TOO HIGH.
 * If the game instead OOMs on the managed side, trade back down. */
/* Build #346: 192 -> 96. #345 finally OOM'ed on the MANAGED side, which the
 * note above says to answer by trading this constant back down. Its last lines
 * are
 *     [fb316] memalign FAILED: 53772 KB ... heap 2723/50 MB, free-chunks 44922
 *             top-chunk 8 KB, blocks 33/1474 MB
 *     [mmap] arena FULL and newlib fallback FAILED for 52 MB (out of RAM)
 * i.e. the 52 MB FMOD bank needed ONE contiguous block and the heap held 50 MB
 * in 44922 pieces with an 8 KB top chunk. #342 (same scene, 7270 frames, no
 * crash) had 99 MB free at that moment and its 52 MB block landed right after
 * the 107 MB libil2cpp.so map. 96 MB more newlib puts a 96 MB top chunk at the
 * end of the heap, which is what that request needs.
 *
 * The check the note above asks for says the driver can afford it:
 *     [probe] mem total=3189 MB used=2993 MB free=195 MB
 * 195 MB free is nowhere near the "small N => raise this constant" warning, and
 * this keeps ~99 MB, still above the 1080p swapchain + depth + render targets
 * budget listed above (~60-80 MB). If the next log shows GPU allocation
 * failures instead, this line is the one to put back. */
/* Build #350: 96 -> 48. #349 finally got past the resource failures (Cores=3,
 * Memory=512mb, zero "is missing"), and the next managed-side OOM is the FMOD
 * bank, exactly as the note above predicts:
 *     [mem150] ... newlib used 2603 MB free 77 MB
 *     [mmap] fallback 53772 KB ...   <- the jar entry buffer for Master.bank
 *     Unity: BankLoadException: ... ERR_MEMORY
 * The 52 MB jar buffer leaves ~25 MB, and FMOD's own ~54 MB copy of the bank
 * then has nowhere to go. 48 MB more newlib (plus 18 MB from shrinking the
 * asset read cache 24 -> 6 MB) puts ~140 MB free at that point. The driver
 * keeps 147 MB (was 195 MB), still above the ~60-80 MB listed above. If a
 * later log shows GPU allocation failures, put this back to 96. */
#define GFX_RESERVE_MB      48u

// Overcommit (alias-region) mode: reserve a big *virtual* window (PROT_NONE
// costs only address space) and commit physical pages on demand -- true
// overcommit, matching Android.
#define MMAP_VIRT_RESERVE   ((size_t)6144 * 1024 * 1024)  // 6 GB virtual reservation window
#define OVERCOMMIT_HEAP_MB  608u                          // newlib malloc + .so load zone

/* ============================ GAME IDENTITY =============================== */

// PvZ Fusion ships the engine as the standard modern Unity trio; libmain.so
// dlopens libunity.so which dlopens libil2cpp.so. (No libcrx/MVGL here -- this
// is a normal IL2CPP game, so main.c loads libmain/libunity/libil2cpp directly
// and these SO_NAME macros are unused, kept only for parity with the base.)
#define SO_NAME      "libunity.so"
#define SO_CPP_NAME  "libil2cpp.so"

// The SD-card folder holding the .nro + the game files.
#define GAME_FOLDER  "aota"

/* The Android package this build reports to game code. Real value, from the
 * game's Play Store listing: com.Diamondhenge.ArcaneAttorneyF (Diamondhenge
 * Entertainment). Unity's getPackageName() and any plugin reading it must see
 * the real package. */
#define GAME_PACKAGE "com.Diamondhenge.ArcaneAttorneyF"

/* Unity's AndroidJavaObject reflection bridge (ReflectionHelper.getMethodID ->
 * java.lang.reflect.Method -> FromReflectedMethod -> jmethodID). Serving it lets
 * managed code actually reach the game's Java plugins; with it off those calls
 * silently no-op, which is how the port behaved before and is a safe fallback if
 * the reflection path misbehaves. */
/* Full-screen movie playback. REQUIRED for this title.
 *
 * CORRECTION -- AN EARLIER REVISION OF THIS FILE HAD THIS AT 0, AND IT WAS
 * WRONG. The reasoning was: grep the game's own assembly in dump.cs
 * (Assembly-CSharp, TypeDefIndex 0..3220) for PlayFullScreenMovie /
 * ShowVideoPlayer / VideoPlayer, find zero hits, conclude there is no movie
 * path. Both halves of that were bad method:
 *
 *   - dump.cs lists DECLARATIONS, not call sites. Handheld.PlayFullScreenMovie
 *     is declared in UnityEngine.CoreModule.dll, so it can never appear inside
 *     the Assembly-CSharp line range no matter how often the game calls it.
 *   - IL2CPP string literals do not live in dump.cs at all. They live in
 *     global-metadata.dat, which was not being read.
 *
 * WHAT THE EVIDENCE ACTUALLY SHOWS, from assets/bin/Data/Managed/Metadata/
 * global-metadata.dat and from the game's own binaries:
 *
 *   "Ending.mp4"                          literal @0x2e000
 *   "Eyeball_argument.mp4"                literal @0x2ef49
 *   "4-3"                                 literal (the only aspect-ratio folder;
 *                                         no "16-9" anywhere, same as R3)
 *   "FullScreenMovieControlMode.Full"     @0x8bdc85
 *   "FullScreenMovieScalingMode.AspectFit" @0x8bdcae
 *   "FIN_VideoCanvas"                     GameObject name
 *
 * and both clips are on disk at assets/4-3/ (32.7 MB for the two).
 *
 * The caller is iOSVideoManager (yes, on Android -- it is the game's own
 * cross-platform wrapper, [AddComponentMenu("Common/Video/iOS Video Manager")]).
 * PlayMovie / PlayMovieCustomFade store the name, and FadeCallback
 * (libil2cpp +0x7FAC18) makes the actual call:
 *
 *     ldr  x0, [x19, #0x20]!        ; VideoName
 *     ldp  s0, s1, [x19, #0x14]     ; FadeColour (Color, 4 floats)
 *     ldp  s2, s3, [x19, #0x1c]
 *     csel w2, w8, wzr, lo          ; ScalingMode
 *     cinc w1, w20, eq              ; ControlMode
 *     bl   #0x19924bc               ; Handheld::PlayFullScreenMovie
 *
 * which on Android reaches UnityPlayerJavaWrapper::ShowVideoPlayer ->
 * UnityPlayer.showVideoPlayer -> android.media.MediaPlayer. None of that exists
 * here, so jni_fake.c answers the JNI call itself and routes the path to
 * os_video.c, which decodes with ffmpeg. libunity is not patched at all.
 *
 * Requires switch-ffmpeg (see the Makefile). Setting this to 0 makes os_video.c
 * compile to empty stubs, drops the ffmpeg dependency, and skips the clips --
 * a legitimate build if you do not want the dependency, but you lose two
 * cutscenes, so do it knowingly rather than by default. */
#define OS_VIDEO 0   /* v1: video playback stubbed (skipped). Set to 1 + install
                      * switch-ffmpeg if the game needs its cutscenes. */

/* Decode ceiling. A clip larger than this is downscaled by swscale, YUV to YUV,
 * on the decode thread. This title's two clips are 4:3 and well under the
 * ceiling, so swscale never runs -- these exist as a safety valve. If a
 * graphics allocation starts failing during an ending, halve them before
 * touching anything else.
 *
 * CPU-side buffers are not the concern: three staging slots at this size are
 * about 9 MB. */
#define OS_VIDEO_MAX_W 1920
#define OS_VIDEO_MAX_H 1080

/* ffmpeg frame threads for the video decoder. The console gives homebrew three
 * cores and our own decode thread already occupies one, so 2 is the honest
 * default; 1 disables threading entirely if a decoder turns out unstable with
 * it. Ignored if switch-ffmpeg was built without pthreads. */
#define OS_VIDEO_DECODE_THREADS 2

#define OS_JNI_REFLECTION 1

#define CONFIG_NAME "config.txt"
#define LOG_NAME    game_path("debug.log")

// Returned for getenv("HOME")/getpwuid()->pw_dir. Point it at the (writable)
// game data root instead of letting the engine deref a NULL passwd.
/* ---- game root -----------------------------------------------------------
 * Resolved at runtime by game_root.c: the folder holding the .nro, else any
 * folder under sdmc:/switch that contains an install, else sdmc:/switch/
 * GAME_FOLDER. GAME_FOLDER is now only the fallback name, not a requirement.
 *
 * DATA_ROOT is a char array rather than a literal, so `"%s", DATA_ROOT` works
 * unchanged but `DATA_ROOT "/sub"` no longer compiles -- use game_path("sub"),
 * which returns a rotating static buffer (safe to use twice in one call). */
extern char g_game_root[512];
const char *game_path(const char *relative);
const char *game_root(void);
void game_root_resolve(int argc, char *argv[]);

#define GAME_HOME   ((const char *)g_game_root)
#define DATA_ROOT   GAME_HOME

// flip to 1 (and rebuild) to get file logging (debug.log) for on-hardware debugging
#define DEBUG_LOG 1   /* ON: writes debug.log next to the .nro */

/* #288: futex fake-wake escalation. An "infinite" FUTEX_WAIT on an address
 * that nobody ever writes or wakes is the black-screen livelock in wake.log
 * (FAKEWAKE on the same address every ~10 ms, forever). With this at 1 such a
 * wait reports a real ETIMEDOUT after 16 consecutive 10 ms fake-wakes instead
 * of claiming it was woken, so the caller's own timeout path gets control.
 * Set to 0 to restore the pre-#288 "a fake wake always reports success"
 * behaviour for an A/B boot: the zero is the only behavioural revert in #288
 * (the counter-first pulse and the tick-paced vsync thread are independent). */
#define OS_FUTEX_TIMEOUT_ESCALATE 1
/* MUST stay 1 until the port boots. With this at 0 the crash handler in
 * nx_exception_dump.c still runs and still calls svcBreak, but every line it
 * writes -- pc/far/esr, all 29 registers, the frame-pointer backtrace -- is
 * compiled out, so a crash leaves nothing behind but Atmosphere's report, which
 * captures registers at the svcBreak rather than at the fault and is therefore
 * all zeroes. debugPrintf already fflush()es per line, so the log survives a
 * hard crash; the only reason one would be missing is this switch. */

/* High-volume per-operation traces. These were invaluable for the black-screen /
 * boot-hang triage but are catastrophic for load speed once the game runs: every
 * every archive read/lseek and most mprot calls fflush two lines to the SD card, so
 * a synchronous scene load (~1700 bundle reads) takes minutes instead of seconds
 * and looks like a hang. Keep them OFF for normal play; flip to 1 to re-trace. */
#define TRACE_BUNDLE_IO 0   /* per-read/lseek trace of the main archive */
#define TRACE_MPROT     0   /* per-mprotect commit trace */

extern int screen_width;
extern int screen_height;

/* ----------------------------- Language ----------------------------------
 * The Room: Old Sins shipped a broad language set. The game reads locale through
 * AndroidJavaClass -> our jni_fake getLanguage()/java.util.Locale, so these
 * indices map to the 2-letter token lang_code() returns. 0 follows the Switch
 * system language. If this build expects different tokens, edit lang_code()
 * in jni_fake.c -- see PORTING.md section 5.                                */
#define LANG_AUTO 0
#define LANG_EN   1
#define LANG_FR   2
#define LANG_DE   3
#define LANG_ES   4
#define LANG_IT   5
#define LANG_PT   6
#define LANG_RU   7
#define LANG_JA   8
#define LANG_KO   9
#define LANG_ZH   10

/* No orientation field: the port renders landscape only, matching The Room: Old Sins'
 * Android build. CONFIRM this against your APK's AndroidManifest.xml
 * (android:screenOrientation on the activity) before you build -- a portrait
 * title rendered landscape gives a black screen that looks like a render bug,
 * not a layout bug. The retired `portrait` knob is dropped from any existing
 * config.txt on next launch. */
typedef struct {
  int handheld_res; /* render height in handheld: 720 or 1080 */
  int docked_res;   /* render height when docked:  720 or 1080 */
  int framerate;    /* 30 or 60 */
} Config;

extern Config config;

int read_config(const char *file);
int write_config(const char *file);


/* ---- app identity reported to game code -----------------------------------
 * Surfaced as PackageInfo.versionName / versionCode and hence
 * UnityEngine.Application.version.
 *
 * THE ROOM THREE HAD A REMOTE VERSION GATE. THIS TITLE DOES NOT.
 * That port had to report a truthful versionName because
 * Deca.RemoteVersioning.RemoteVersioningConfig::ValidateAppVersion compared
 * Application.version against a remote minimum and raised an "out of date"
 * popup on failure. Searching this game's own assembly for the same surface
 * (RemoteVersioning, ValidateAppVersion, MinVersion, an UPDATED popup) finds
 * nothing -- Old Sins does not self-version-check.
 *
 * So this value is cosmetic here. It is left as a placeholder deliberately
 * rather than guessed, because a wrong-but-plausible number is worse than an
 * obvious one if anything downstream (analytics, crash keys) ever reads it.
 *
 * To set it truthfully from your own copy:
 *     aapt dump badging base.apk | grep -E "versionName|versionCode"
 * It is NOT recoverable from classes.dex -- every BuildConfig.VERSION_NAME in
 * there belongs to a third-party library.
 * -------------------------------------------------------------------------- */
#define APP_VERSION_NAME "1.0.0"   /* placeholder -- no version gate in this title */
#define APP_VERSION_CODE 999999    /* still unknown; nothing observed reads it */

#endif
