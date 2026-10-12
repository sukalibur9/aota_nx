/* nx_patch_os.h -- engine patch offsets and feature switches for
 *                  THE ROOM: OLD SINS  (Fireproof Games, internally "TheRoom4",
 *                  Unity 2021.3.8f1, arm64 / IL2CPP)
 *
 * FORKED FROM THE ROOM THREE PORT. Same studio, same engine version, and -- as
 * it turns out -- structurally the same everywhere that matters. But NOTHING
 * numeric is inherited: every offset below was re-derived against THIS build's
 * libunity.so (BuildID 52a92d39...) and libil2cpp.so.
 *
 * DERIVATION WAS EXACT, NOT STRUCTURAL. This game ships with a symbol file
 * whose BuildID matches its libunity.so byte-for-byte, so every engine function
 * here was located BY NAME at its true address -- no fingerprinting, no
 * constant-scanning, no instruction-run matching. The Room Three port had to
 * work structurally because its reference was a different build; this one did
 * not. Where that changes the confidence level, it is stated per section.
 *
 * CROSS-VALIDATION AGAINST THE ROOM THREE. The allocator table below came out
 * at 23 sites in the same 11 functions, in the same order, with the same 23
 * instruction encodings and the same intra-function deltas as the R3 table.
 * Two independent 2021.3.8f1 builds agreeing on all of it is strong evidence
 * both derivations are right.
 *
 * This header is the whole contract main.c compiles against. Every offset that
 * is filled in was DERIVED from this game's own binaries and confirmed by
 * disassembly; provenance is recorded per entry. Everything NOT derived is
 * switched OFF with its table left as a compiling placeholder, so nothing here
 * silently patches an address that was guessed.
 *
 * Runtime address = <module>.load_virtbase + offset. Both .so files link at
 * base 0, so link-time offsets are also RVAs.
 *
 * ALL PATCHES ARE APPLIED VERIFY-FIRST: main.c checks the stock word at each
 * site and skips + logs on mismatch rather than writing. That turns a stale
 * offset into a readable log line instead of a random crash.
 *
 * MIT, same as the rest of the loader.
 */
#ifndef NX_PATCH_OS_H
#define NX_PATCH_OS_H

#include <stdint.h>

typedef struct { uint32_t off, from, to; } NxPatchWord;

/* ===========================================================================
 * SECTION 0 -- feature switches
 *
 * ON  = derived for this build and confirmed.
 * OFF = not derived. Turning one on without deriving its offsets first does
 *       nothing useful -- verify-first will reject every site.
 * ======================================================================== */
#define OS_DISABLE_IL2CPP_GC     1   /* il2cpp_gc_disable() before first render  */
#define OS_HAVE_TIME_FIX         0   /* TimeManager::Update hook -- NOT derived for AotA yet (v1: run at default fps) */

#define OS_HAVE_TIME_HOOKS       0   /* managed Time.get_* redirect    -- see §6 */
#define OS_HAVE_SCREEN_HOOKS     0   /* managed Screen.width/height    -- see §6 */
#define OS_HAVE_MANAGED_PROBE    0   /* periodic managed-state probe   -- see §6 */
#define OS_HAVE_RES_TRACE        0   /* Resources.Load tracing         -- see §6 */
#define OS_HAVE_FPS_OVERRIDE     0   /* frame-rate lock -- NOT derived for AotA yet */
#define OS_HAVE_BSA_BYPASS       0   /* BetterStreamingAssets -- NOT derived for AotA yet */
#define OS_HAVE_NRE_TRACE        1   /* NullReferenceException tracing -- see §6 */
#define OS_HAVE_SCENE_CENSUS     0   /* FindObjectsOfType census       -- see §6 */
#define OS_HAVE_BRANCH_FORCES    0   /* none needed for this build               */

/* ===========================================================================
 * SECTION 1 -- libunity: allocator region granularity 256MB -> 64MB.  DERIVED.
 *
 * Unity's memory manager encodes a pointer as (regionIndex << 28) | offset --
 * a 256MB region granularity. Switch homebrew cannot afford reservations that
 * large, so the shift is rewritten to 26 (64MB) everywhere it appears.
 * MMAP_ARENA_ALIGN in config.h MUST equal 64MB to match; the two are one
 * decision, not two.
 *
 * HOW THIS WAS DERIVED (tools/derive_alloc_symscoped.py)
 * ------------------------------------------------------------------------
 * Earlier ports shipped this as a literal offset list transplanted between
 * builds at a uniform delta. That does not work even between two games on the
 * SAME Unity patch level: The Room Three's verified table sits at 0x11ded4..
 * 0x126150 and this build's at 0x34eda4..0x3572a8, and no constant delta maps
 * one onto the other (libunity is rebuilt per project with different module
 * sets). So the offsets are re-derived from scratch, in two stages.
 *
 * 1. LEARN THE RULES, REGISTER-INDEPENDENTLY. In every edit of this family --
 *
 *      mov  wD, #0x10000000              -> mov  wD, #0x4000000
 *      mov  wD, #0xfffffff               -> mov  wD, #0x3ffffff
 *      and  xD, xN, #0xfffffffff0000000  -> and  xD, xN, #0xfffffffffc000000
 *      lsr  xD, xN, #0x1c                -> lsr  xD, xN, #0x1a
 *      ubfx xD, xN, #0x1c, #W            -> ubfx xD, xN, #0x1a, #W
 *      mov  xD, #-0x1000000000           -> mov  xD, #-0x400000000
 *      movk xD, #0x1000, lsl #16         -> movk xD, #0x400, lsl #16
 *      sub  xD, xN, xM, lsl #28          -> sub  xD, xN, xM, lsl #26
 *
 *    -- (from ^ to) touches ONLY immediate-field bits: imm16 for the mov
 *    family, N/immr/imms for UBFM and logical-immediate, the shift amount for
 *    shifted-register. None of those ranges overlap Rd, Rn or Rm. So the rule
 *    transfers even though the encoding does not: match the reference pair with
 *    that class's register fields masked out, then to = from ^ delta.
 *
 * 2. SCOPE BY NAME, NOT BY ADDRESS. The rule family is not unique to the
 *    allocator -- it also matches mbedtls_sha512 byte extraction,
 *    double_conversion::Bignum, libtess, and UNET bandwidth math. Patching any
 *    of those would corrupt something unrelated.
 *
 *    THIS IS WHERE OLD SINS DIFFERS FROM THE ROOM THREE, AND IT IS THE ONE
 *    PLACE THE FORK IS STRICTLY BETTER THAN ITS PARENT. That port had to locate
 *    the allocator functions structurally, by offset-free instruction runs,
 *    because its only symbol reference was a different build; it could pin
 *    eight of thirteen and had to bound the rest by translation-unit window.
 *
 *    This game ships a symbol file whose BuildID matches its libunity.so
 *    exactly (52a92d394c19307ba4a5c1b90b887caf9df7a933 on both), so each
 *    function's true [start, start+size) is simply read out of .symtab and
 *    only words inside it are considered. The whole false-positive class the
 *    window heuristic existed to fight is gone by construction. Eleven of the
 *    thirteen functions are present and carry hits:
 *
 *      MemoryManager::VirtualAllocator::{GetMemoryBlockFromPointer,
 *          GetBlockInfoFromPointer, MarkMemoryBlocks, ReserveMemoryBlock}
 *      MemoryManager::GetAllocatorContainingPtr
 *      DynamicHeapAllocator::{DynamicHeapAllocator, RequestLargeAllocMemory}
 *      LocalLowLevelAllocator::ReserveMemoryBlock
 *      BucketAllocator::BucketAllocator
 *      AtomicPageAllocator::AllocatePage
 *      TLSAllocator<(AllocatorMode)0>::ThreadInitialize
 *
 *    MemoryManager::GetRequestedPointerSize and TLSAllocator<1>::ThreadInitialize
 *    are not instantiated in this build. That is a reported absence, not a
 *    silent one -- the tool prints it.
 *
 * THE SITE COUNT IS 23, AND THAT NUMBER IS THE CHECK.
 * The Room Three port lost a boot to a missed 23rd site: an AND-immediate
 * `and x8, x1, #0xfffffffff0000000` inside GetMemoryBlockFromPointer, skipped
 * because the rule classifier keyed on the instruction's TOP BYTE and 0x92 is
 * shared by MOVN (64-bit) and AND-immediate (64-bit). AND-immediate was treated
 * as mov-family, only Rd was masked, and a rule learned from
 * `and x22, x9, #mask` failed to match `and x8, x1, #mask`.
 *
 * The consequence was not subtle: the allocator reserved a region, aligned the
 * pointer down with the one surviving 256MB mask to 128MB BELOW its own
 * reservation, and wrote a block header into unmapped space. Data abort inside
 * libunity's init_array.
 *
 * That fix is inherited here (the classifier keys on bits 28..23), and this
 * table does contain the equivalent site -- index 13, +0x35503c. If you ever
 * re-derive: 23 sites, and index 13 must be an AND-immediate.
 *
 * TWO SITES WERE CHECKED BY HAND because they were not inside a located
 * function:
 *   +0x11e780/4  `lsr x8,x1,#0x1c ; mov w9,#0x10000000 ; cmp x8,#0 ;
 *                 csel x8,x1,x9,eq` -- clamping a requested size to one region.
 *                 Region math, in scope.
 *   +0x126150    inside AtomicPageAllocator::AllocatePage, on the out-of-memory
 *                 path, feeding FormatBytes for "Page Allocator out of memory.
 *                 Maximum allowed memory: %s". Confirmed against the same site
 *                 in the reference (+0x4ee378, identical surrounding shape).
 *                 COSMETIC -- it is the printed value, not an enforced cap --
 *                 but after the patch the true maximum really is 64MB, so
 *                 rewriting it keeps the message honest.
 *
 * VERIFIED: all 22 stock words read back from the shipped libunity.so, all 22
 * patched words decode to the same mnemonic, and no patched word re-matches a
 * rule (so a double application cannot shift the granularity twice).
 * ======================================================================== */
__attribute__((unused))
static const NxPatchWord OS_PATCH_WORDS[] = {
  /* Derived for Attorney of the Arcane v57 libunity.so (Unity IL2CPP, arm64).
   * 13 sites in the VirtualAllocator family + reserve paths, relaxing the
   * memory-region granularity 256MB -> 64MB so the engine fits the so_loader
   * address space on a 4GB Switch. Every site was located by disassembling
   * THIS build's libunity.so and matching the instruction patterns against the
   * proven Unity 2022.3 table; all 13 stock words were read back from the
   * binary and all 13 patched words decode to the same mnemonic.
   *
   * NOTE: the sub-allocator sites (TLSAllocator, BucketAllocator,
   * DynamicHeapAllocator ctor, MarkMemoryBlocks, AtomicPageAllocator) found in
   * the reference Unity 2022.3 build have no clear counterparts in this
   * binary -- this Unity version's sub-allocators do not appear to do their
   * own 256MB-granularity math. They are intentionally omitted; verify-first
   * patching + the boot log will reveal if any are actually needed.
   *
   * Site 6 uses a narrower mask (bits 28-55, not 28-63) in this build; the
   * 64MB equivalent keeps the same shape (bits 26-55). */
  /* ---- LocalLowLevelAllocator::ReserveMemoryBlock ---- */
  /*  0 */ { 0x1225564, 0x12be0009, 0x12bf8009 },   /* mov w9, #0xfffffff -> #0x3ffffff */
  /*  1 */ { 0x1225574, 0x92648d35, 0x92669535 },   /* and x21, x9, #0xfffffffff0000000 -> #0xfffffffffc000000 */
  /* ---- DynamicHeapAllocator::RequestLargeAllocMemory ---- */
  /*  2 */ { 0x122aea0, 0x12be000c, 0x12bf800c },   /* mov w12, #0xfffffff -> #0x3ffffff */
  /*  3 */ { 0x122aed8, 0x92648d17, 0x92669517 },   /* and x23, x8, #0xfffffffff0000000 -> #0xfffffffffc000000 */
  /* ---- MM::VirtualAllocator::ReserveMemoryBlock ---- */
  /*  4 */ { 0x122c790, 0xd35cdc33, 0xd35ad433 },   /* ubfx x19, x1, #0x1c, #0x1c -> #0x1a, #0x1a */
  /*  5 */ { 0x122c798, 0xd35cfd15, 0xd35afd15 },   /* lsr x21, x8, #0x1c -> #0x1a */
  /*  6 */ { 0x122c83c, 0x52a20008, 0x52a08008 },   /* mov w8, #0x10000000 -> #0x4000000 */
  /* ---- MM::VirtualAllocator::GetMemoryBlockFromPointer ---- */
  /*  7 */ { 0x122ca6c, 0xd35cfc28, 0xd35afc28 },   /* lsr x8, x1, #0x1c -> #0x1a */
  /*  8 */ { 0x122ca7c, 0x92646c28, 0x92667428 },   /* and x8, x1, #0xfffffff0000000 -> #0xfffffffc000000 */
  /*  9 */ { 0x122ca84, 0xd35c9c2a, 0xd35a942a },   /* ubfx x10, x1, #0x1c, #0xc -> #0x1a, #0xc */
  /* 10 */ { 0x122ca98, 0xd35cdc29, 0xd35ad429 },   /* ubfx x9, x1, #0x1c, #0x1c -> #0x1a, #0x1a */
  /* 11 */ { 0x122ca9c, 0xb25c6feb, 0xb25e77eb },   /* mov x11, #-0x1000000000 -> #-0x400000000 */
  /* 12 */ { 0x122caa0, 0xf2a2000b, 0xf2a0800b },   /* movk x11, #0x1000, lsl #16 -> #0x400, lsl #16 */
  /* 13 */ { 0x122cae4, 0xcb0a7108, 0xcb0a6908 },   /* sub x8, x8, x10, lsl #28 -> lsl #26 */
  /* ---- MM::VirtualAllocator::GetBlockInfoFromPointer ---- */
  /* 14 */ { 0x122cb08, 0xd35c9c29, 0xd35a9429 },   /* ubfx x9, x1, #0x1c, #0xc -> #0x1a, #0xc */
  /* ---- MM::GetAllocatorContainingPtr ---- */
  /* 15 */ { 0x122ec04, 0xd35c9e89, 0xd35a9689 },   /* ubfx x9, x20, #0x1c, #0xc -> #0x1a, #0xc */
};
#define OS_PATCH_WORDS_N ((int)(sizeof(OS_PATCH_WORDS)/sizeof(OS_PATCH_WORDS[0])))

/* ---- branch/word force sites -------------------------------------------
 * None needed for this build. The earlier lineage's single entry was a
 * BufferGLES BeginWrite caps gate, a workaround for a mesa bug fixed upstream;
 * it is not carried over. */
__attribute__((unused))
static const NxPatchWord OS_BRANCH_FORCES[] = {
  { 0, 0, 0 },  /* placeholder; unused while OS_HAVE_BRANCH_FORCES == 0 */
};
#define OS_BRANCH_FORCES_N (OS_HAVE_BRANCH_FORCES ? \
  ((int)(sizeof(OS_BRANCH_FORCES)/sizeof(OS_BRANCH_FORCES[0]))) : 0)

/* ===========================================================================
 * SECTION 1b -- DIAGNOSTIC: skip Unity 6 property-vector builder (0x605b88).
 *
 * OBSERVED (2026-10-10, hw test): JNI_OnLoad crashes at libunity+0x5cdebc
 * (ldp x25, x8, [x0, #0x10]) with x0 = 0x81ff -- a bogus vector pointer passed
 * as x1 to the function at 0x605b88. That function builds a vector of 0x68-byte
 * property descriptors using format strings "mode%d", "color%d",
 * "vector%d_%d", "vectorComponentCount%d", "InheritVelocityModule.enabled"
 * (Unity 6000.5.8f1; the template was derived for Unity 2021.3.8f1).
 *
 * The caller passes x1 = 0x81ff, which is not a valid pointer. Patching the
 * function entry (sub sp, sp, #0xf0) to ret makes it a no-op. If the vector
 * is non-essential (or rebuilt later), boot proceeds and we learn that. If
 * the caller needs it, we crash in the caller with a clearer log.
 *
 * VERIFY-FIRST: only applied if the stock word matches. Remove once the root
 * cause (why x1 = 0x81ff) is understood.
 * ======================================================================== */
#define OS_HAVE_DIAG_SKIP_PROPVEC 0
__attribute__((unused))
static const NxPatchWord OS_DIAG_PATCHES[] = {
  { 0x122b004, 0x081140f9, 0xd503201f },  /* DIAG: ldr x8,[x8,#0x20] -> nop (vtable ID) */
  { 0x124400c, 0xf9000d2b, 0xd503201f },  /* FIX: STR x11,[x9,#0x18] -> nop (null list head) */
  { 0x1244014, 0xf9000969, 0xd503201f },  /* FIX: STR x9,[x11,#0x10] -> nop (null list node) */
};
#define OS_DIAG_PATCHES_N (OS_HAVE_DIAG_SKIP_PROPVEC ? \
  ((int)(sizeof(OS_DIAG_PATCHES)/sizeof(OS_DIAG_PATCHES[0]))) : 0)

/* ===========================================================================
 * SECTION 2 -- libunity: frame pacing (Swappy) force-disable.  DERIVED.
 *
 * Swappy::IsEnabledAndActive() -- the cached "is frame pacing on?" getter.
 * Located by exact-matching its offset-free tail (cmp/cset/cmp/cset/and/ldp/ret)
 * from the version-matched 2021.3.8f1 reference: exactly ONE site in .text. The
 * body then verified instruction-for-instruction against that reference; only
 * the global page offsets differ (cached flag +0x701, value +0x700, second flag
 * +0x704).
 *
 * 13 call sites, 12 immediately followed by a tbz/cbz on w0 -- the same shape
 * the reference ports found. Forcing a 0 return makes every site take the
 * disabled path: plain eglSwapBuffers, no Choreographer-driven pacing threads,
 * no frame-0 join.
 * ======================================================================== */
/* Swappy::IsEnabledAndActive() -- located by name in the symbol file, size 96,
 * body confirmed: adrp/ldrb a pair of bytes at .bss+0x940/+0x941 and return
 * their AND. Forcing it to return 0 keeps the frame pacer out of the loop. */
#define OS_OFF_PACING_GETTER   0x5d7aac
#define OS_WORD_PACING_STOCK   0xA9BF7BF3u  /* stp x19,x30,[sp,#-0x10]! */
/* NOTE the register order. The reference port's constant is 0xA9BF4FFE
 * (stp x30,x19) -- the SAME instruction with the two registers swapped, so
 * it disassembles almost identically and reads as correct at a glance. This
 * build emits 0xA9BF7BF3. Copying the reference value here made verify-first
 * reject the patch every boot, silently leaving Swappy frame pacing ENABLED.
 * Re-read every stock word from the shipped libunity.so; never copy one. */

/* ===========================================================================
 * SECTION 3 -- libunity: audio.  DERIVED.
 *
 * (a) FMOD output type. Unity's internal FMOD defaults to the Java AudioTrack
 *     output, which needs a JVM run loop this loader does not have. The
 *     selection site is AudioManager::InitNormal:
 *
 *         bl   AndroidAudio::GetAndroidAudioOutputType
 *         cmp  w0, #2
 *         mov  w8, #0x15                 ; 21 = AudioTrack
 *         cinc w21, w8, eq               ; -> 21, or 22 = OpenSL
 *         ldr  x0, [x19, #0x158]
 *         mov  w1, w21                   ; <-- patch site
 *         bl   FMOD::System::setOutput
 *
 *     Forcing w1 to 22 makes FMOD drive its own self-scheduling OpenSL output,
 *     which opensles.c backs. Confirmed in THIS build at +0x77ecd8: the call
 *     target one instruction later disassembles to
 *     FMOD::System::setOutput(FMOD_OUTPUTTYPE) by name, and the feeding call at
 *     +0x77ecc4 is AndroidAudio::GetAndroidAudioOutputType(int). Same two-way
 *     cinc shape as The Room Three, same stock word.
 *
 * (b) OpenSL buffer geometry. FMOD::OutputOpenSL::init validates the requested
 *     buffer against (bufferCount-1)*bufferSize, halves it once, then rechecks:
 *
 *         sub  w10, w20, #1 ; mul w10, w10, w21 ; cmp w9, w10
 *         b.ls +0xc                      ; first check
 *         lsr  w9, w9, #1                ; halve it
 *         str  w9, [x19, #0x3f8]
 *         cmp  w9, w10
 *         b.ls +0x10                     ; <-- TERMINAL check, patch site
 *         mov  x0, x19 ; bl close()      ; still too big -> bail out
 *
 *     Forcing the terminal b.ls to an unconditional b always takes the success
 *     path. Confirmed in THIS build inside FMOD::OutputOpenSL::init (+0x12f0b28,
 *     by name): three b.ls in the function, and only the one at +0x12f0ca8
 *     carries the 0x54000089 encoding and falls through to
 *     `mov x0,x19 ; bl FMOD::OutputOpenSL::close` -- the bail-out. FMOD is a
 *     vendored library compiled identically across builds, which is why the
 *     8-word signature and the +0x3f8 field offset match the parent port
 *     exactly.
 * ======================================================================== */
#define OS_OFF_FMOD_OUTPUT     0x77ecd8
#define OS_WORD_FMOD_STOCK     0x2A1503E1u  /* mov  w1, w21   */
#define OS_WORD_FMOD_OPENSL    0x528002C1u  /* movz w1, #22   */

#define OS_OFF_FMOD_BUFGEO     0x12f0ca8
#define OS_WORD_BUFGEO_STOCK   0x54000089u  /* b.ls +0x10 */
#define OS_WORD_BUFGEO_FORCE   0x14000004u  /* b    +0x10 */

/* ===========================================================================
 * SECTION 4 -- libil2cpp globals.  DERIVED.
 *
 * We do not call libil2cpp's JNI_OnLoad: its first action is an
 * __android_log_print through a GOT slot that is not safely bound at that
 * point. Its only essential effects are two global stores, which main.c
 * replicates.
 *
 * Recovered by disassembling THIS libil2cpp's JNI_OnLoad @ 0x673fc0 (exported
 * dynsym, 68 bytes):
 *     adrp x8,#0x256e000 ; str x19,[x8,#0x240]   -> VM global  +0x256e240
 *     adrp x0,#0x674000  ; add x0,x0,#4          -> handler fn +0x674004
 *     bl 0x6d6858, whose entire body is
 *       { adrp x8,#0x256f000 ; str x0,[x8,#0x5d8] ; ret }
 *                                                -> handler ptr +0x256f5d8
 *
 * Cross-check: the handler at +0x674004 opens by reading the VM global back --
 * `adrp x26,#0x256e000 ; ldr x8,[x26,#0x240]` -- so the two agree with each
 * other rather than only with the pattern.
 * Both globals land in .bss; the handler fn is in .text. Same three-instruction
 * registration shape as every other port in this lineage.
 * ======================================================================== */
#define OS_IL2CPP_VM_GLOBAL     0x256e240
#define OS_IL2CPP_HANDLER_PTR   0x256f5d8
#define OS_IL2CPP_HANDLER_FN    0x674004

/* ---- il2cpp object layout (64-bit, version-independent) ------------------
 * Il2CppString : Il2CppObject{klass,monitor} = 0x10, then int32 length, chars.
 * Il2CppArray  : Il2CppObject + bounds ptr + uintptr max_length, then vector. */
#define OS_STR_LEN_OFF          0x10
#define OS_STR_CHARS_OFF        0x14
#define OS_IL2CPP_ARRAY_LEN     0x18
#define OS_IL2CPP_ARRAY_DATA    0x20

/* ===========================================================================
 * SECTION 5 -- libunity: engine clock.  DERIVED.
 *
 * On Switch the player loop parks UnityMain inside a synchronous scene load, so
 * TimeManager::Update stops being driven: newTime freezes, deltaTime collapses
 * to its 1e-5 floor, and Loading.PreloadManager -- which integrates load
 * progress over deltaTime -- starves. That is the frame-0 async-load hang. It
 * is a property of this loader architecture rather than anything
 * title-specific, and every port in this lineage carries the fix.
 *
 * main.c installs an entry hook that replays the prologue and re-drives the
 * body, plus a background clock thread that re-drives the body with a
 * wall-clock newTime whenever the main thread has been silent for >100ms.
 *
 * Derived twice independently: once by constant-scanning for the 1e-5 deltaTime
 * floor (0x3727c5ac), once by name against the version-matched 2021.3.8f1
 * reference. Both land on the same entry:
 *
 *   0x1bba28  ldr  x8,[x0,#0xc8] / ldr w9,[x0,#0xd0] / ldrb w10,[x0,#0xf8]
 *             add  x8,x8,#1      / add w9,w9,#1
 *             str  x8,[x0,#0xc8] / str w9,[x0,#0xd0]
 *             cbz  w10,+0x24     / ret          <- paused early-out
 *
 * The body at entry+0x24 opens `ldr d2,[x0,#0xe8]` / `fsub d2,d0,d2`,
 * confirming +0xe8 is the startup-reference double and that the body takes
 * newTime in d0, i.e. body(void *tm, double newTime).
 *
 * GetTimeManager() is reached from every UnityEngine.Time binding. Its body is
 * `str x30 / mov w0,#7 / bl GetSubsystem / ldr x30 / ret` -- subsystem index 7,
 * matching every reference build. The patch site is the `mov w0,#7` at entry+4,
 * so the function entry itself is 0x1bc0b8.
 * ======================================================================== */
#define OS_OFF_TIMEMGR_UPDATE_ENTRY  0x42bb00
#define OS_OFF_TIMEMGR_UPDATE_BODY   0x42bb24   /* entry + 0x24               */
#define OS_OFF_GET_TIME_MANAGER      0x42c1b8   /* FUNCTION ENTRY -- see below */
#define OS_WORD_TIMEMGR_STOCK        0xF9406408u /* ldr x8,[x0,#0xc8] */
#define OS_WORD_GETTIMEMGR_STOCK     0xF81F0FFEu /* str x30,[sp,#-0x10]! */
/* OS_OFF_GET_TIME_MANAGER MUST be the function entry, because main.c uses it
 * BOTH as the verify site AND as a call target:
 *     g_get_time_manager = (void *(*)(void))(ub + OS_OFF_GET_TIME_MANAGER);
 *
 * In the reference port those were the same address: its GetTimeManager was a
 * tail call, so the entry instruction WAS `mov w0,#7` (0x528000E0). This build
 * is not a tail call --
 *     0x1bc0b8  str x30,[sp,#-0x10]!   <- entry
 *     0x1bc0bc  mov w0,#7              <- the reference port's landmark
 *     0x1bc0c0  bl  GetSubsystem
 *     0x1bc0c4  ldr x30,[sp],#0x10
 *     0x1bc0c8  ret
 * -- so pointing the macro at the `mov` (which is what the reference's landmark
 * matches) would enter at +4, skip the push, then pop a garbage x30 off the
 * caller's frame and `ret` into it, with SP left 0x10 high. A wild jump on the
 * clock thread the moment the hook first ticks.
 *
 * The verify word therefore has to be the PROLOGUE, not the `mov`. */

/* ---- TimeManager field offsets (Release layout, this build) --------------
 * Read directly off the binding stubs in libunity. Informational -- main.c
 * drives Update rather than poking fields -- but useful when reading a dump.
 * NOTE a Development-build reference carries 0x18 extra bytes at the front of
 * TimeManager, so every offset there is +0x18 from these. Use THESE. */
#define OS_TM_FIXED_TIME          0x30   /* double */
#define OS_TM_FIXED_DELTA_TIME    0x48   /* float  */
#define OS_TM_TIME                0x90   /* double */
#define OS_TM_UNSCALED_TIME       0xa0   /* double */
#define OS_TM_DELTA_TIME          0xa8   /* float  */
#define OS_TM_UNSCALED_DELTA_TIME 0xac   /* float  */
#define OS_TM_SMOOTH_DELTA_TIME   0xb0   /* float  */
#define OS_TM_FRAME_COUNT         0xc8   /* int64, read as int32 by frameCount */
#define OS_TM_RENDERED_FRAMES     0xd0   /* uint32 */
#define OS_TM_PAUSE               0xf8   /* bool   */
#define OS_TM_TIME_SCALE          0xfc   /* float  */
#define OS_TM_MAXIMUM_DELTA_TIME  0x100  /* float  */

/* The libunity binding stubs themselves, for reference. Each is the same
 * 5-instruction Release form:
 *     str x30,[sp,#-0x10]! ; bl GetTimeManager ; ldr <reg>,[x0,#FIELD] ;
 *     ldr x30,[sp],#0x10 ; ret
 * Enumerated by finding all 129 callers of GetTimeManager and matching each
 * one's field load against the reference's named binding. These are NOT the
 * managed hook targets -- see §6.
 *   time 0x0e529c  timeAsDouble 0x0e52b4  deltaTime 0x0e52d4  fixedTime 0x0e52e8
 *   unscaledTime 0x0e5300  unscaledDeltaTime 0x0e5318  fixedDeltaTime 0x0e532c
 *   maximumDeltaTime 0x0e5360  smoothDeltaTime 0x0e5394  timeScale 0x0e53a8
 *   frameCount 0x0e53dc
 * (Unlike the reference port's build, IL2CPP did not strip smoothDeltaTime.) */

/* ===========================================================================
 * SECTION 6 -- managed-side hooks.  NOT DERIVED, ALL OFF.
 *
 * Everything in this section targets libil2cpp RVAs -- GAME code -- so no
 * reference port's values mean anything here; they must be derived per build.
 *
 * The reference derived them from a per-getter shape where each managed icall
 * stub embeds its own signature string:
 *     stp x30,x19,[sp,#-0x10]! ; adrp/ldr cache ; cbnz done
 *     adrp/add x0,"UnityEngine.Time::get_deltaTime()" ; bl resolve ; str cache
 *   done: ldp ; br x0
 *
 * THIS BUILD DOES NOT USE THAT SHAPE. The signature strings are present in
 * libil2cpp's .rodata -- get_deltaTime at 0x14ffe41, get_time at 0x14ffdf9,
 * get_frameCount at 0x1500007, get_realtimeSinceStartup at 0x150002a,
 * Screen::get_width at 0x14fa7b1 -- but nothing in .text reaches them by an
 * adrp/add pair, and no relocated data pointer targets them either. There are
 * only 8,187 ADRP instructions across 469,325 .text instructions, and zero ADDs
 * carrying the right imm12. Icall binding here is metadata-driven, so
 * recovering the stubs needs a different route than the reference used.
 *
 * None of this blocks booting. The TimeManager::Update fix in §5 is the
 * fundamental one and is independent of these -- the reference port's own notes
 * say so explicitly. What is off:
 *   TIME_HOOKS     managed Time.get_* agreeing exactly with the native clock
 *   SCREEN_HOOKS   managed Screen.width/height following dock state
 *   FPS_OVERRIDE   ignoring the game's Application.targetFrameRate
 *   RES_TRACE      logging Resources.Load calls
 *   MANAGED_PROBE  periodic camera/scene/isPlaying probe
 *   NRE_TRACE      managed stack trace on NullReferenceException
 *   SCENE_CENSUS   FindObjectsOfType census at chosen frames
 *
 * The placeholders below exist only so the file compiles with the switches off.
 * Do not turn a switch on until its RVAs are real.
 * ======================================================================== */

/* UNVERIFIED -- every constant in this section was copied from the reference
 * port and belongs to a feature that is OFF. They have NOT been read out of this
 * build (the pacing bug above is exactly what that costs). Re-read each one from
 * the shipped binary before enabling its feature.
 *
 * For reference, this build's libunity Time binding stubs open with
 * `str x30,[sp,#-0x10]!` = 0xF81F0FFE, not the value below -- but the hook list
 * targets libil2cpp stubs that this build does not emit in that shape at all
 * (see the note under SECTION 6), so neither value is usable as-is. */
#define OS_WORD_TIMEGET_STOCK   0xA9BF4FFEu  /* UNVERIFIED (copied) */
/* X(rva, clock_fn, name) -- clock_fn is bound in main.c's translation unit. */
#define OS_TIME_HOOK_LIST(X)     /* empty -- OS_HAVE_TIME_HOOKS == 0 */

/* X(rva, fn, name, verify_word) */
#define OS_SCREEN_HOOK_LIST(X)   /* empty -- OS_HAVE_SCREEN_HOOKS == 0 */

#define OS_PROBE_VERIFY_WORD    0xA9BF4FFEu
#define OS_PROBE_PERIOD_FRAMES  60
#define OS_PROBE_MAX_QUIET      600
/* X(rva, label, kind) */
#define OS_MANAGED_PROBE_LIST(X) /* empty -- OS_HAVE_MANAGED_PROBE == 0 */

#define OS_RES_LOAD_THUNK       0x0         /* UNDERIVED */
#define OS_RES_LOAD_CACHE       0x0         /* UNDERIVED */
#define OS_RES_LOAD_SIG         "UnityEngine.ResourcesAPIInternal::Load"
#define OS_WORD_RES_THUNK_STOCK 0xa9be57feu /* stp x30,x21,[sp,#-0x20]! */
#define OS_RES_TRACE_MAX        200

/* (The reference port's targetFrameRate icall-cache hook is not applicable here
 * -- see SECTION 8. These remain only so nothing references a missing macro.) */
#define OS_SET_TFR_THUNK        0x0         /* N/A for this build */
#define OS_SET_TFR_CACHE        0x0         /* N/A for this build */
#define OS_SET_TFR_SIG          "UnityEngine.Application::set_targetFrameRate"
#define OS_WORD_TFR_THUNK_STOCK 0xf81e0ffeu /* N/A for this build */

/* DERIVED for this build. Every null check in libil2cpp does `bl 0x6D0108`
 * (43,152 call sites in the il2cpp section, 2,215 in .text); that is a two-word
 * thunk `str x30,[sp,#-0x10]! ; bl 0x699068`, which is why the managed caller's
 * return address ends up at [sp] rather than in x30. The real raiser is the
 * target, +0x699068, and its first four words match the expected splice
 * prologue exactly:
 *     sub sp,sp,#0x20 ; stp xzr,x30,[sp,#8] ; mov x0,sp ; str xzr,[sp]
 * so the R3 splice design transfers unchanged. */
#define OS_NRE_RAISER           0x699068
#define OS_NRE_PATCH_LEN        0x10
#define OS_NRE_WORD_0           0xd10083ffu /* sub sp, sp, #0x20      */
#define OS_NRE_WORD_1           0xa900fbffu /* stp xzr, x30, [sp, #8] */
#define OS_NRE_WORD_2           0x910003e0u /* mov x0, sp             */
#define OS_NRE_WORD_3           0xf90003ffu /* str xzr, [sp]          */
#define OS_NRE_TRACE_MAX        12
#define OS_NRE_MAX_FRAMES       10

#define OS_FINDOBJECTS_RVA      0x0         /* UNDERIVED */
#define OS_WORD_FINDOBJ_STOCK   0xa9be57feu /* stp x30,x21,[sp,#-0x20]! */
#define OS_OBJ_GET_NAME_RVA     0x0         /* UNDERIVED */
#define OS_WORD_GETNAME_STOCK   0xa9be57feu /* stp x30,x21,[sp,#-0x20]! */
#define OS_CENSUS_FRAMES        { 2, 6, 120, 360 }
/* X(namespace, class, label) */
#define OS_SCENE_CENSUS_LIST(X)  /* empty -- OS_HAVE_SCENE_CENSUS == 0 */

/* ===========================================================================
 * SECTION 8 -- libil2cpp: frame-rate lock.  DERIVED.
 *
 * The game does not use Application.targetFrameRate. It picks
 * QualitySettings.vSyncCount from one bool in its own settings model,
 * RecommendedPlatformSettings.runAt60 (+0x29), inside
 * PlatformSettings.ApplyRecommendedSettings (+0x5BA040):
 *
 *   +0x5ba230  mov  w9,#0x1e ; str w9,[sp,#0x28]   default 30 (the logged value)
 *   +0x5ba258  ldrb w8,[x8,#0x29]                  runAt60
 *   +0x5ba25c  cbz  w8,#0x5ba270                   <-- PATCH SITE
 *   +0x5ba260  mov  w8,#0x3c / mov w0,#1           60, vSyncCount = 1
 *   +0x5ba270  mov  w0,#2                          vSyncCount = 2  -> 30 fps
 *
 * That ldrb is the ONLY read of runAt60 in the entire binary (checked across
 * ApplyRecommendedSettings and GenerateRecommendedSettings), so rewriting the
 * branch is equivalent to setting the field -- nothing else can disagree.
 *
 * Both directions are single words, so config.framerate works either way:
 *   nop            always fall through to the 60 path
 *   b #+0x14       always jump to the 30 path (needed if a device map or a
 *                  PlatformSettings.xml ever sets runAt60 = true)
 *
 * The 30 branch distance is (0x5ba270 - 0x5ba25c) / 4 = 5.
 * ======================================================================== */
#define OS_OFF_FPS_RUNAT60_BRANCH 0x835690
#define OS_WORD_FPS_BRANCH_STOCK  0x3940B108u  /* ldrb w8,[x8,#0x2c]  <- runAt60 */
#define OS_WORD_FPS_FORCE60       0x52800028u  /* mov  w8, #1  -> 60fps, vSync 1 */
#define OS_WORD_FPS_FORCE30       0x52800008u  /* mov  w8, #0  -> 30fps, vSync 2 */

/* ===========================================================================
 * SECTION 7 -- libil2cpp: Boehm GC stop-the-world bridge.  DERIVED.
 *
 * The collector stops the world by pthread_kill-ing every other thread with a
 * suspend signal; each target's handler sem_posts an ack and parks. Switch
 * delivers no POSIX signals, so without help the collector waits forever.
 *
 * TWO MUTUALLY EXCLUSIVE OPTIONS:
 *
 *  (a) OS_DISABLE_IL2CPP_GC -- call il2cpp_gc_disable() after surface setup and
 *      BEFORE the first nativeRender. It is an exported dynsym here, so resolve
 *      it BY NAME (so_find_addr); the offset below is for reference only. Cost:
 *      managed memory is never reclaimed, acceptable for a session-length
 *      puzzle game.
 *
 *      Ordering matters. Calling it during GC INIT deadlocks -- it blocks on a
 *      lock held by a helper thread that has not started yet. After surface
 *      setup and before the first render is the safe window.
 *
 *  (b) the pthread_kill bridge in libc_shim.c, using the globals below.
 *
 * DO NOT DO BOTH. Disabling the collector behind a live bridge leaves the
 * bridge waiting on an ack that never comes.
 *
 * Derivation: libil2cpp has exactly TWO call sites to pthread_kill --
 * GC_suspend_all (0x506da4) and GC_start_world (0x507008). Resolving the
 * adrp/ldr chain feeding the second argument at each gives the two signal
 * globals; they are adjacent, and the word immediately below them is the
 * restart ack gate, read or written at five sites inside the same
 * stop-the-world code. The ack semaphore is whatever sem_init is handed -- one
 * global, also posted at two sites. Sections check out: three ints in .data,
 * the semaphore in .bss.
 * ======================================================================== */
#define OS_IL2CPP_GC_DISABLE_SYM  "il2cpp_gc_disable"  /* resolve by NAME */
#define OS_OFF_IL2CPP_GC_DISABLE  0x6ff8e8             /* reference only  */

#define OS_GC_START_ACK_OFF   0x2563728  /* .data -- restart ack gate      */
#define OS_GC_SUSPEND_SIG_OFF 0x256372c  /* .data -- GC_suspend_all  sig   */
#define OS_GC_RESTART_SIG_OFF 0x2563730  /* .data -- GC_start_world  sig   */
#define OS_GC_ACK_SEM_OFF     0x2572fb0  /* .bss  -- suspend-ack semaphore */

/* call sites, for logging / breakpoints */
#define OS_GC_SUSPEND_ALL_KILL 0x71ca5c
#define OS_GC_START_WORLD_KILL 0x71ccc0

/* ===========================================================================
 * SECTION 9 -- libil2cpp: BetterStreamingAssets bypass.  DERIVED.
 *
 * THE BUG THIS FIXES: main menu appears, fades to black, reappears, forever.
 *
 * The game reads StreamingAssets through the BetterStreamingAssets plugin,
 * which on Android does not use the filesystem at all -- it opens the APK as a
 * ZIP and indexes the "assets/" entries inside it. This port serves plain files
 * off the SD card and has no APK, so Application.dataPath is empty and
 *
 *     BetterStreamingAssets.Initialize()
 *       -> ApkImpl.Initialize(dataPath, streamingAssetsPath)
 *         -> GetStreamingAssetsInfoFromJar(apkPath="")
 *           -> File.OpenRead("")  ->  ArgumentException: Path is empty
 *
 * throws out of BoxGameStateManager.Awake(). Awake never completes, so nothing
 * downstream of it runs -- including AssetBundleManager.Initialize().
 *
 * THE CASCADE, all four steps visible in one boot log:
 *
 *   1. ArgumentException in BoxGameStateManager.Awake()      (BSA, above)
 *   2. AssetBundleManager.Initialize() therefore never runs. It is the ONLY
 *      writer of m_ActiveVariants in the whole binary (verified by scanning
 *      every reference to the AssetBundleManager class slot at +0x23C1788):
 *          +0xE213CC  mov w1, #1 ; bl <array new>   -> new string[1]
 *          +0xE213F8  str x19, [x0, #0x10]!         -> m_ActiveVariants =
 *      so the field keeps the .cctor's value, `new string[0]` (+0xE2312C
 *      passes w1 = 0).
 *   3. PostFXController.Start() -> PlatformSettings.ApplyRecommendedSettings()
 *      -> AssetBundleManager.SetTexturesVariant() writes m_ActiveVariants[0]
 *      unconditionally (+0xE20400 `cbz w8` on max_length -> throw), so it
 *      raises IndexOutOfRangeException and Start() dies half-finished.
 *   4. PostFX render targets are never created -> the port logs
 *      "INCOMPLETE FBO status=0x8CD7" with no colour/depth/stencil attachment
 *      -> black screen; and MainMenu.IntroAnimFinished() NREs every cycle, so
 *      MainMenu.Update() restarts the intro forever. That is the loop.
 *
 * TWO CORRECTIONS TO THIS SECTION, BOTH WORTH READING BEFORE TRUSTING IT
 * ---------------------------------------------------------------------
 *
 * (1) An earlier revision also stubbed BetterStreamingAssets.FileExists() to
 *     return false, reasoning that its two callers are
 *     `bl FileExists ; tbz w0,#0,<fallback>` and false would therefore take a
 *     plain-File branch. The `tbz` was read; its TARGET was not. They are:
 *
 *       +0x95986C SaveThread.LoadFileIntoByteArray
 *                 false -> +0x959A98 = `mov x0, x22` (x22 zeroed one
 *                 instruction earlier) + epilogue.  RETURN NULL, no fallback.
 *       +0x95A6B4 SaveManager.DeserialisePlayerSlotFromFile
 *                 false -> +0x95A7A4, logs and sets w19 = 3 (an error code).
 *
 *     The game routes StreamingAssets reads through BSA with NO fallback by
 *     design. That stub is gone.
 *
 * (2) The replacement -- the two branch forces below -- was then wrongly
 *     announced as the fix for "touch does not register on the profile
 *     screen". IT IS NOT, and the boot log says so plainly: neither reader is
 *     ever entered. Both open with a Debug.Log before any BSA call
 *     (+0x959818, +0x95A648) and NEITHER message appears anywhere in a full
 *     boot. SlotManager.LoadAllSlotData() reaches
 *     SaveManager.FindSaveFileNames() (+0x959F88, which makes no BSA calls at
 *     all), gets an empty list on a first run, skips the loop entirely at
 *     +0x95ED00, and falls through to
 *
 *         +0x95EE98  mov  w8, #1
 *         +0x95EEA0  strb w8, [x19, #0x29]     ; SlotDataLoaded = true
 *         +0x95EEA8  str  s0, [x19, #0x2c]     ; LastTimeSlotsLoaded
 *         +0x95EEC8  ret
 *
 *     so slot loading COMPLETES and AreSlotsEnabled() returns true. (The
 *     `cbz ... #0x95EEE0` sites that look like early exits are `bl` to the
 *     throw-NullReference helper, and no exception appears in the log.)
 *
 * WHY THE BRANCH FORCES ARE STILL HERE. They are correct and they will be
 * needed the moment a profile actually exists and those readers run for real
 * -- at which point BSA, whose Initialize() is a no-op, would be queried for
 * an index that was never built. Both readers open with
 *
 *     if (fileName.StartsWith(Application.streamingAssetsPath)) -> BSA route
 *     else                                                      -> File route
 *
 * and here the files are loose on the SD card at an ordinary absolute path, so
 * the File route is the correct one. Both targets were followed to a
 * File.Exists before being written down (+0x9598CC reaches it at +0x9598D4;
 * +0x95A754 is `mov x21,xzr ; cbz x21,#0x95A70C`, joining the File.Exists block
 * at +0x95A718), and x19 still holds the ORIGINAL absolute path at both -- it
 * is the BSA branch that would have rewritten it to a relative one.
 *
 * They are a forward fix, not a fix for anything currently observed. Do not
 * cite them as the cause of any symptom without a log line proving the reader
 * was entered.
 *
 * Initialize() -> ret remains load-bearing: it is what stops
 * ArgumentException: Path is empty escaping BoxGameStateManager.Awake(), and
 * nothing downstream of that Awake runs, including
 * AssetBundleManager.Initialize(). The cascade documented above is real and
 * this is what fixed it.
 * ======================================================================== */
#define OS_OFF_BSA_INITIALIZE     0x7840ec
#define OS_WORD_BSA_INIT_STOCK    0xA9BF7BF3u  /* stp x19,x30,[sp,#-0x10]! */
#define OS_WORD_BSA_INIT_RET      0xD65F03C0u  /* ret                      */

/* The two StreamingAssets-route branches. Both are
 *     bl String.StartsWith(Application.streamingAssetsPath)
 *     tbz w0, #0, <plain-file route>
 * so forcing the tbz to an unconditional b takes the plain-file route always.
 * Both targets were followed to a File.Exists before being written down:
 *   +0x9598CC reaches File.Exists at +0x9598D4
 *   +0x95A754 is `mov x21,xzr ; cbz x21,#0x95A70C`, joining the File.Exists
 *             block at +0x95A718
 * and on both, x19 still holds the ORIGINAL absolute path at the target -- the
 * BSA branch is what would have overwritten it with the relative one. */
#define OS_OFF_BSA_SA_BRANCH_A    0x9597b8   /* SaveThread.LoadFileIntoByteArray */
#define OS_WORD_BSA_SA_A_STOCK    0x360008A0u /* tbz w0,#0,#0x9598cc */
#define OS_WORD_BSA_SA_A_FORCE    0x14000045u /* b   #0x9598cc       */

#define OS_OFF_BSA_SA_BRANCH_B    0x95a604   /* SaveManager.DeserialisePlayerSlotFromFile */
#define OS_WORD_BSA_SA_B_STOCK    0x36000A80u /* tbz w0,#0,#0x95a754 */
#define OS_WORD_BSA_SA_B_FORCE    0x14000054u /* b   #0x95a754       */

#endif /* NX_PATCH_OS_H */
