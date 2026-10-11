/* aaudio_shim.c -- minimal AAudio implementation for FMOD on Switch.
 *
 * Attorney of the Arcane ships FMOD (libfmod.so) which opens its output via
 * the Android AAudio API (dlopens libaaudio.so at runtime and dlsyms the
 * entry points). There is no AAudio on Switch, so this file implements the
 * subset FMOD actually uses (~27 functions, enumerated by scanning
 * libfmod.so's string table for AAudio* names) on top of the SDL queue-mode
 * audio device already provided by opensles.c (audio_fmod_open/write).
 *
 * Model: AAudio's data-callback. FMOD registers a callback via
 * AAudioStreamBuilder_setDataCallback; on requestStart we spawn a thread that
 * periodically invokes it to fill a PCM buffer, then queues the buffer via
 * audio_fmod_write(). All the getters return the stored (or sensible default)
 * stream parameters. Anything FMOD doesn't use is a stub returning AAUDIO_OK.
 *
 * Registered into the dynlib export table (see imports.c) so FMOD's
 * dlsym("AAudio_...") resolves. dlopen("libaaudio.so") itself is already
 * faked by libc_shim.c.
 *
 * MIT, same as the rest of the loader.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <switch.h>

#include "opensles.h"   /* audio_fmod_open / audio_fmod_write */
#include "util.h"       /* debugPrintf */

/* --- AAudio types (subset) ------------------------------------------------ */
typedef int32_t aaudio_result_t;
typedef int32_t aaudio_direction_t;
typedef int32_t aaudio_format_t;
typedef int32_t aaudio_stream_state_t;
typedef struct AAudioStreamStruct *AAudioStream;
typedef struct AAudioStreamBuilderStruct *AAudioStreamBuilder;

#define AAUDIO_OK                            0
#define AAUDIO_ERROR_INVALID_STATE         (-5)

#define AAUDIO_DIRECTION_OUTPUT              0
#define AAUDIO_DIRECTION_INPUT               1

#define AAUDIO_FORMAT_PCM_I16                1
#define AAUDIO_FORMAT_PCM_FLOAT              2

#define AAUDIO_STREAM_STATE_UNINITIALIZED    0
#define AAUDIO_STREAM_STATE_STARTED         10
#define AAUDIO_STREAM_STATE_STOPPED         12

#define AAUDIO_CALLBACK_RESULT_CONTINUE      0
#define AAUDIO_CALLBACK_RESULT_STOP          1

typedef int (*AAudioStream_dataCallback)(AAudioStream *stream, void *userData,
                                         void *audioData, int32_t numFrames);
typedef void (*AAudioStream_errorCallback)(AAudioStream *stream, void *userData,
                                           aaudio_result_t error);

/* --- stream object -------------------------------------------------------- */
#define AAUDIO_SHIM_FRAMES 512

typedef struct AAudioStreamStruct {
  int32_t  sampleRate;      /* e.g. 48000 */
  int32_t  channelCount;   /* e.g. 2 */
  int32_t  format;         /* AAUDIO_FORMAT_* */
  int32_t  framesPerBurst; /* callback chunk */
  int32_t  direction;
  int32_t  deviceId;
  int32_t  state;
  AAudioStream_dataCallback dataCb;
  void                    *dataCbUser;
  AAudioStream_errorCallback errCb;
  void                    *errCbUser;
  /* callback pump thread */
  Thread   pump;
  volatile int pumpRun;
  int16_t *pcmBuf;         /* S16 interleaved scratch */
} AAudioStreamRec;

typedef struct AAudioStreamBuilderStruct {
  int32_t sampleRate;
  int32_t channelCount;
  int32_t format;
  int32_t direction;
  int32_t deviceId;
  int32_t bufferCapacity;
  AAudioStream_dataCallback dataCb;
  void *dataCbUser;
  AAudioStream_errorCallback errCb;
  void *errCbUser;
} AAudioStreamBuilderRec;

/* --- pump thread: drive FMOD's data callback into the SDL queue ------------ */
static void aaudio_pump_main(void *arg) {
  AAudioStreamRec *s = (AAudioStreamRec *)arg;
  const int frames = s->framesPerBurst > 0 ? s->framesPerBurst : AAUDIO_SHIM_FRAMES;
  const int bytesPerFrame = s->channelCount * (int)sizeof(int16_t);
  const int bufBytes = frames * bytesPerFrame;
  /* Pace to realtime: frames / sampleRate seconds per chunk. */
  uint64_t nsPerChunk = (uint64_t)frames * 1000000000ull / (uint64_t)(s->sampleRate > 0 ? s->sampleRate : 48000);
  if (nsPerChunk < 1000000ull) nsPerChunk = 1000000ull;

  debugPrintf("[aaudio] pump start: %d Hz %d ch, %d frames/chunk\n",
              s->sampleRate, s->channelCount, frames);
  while (s->pumpRun) {
    uint64_t t0 = armGetSystemTick();
    memset(s->pcmBuf, 0, (size_t)bufBytes);
    int rc = AAUDIO_CALLBACK_RESULT_CONTINUE;
    if (s->dataCb)
      rc = s->dataCb((AAudioStream *)s, s->dataCbUser, s->pcmBuf, frames);
    if (rc == AAUDIO_CALLBACK_RESULT_STOP) break;
    audio_fmod_write(s->pcmBuf, bufBytes);
    /* Sleep the remainder of the chunk period (crude pacing is fine; the SDL
     * queue absorbs jitter). */
    uint64_t dt = armTicksToNs(armGetSystemTick() - t0);
    if (dt < nsPerChunk)
      svcSleepThread(nsPerChunk - dt);
  }
  debugPrintf("[aaudio] pump stop\n");
}

/* --- builder --------------------------------------------------------------- */
aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder *builder) {
  if (!builder) return AAUDIO_ERROR_INVALID_STATE;
  AAudioStreamBuilderRec *b = calloc(1, sizeof(*b));
  if (!b) return AAUDIO_ERROR_INVALID_STATE;
  b->sampleRate   = 48000;
  b->channelCount = 2;
  b->format       = AAUDIO_FORMAT_PCM_I16;
  b->direction    = AAUDIO_DIRECTION_OUTPUT;
  *builder = (AAudioStreamBuilder)b;
  return AAUDIO_OK;
}

aaudio_result_t AAudioStreamBuilder_delete(AAudioStreamBuilder builder) {
  free(builder);
  return AAUDIO_OK;
}

aaudio_result_t AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder b, int32_t id) {
  if (b) { ((AAudioStreamBuilderRec *)b)->deviceId = id; } return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setDirection(AAudioStreamBuilder b, aaudio_direction_t dir) {
  if (b) { ((AAudioStreamBuilderRec *)b)->direction = dir; } return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setFormat(AAudioStreamBuilder b, aaudio_format_t fmt) {
  if (b) { ((AAudioStreamBuilderRec *)b)->format = fmt; } return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setChannelMask(AAudioStreamBuilder b, uint32_t mask) {
  /* Derive channel count from mask population count. */
  if (b) {
    int n = 0; for (uint32_t m = mask; m; m >>= 1) n += (m & 1);
    if (n > 0) ((AAudioStreamBuilderRec *)b)->channelCount = n;
  }
  return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setSampleRate(AAudioStreamBuilder b, int32_t rate) {
  if (b && rate > 0) { ((AAudioStreamBuilderRec *)b)->sampleRate = rate; } return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setBufferCapacityInFrames(AAudioStreamBuilder b, int32_t n) {
  if (b) { ((AAudioStreamBuilderRec *)b)->bufferCapacity = n; } return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setDataCallback(AAudioStreamBuilder b,
    AAudioStream_dataCallback cb, void *userData) {
  if (b) { ((AAudioStreamBuilderRec *)b)->dataCb = cb; ((AAudioStreamBuilderRec *)b)->dataCbUser = userData; }
  return AAUDIO_OK;
}
aaudio_result_t AAudioStreamBuilder_setErrorCallback(AAudioStreamBuilder b,
    AAudioStream_errorCallback cb, void *userData) {
  if (b) { ((AAudioStreamBuilderRec *)b)->errCb = cb; ((AAudioStreamBuilderRec *)b)->errCbUser = userData; }
  return AAUDIO_OK;
}
/* Stubs FMOD sets but whose values we ignore. */
aaudio_result_t AAudioStreamBuilder_setPerformanceMode(AAudioStreamBuilder b, int32_t m) { (void)b; (void)m; return AAUDIO_OK; }
aaudio_result_t AAudioStreamBuilder_setUsage(AAudioStreamBuilder b, int32_t u)            { (void)b; (void)u; return AAUDIO_OK; }
aaudio_result_t AAudioStreamBuilder_setInputPreset(AAudioStreamBuilder b, int32_t p)      { (void)b; (void)p; return AAUDIO_OK; }
aaudio_result_t AAudioStreamBuilder_setSharingMode(AAudioStreamBuilder b, int32_t m)      { (void)b; (void)m; return AAUDIO_OK; }

/* --- stream ---------------------------------------------------------------- */
aaudio_result_t AAudioStreamBuilder_openStream(AAudioStreamBuilder builder, AAudioStream *stream) {
  if (!builder || !stream) return AAUDIO_ERROR_INVALID_STATE;
  AAudioStreamBuilderRec *b = (AAudioStreamBuilderRec *)builder;
  AAudioStreamRec *s = calloc(1, sizeof(*s));
  if (!s) return AAUDIO_ERROR_INVALID_STATE;
  s->sampleRate   = b->sampleRate > 0 ? b->sampleRate : 48000;
  s->channelCount = b->channelCount > 0 ? b->channelCount : 2;
  s->format       = b->format;
  s->direction    = b->direction;
  s->deviceId     = b->deviceId;
  s->framesPerBurst = AAUDIO_SHIM_FRAMES;
  s->state        = 1; /* open */
  s->dataCb       = b->dataCb;
  s->dataCbUser   = b->dataCbUser;
  s->errCb        = b->errCb;
  s->errCbUser    = b->errCbUser;
  s->pcmBuf = malloc((size_t)s->framesPerBurst * s->channelCount * sizeof(int16_t));
  debugPrintf("[aaudio] openStream: %d Hz %d ch fmt=%d\n", s->sampleRate, s->channelCount, s->format);
  *stream = (AAudioStream)s;
  return AAUDIO_OK;
}

aaudio_result_t AAudioStream_requestStart(AAudioStream stream) {
  AAudioStreamRec *s = (AAudioStreamRec *)stream;
  if (!s) return AAUDIO_ERROR_INVALID_STATE;
  int rate = audio_fmod_open(s->sampleRate, s->channelCount);
  if (!rate) {
    debugPrintf("[aaudio] requestStart: audio device failed\n");
    return AAUDIO_ERROR_INVALID_STATE;
  }
  s->sampleRate = rate;
  s->pumpRun = 1;
  Result rc = threadCreate(&s->pump, aaudio_pump_main, s, NULL, 0x4000, 0x2C, -2);
  if (R_FAILED(rc)) {
    debugPrintf("[aaudio] requestStart: threadCreate failed\n");
    s->pumpRun = 0;
    return AAUDIO_ERROR_INVALID_STATE;
  }
  threadStart(&s->pump);
  s->state = AAUDIO_STREAM_STATE_STARTED;
  return AAUDIO_OK;
}

aaudio_result_t AAudioStream_requestStop(AAudioStream stream) {
  AAudioStreamRec *s = (AAudioStreamRec *)stream;
  if (!s) return AAUDIO_ERROR_INVALID_STATE;
  s->pumpRun = 0;
  threadWaitForExit(&s->pump);
  threadClose(&s->pump);
  s->state = AAUDIO_STREAM_STATE_STOPPED;
  return AAUDIO_OK;
}

aaudio_result_t AAudioStream_close(AAudioStream stream) {
  AAudioStreamRec *s = (AAudioStreamRec *)stream;
  if (!s) return AAUDIO_OK;
  if (s->state == AAUDIO_STREAM_STATE_STARTED)
    AAudioStream_requestStop(stream);
  free(s->pcmBuf);
  free(s);
  return AAUDIO_OK;
}

/* --- getters (FMOD polls these) -------------------------------------------- */
int32_t  AAudioStream_getSampleRate(AAudioStream s)          { return s ? ((AAudioStreamRec *)s)->sampleRate : 48000; }
int32_t  AAudioStream_getChannelCount(AAudioStream s)        { return s ? ((AAudioStreamRec *)s)->channelCount : 2; }
int32_t  AAudioStream_getFormat(AAudioStream s)              { return s ? ((AAudioStreamRec *)s)->format : AAUDIO_FORMAT_PCM_I16; }
int32_t  AAudioStream_getFramesPerBurst(AAudioStream s)      { return s ? ((AAudioStreamRec *)s)->framesPerBurst : AAUDIO_SHIM_FRAMES; }
int32_t  AAudioStream_getBufferCapacityInFrames(AAudioStream s) { (void)s; return AAUDIO_SHIM_FRAMES * 4; }
int32_t  AAudioStream_getBufferSizeInFrames(AAudioStream s)  { (void)s; return AAUDIO_SHIM_FRAMES * 2; }
int32_t  AAudioStream_getDeviceId(AAudioStream s)            { return s ? ((AAudioStreamRec *)s)->deviceId : 0; }
aaudio_stream_state_t AAudioStream_getState(AAudioStream s)  { return s ? ((AAudioStreamRec *)s)->state : AAUDIO_STREAM_STATE_UNINITIALIZED; }
int64_t  AAudioStream_getXRunCount(AAudioStream s)           { (void)s; return 0; }
aaudio_result_t AAudioStream_setBufferSizeInFrames(AAudioStream s, int32_t n) { (void)s; (void)n; return AAUDIO_OK; }
aaudio_result_t AAudioStream_waitForStateChange(AAudioStream s, aaudio_stream_state_t from,
    aaudio_stream_state_t *to, int64_t timeoutNs) {
  (void)timeoutNs;
  if (s && to) { *to = ((AAudioStreamRec *)s)->state; (void)from; }
  return AAUDIO_OK;
}
/* Blocking I/O (FMOD uses callback mode for output; stub for completeness). */
aaudio_result_t AAudioStream_read(AAudioStream s, void *buf, int32_t frames, int64_t timeoutNs) {
  (void)s; (void)buf; (void)frames; (void)timeoutNs; return 0;
}
