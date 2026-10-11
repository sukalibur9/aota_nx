/* aaudio_shim.h -- AAudio subset for FMOD (see aaudio_shim.c). */
#ifndef AAUDIO_SHIM_H
#define AAUDIO_SHIM_H

#include <stdint.h>

typedef int32_t aaudio_result_t;
typedef int32_t aaudio_stream_state_t;
typedef struct AAudioStreamStruct *AAudioStream;
typedef struct AAudioStreamBuilderStruct *AAudioStreamBuilder;

aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder *builder);
aaudio_result_t AAudioStreamBuilder_delete(AAudioStreamBuilder builder);
aaudio_result_t AAudioStreamBuilder_openStream(AAudioStreamBuilder builder, AAudioStream *stream);
aaudio_result_t AAudioStreamBuilder_setBufferCapacityInFrames(AAudioStreamBuilder b, int32_t n);
aaudio_result_t AAudioStreamBuilder_setChannelMask(AAudioStreamBuilder b, uint32_t mask);
aaudio_result_t AAudioStreamBuilder_setDataCallback(AAudioStreamBuilder b,
    int (*cb)(AAudioStream *s, void *u, void *d, int32_t n), void *userData);
aaudio_result_t AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder b, int32_t id);
aaudio_result_t AAudioStreamBuilder_setDirection(AAudioStreamBuilder b, int32_t dir);
aaudio_result_t AAudioStreamBuilder_setErrorCallback(AAudioStreamBuilder b,
    void (*cb)(AAudioStream *s, void *u, aaudio_result_t e), void *userData);
aaudio_result_t AAudioStreamBuilder_setInputPreset(AAudioStreamBuilder b, int32_t p);
aaudio_result_t AAudioStreamBuilder_setPerformanceMode(AAudioStreamBuilder b, int32_t m);
aaudio_result_t AAudioStreamBuilder_setUsage(AAudioStreamBuilder b, int32_t u);
aaudio_result_t AAudioStream_close(AAudioStream stream);
int32_t  AAudioStream_getBufferCapacityInFrames(AAudioStream s);
int32_t  AAudioStream_getBufferSizeInFrames(AAudioStream s);
int32_t  AAudioStream_getChannelCount(AAudioStream s);
int32_t  AAudioStream_getDeviceId(AAudioStream s);
int32_t  AAudioStream_getFormat(AAudioStream s);
int32_t  AAudioStream_getFramesPerBurst(AAudioStream s);
int32_t  AAudioStream_getSampleRate(AAudioStream s);
aaudio_stream_state_t AAudioStream_getState(AAudioStream s);
int64_t  AAudioStream_getXRunCount(AAudioStream s);
aaudio_result_t AAudioStream_read(AAudioStream s, void *buf, int32_t frames, int64_t timeoutNs);
aaudio_result_t AAudioStream_requestStart(AAudioStream stream);
aaudio_result_t AAudioStream_requestStop(AAudioStream stream);
aaudio_result_t AAudioStream_setBufferSizeInFrames(AAudioStream s, int32_t n);
aaudio_result_t AAudioStream_waitForStateChange(AAudioStream s, aaudio_stream_state_t from,
    aaudio_stream_state_t *to, int64_t timeoutNs);

#endif
