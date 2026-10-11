/* os_video.c -- full-screen movie playback for The Room Three's ending clips.
 *
 * WHY THIS IS NEEDED
 * ------------------
 * The Room: Old Sins shows two cutscenes with Handheld.PlayFullScreenMovie, the
 * legacy API -- NOT UnityEngine.Video. Its build contains no
 * UnityEngine.VideoModule.dll at all (checked against the 36 images in the
 * IL2CPP metadata), so there is no VideoPlayer to hook and no in-engine
 * fallback.
 *
 * On Android that API lands in UnityPlayerJavaWrapper::ShowVideoPlayer, which
 * attaches to the JVM and calls
 *
 *     com.unity3d.player.UnityPlayer.showVideoPlayer(String path, IIIZII) -> Z
 *
 * handing the whole job to android.media.MediaPlayer. There is no MediaPlayer
 * here, so without this the endings are simply skipped.
 *
 * That JNI call is the hook, and it is much cheaper than patching libunity: the
 * path arrives as the first argument, jni_fake.c intercepts it, and the engine
 * is told the video started. libunity is not modified at all.
 *
 * HOW IT PLAYS
 * ------------
 *   - os_video_play(path) opens the .mp4 and decodes it with ffmpeg on its own
 *     thread, publishing finished frames as packed YUV420 planes;
 *   - os_video_draw(), called from the eglSwapBuffers wrapper in
 *     unity_imports.c, uploads the newest frame into three GL_LUMINANCE
 *     textures and draws one letterboxed quad, converting YUV to RGB in the
 *     shader;
 *   - os_video_mix_audio() folds the clip's audio into the FMOD pump.
 *
 * The engine keeps running underneath, because ShowVideoPlayer does NOT block:
 * it makes the JNI call and returns the boolean (verified by disassembly -- the
 * only calls it makes are string handling, apkStat, the ScopedJNI attach, and
 * the JavaMethod<bool> invoke). On Android the game pauses only because the
 * video Activity comes to the front, which has no equivalent here. So this
 * draws over the top instead. If the game advances behind the clip, that is the
 * one behavioural difference from Android, and it is confined to the few
 * seconds of an ending cutscene.
 *
 * Everything degrades to the previous behaviour -- endings skipped, no hang --
 * if the file is missing, ffmpeg lacks the codec, or OS_VIDEO is 0.
 *
 * Decoder, GL upload/draw, colour handling and audio mixing are carried over
 * essentially unchanged from the CloverPit NX port (MIT, same lineage). What is
 * specific here is the trigger, and that the clip is named by an explicit path
 * rather than identified by duration from a manifest.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license. See the LICENSE file for details.
 */

#include "config.h"

/* Tripwire, for the same reason cloverpit_il2cpp.c has one: this file gates
 * almost everything on OS_VIDEO, and a missing config.h would silently compile
 * the entire feature out with no warning and no log line. tools/check_flags.sh
 * enforces the include; this catches it even if that is not run. */
#ifndef OS_VIDEO
#error "config.h not included -- the whole video path would compile out silently"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_video.h"
#include "util.h"

#if OS_VIDEO

#include <switch.h>
#include <pthread.h>
#include <sys/stat.h>

#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libswscale/swscale.h>
#include <libswresample/swresample.h>

#include "opensles.h"
#include "diag.h"

/* ------------------------------------------------------------------- clips */

/* CloverPit had to hunt its clips: they lived inside data.unity3d and were
 * identified by matching VideoClip.length against what the engine asked for.
 * None of that applies here -- showVideoPlayer hands us the exact path, and The
 * Room Three ships its endings as four ordinary .mp4 files:
 *
 *   assets/4-3/Ending.mp4          (16.2 MB)
 *   assets/4-3/Eyeball_argument.mp4 (18.1 MB)
 *
 * "4-3" is the only aspect-ratio folder in this build (the managed string
 * literals have "4-3" and no "16-9"), so both clips are 4:3 and the draw path
 * letterboxes it into the 16:9 framebuffer. */

static char s_game_root[256];
static int  s_inited;

void os_video_init(const char *game_root) {
  if (s_inited) return;
  snprintf(s_game_root, sizeof s_game_root, "%s", game_root ? game_root : ".");
  s_inited = 1;
  debugPrintf("[video] ready, root=%s (clips open by the path the engine passes "
              "to showVideoPlayer)\n", s_game_root);
}

/* ------------------------------------------------------------- frame slots */

/* Three slots is the minimum that lets the decoder always have somewhere to
 * write while the renderer holds one and a third stays published. The mutex is
 * held only across index arithmetic -- never across a memcpy, a GL call or a
 * decode -- so neither thread can stall the other for a measurable time. */
#define NSLOT 3

typedef struct {
  uint8_t *buf;        /* Y plane, then U, then V, each tightly packed */
  size_t   cap;
  int      w, h;       /* luma size; chroma is ((w+1)/2) x ((h+1)/2) */
  double   pts;
} VidSlot;

static VidSlot  s_slot[NSLOT];
static Mutex    s_lock;
static int      s_pub  = -1;     /* newest complete slot                    */
static int      s_hold = -1;     /* slot the render thread is reading       */
static uint32_t s_pub_serial;    /* bumped on publish, so draw can skip dups */

/* THESE MUST STAY volatile, and it matters more here than it did in the port
 * this came from. That one forced boot.config's gfx-threading-mode to 0, so
 * play, draw and decode all ran on one thread. THIS PORT DOES NOT -- nothing
 * rewrites gfx-threading-mode, so the engine may present from its own render
 * thread while the JNI hook that starts playback runs on the script thread.
 * The slot handshake below is therefore load-bearing rather than vestigial,
 * and these flags are genuinely read and written by different threads. */
static volatile int s_playing;   /* decode thread is alive and wants pixels */
static volatile int s_stop;      /* request the decode thread to unwind     */
static volatile int s_eof;       /* clip finished on its own                */
static volatile uint64_t s_eof_tick;

static pthread_t s_thread;
static int       s_thread_live;

/* Audio bookkeeping. Written by the decode thread, read by the pump; ints, and
 * only ever monotonic, so no lock is warranted. */
static volatile int s_audio_sink_rate;   /* 0 = playing silent */
static volatile unsigned s_audio_mixed_blocks;

static uint64_t tick_ns(void) {
  return armTicksToNs(armGetSystemTick());
}

/* ------------------------------------------------------------ audio bridge */

/* DELIBERATELY A NO-OP IN THIS PORT, and it must stay one.
 *
 * The clip's PCM is already reaching the speakers: the decode thread pushes it
 * with opensles_movie_queue(), and opensles.c's SDL device callback mixes that
 * ring into the same accumulator as the engine's own OpenSL players --
 * mix_movie(acc, frames), right after the mix_player() loop. That path is
 * live here because the FMOD patches force FMOD onto its OpenSL output, so our
 * opensles.c IS the sink.
 *
 * The port this came from re-routed movie audio into the FMOD pump instead,
 * because its OpenSL path was not the active sink. Doing both would drain the
 * SAME ring from two threads: each would get roughly half the frames, and the
 * clip would play back garbled and short. Wire one or the other, never both.
 *
 * Kept rather than deleted so the FMOD pump's call site stays valid and the
 * reasoning survives next to the thing it is about. */
int os_video_mix_audio(short *dst, int frames, int channels) {
  (void)dst; (void)frames; (void)channels;
  return 0;
}

int os_video_is_playing(void) { return s_playing; }

/* ------------------------------------------------------------- in-memory IO */

typedef struct { const uint8_t *p; int size; int pos; } MemBuf;

static int mem_read(void *o, uint8_t *buf, int n) {
  MemBuf *m = o;
  int left = m->size - m->pos;
  if (left <= 0)
    return AVERROR_EOF;
  if (n > left)
    n = left;
  memcpy(buf, m->p + m->pos, (size_t)n);
  m->pos += n;
  return n;
}

static int64_t mem_seek(void *o, int64_t off, int whence) {
  MemBuf *m = o;
  if (whence == AVSEEK_SIZE)
    return m->size;
  if (whence == SEEK_END)      off += m->size;
  else if (whence == SEEK_CUR) off += m->pos;
  if (off < 0)        off = 0;
  if (off > m->size)  off = m->size;
  m->pos = (int)off;
  return m->pos;
}

/* ---------------------------------------------------------------- decoding */

typedef struct {
  char     path[400];    /* file to open: either videos/<override> or the .resource */
  uint64_t offset, size; /* size 0 => read the whole file (override case) */
  char     label[96];
} DecodeArgs;

static DecodeArgs s_args;

/* Take a slot the renderer is not reading and the publisher has not published.
 * Always succeeds with NSLOT >= 3. */
static int slot_acquire(void) {
  int got = -1;
  mutexLock(&s_lock);
  for (int i = 0; i < NSLOT; i++)
    if (i != s_pub && i != s_hold) { got = i; break; }
  mutexUnlock(&s_lock);
  return got;
}

static void slot_publish(int i) {
  mutexLock(&s_lock);
  s_pub = i;
  s_pub_serial++;
  mutexUnlock(&s_lock);
}

static int slot_reserve(VidSlot *s, int w, int h) {
  const size_t cw = (size_t)((w + 1) / 2), ch = (size_t)((h + 1) / 2);
  const size_t need = (size_t)w * (size_t)h + cw * ch * 2;
  if (s->cap < need) {
    free(s->buf);
    s->buf = malloc(need);
    s->cap = s->buf ? need : 0;
  }
  s->w = w;
  s->h = h;
  return s->buf != NULL;
}

/* Copy an AVFrame's planes into the slot with no row padding. GLES2 has no
 * GL_UNPACK_ROW_LENGTH, so the pack has to happen somewhere; doing it here
 * keeps it off the render thread and costs one memcpy per row. */
static void slot_fill(VidSlot *s, AVFrame *fr) {
  const int w = s->w, h = s->h;
  const int cw = (w + 1) / 2, chh = (h + 1) / 2;
  uint8_t *dst = s->buf;
  for (int y = 0; y < h; y++)
    memcpy(dst + (size_t)y * w, fr->data[0] + (size_t)y * fr->linesize[0], (size_t)w);
  dst += (size_t)w * h;
  for (int y = 0; y < chh; y++)
    memcpy(dst + (size_t)y * cw, fr->data[1] + (size_t)y * fr->linesize[1], (size_t)cw);
  dst += (size_t)cw * chh;
  for (int y = 0; y < chh; y++)
    memcpy(dst + (size_t)y * cw, fr->data[2] + (size_t)y * fr->linesize[2], (size_t)cw);
}

/* Colour conversion constants, resolved once per clip and handed to the shader.
 * Written by the decode thread before the first publish, read by the renderer
 * afterwards -- ordered by the publish, so no lock is needed. */
static float s_cm[9];       /* row-major 3x3, luma gain already folded in */
static float s_coff[3];     /* subtracted from (y,u,v) before the matrix   */

static void colour_setup(enum AVColorSpace cs, enum AVColorRange cr, int h) {
  /* Unity's own message "Video source with full color range is not supported"
   * says limited range is what these clips will be; handle both anyway. */
  const int full = (cr == AVCOL_RANGE_JPEG);
  int bt709;
  switch (cs) {
    case AVCOL_SPC_BT709:                    bt709 = 1; break;
    case AVCOL_SPC_BT470BG:
    case AVCOL_SPC_SMPTE170M:                bt709 = 0; break;
    default:                                 bt709 = (h >= 720); break;
  }
  const float kr = bt709 ? 1.5748f : 1.5960f;
  const float kgu = bt709 ? 0.1873f : 0.3918f;
  const float kgv = bt709 ? 0.4681f : 0.8130f;
  const float kbu = bt709 ? 1.8556f : 2.0172f;

  const float ygain = full ? 1.0f : 255.0f / 219.0f;   /* 1.1644 */
  const float cgain = full ? 1.0f : 255.0f / 224.0f;   /* 1.1384 */

  s_coff[0] = full ? 0.0f : 16.0f / 255.0f;
  s_coff[1] = 0.5f;
  s_coff[2] = 0.5f;

  s_cm[0] = ygain; s_cm[1] = 0.0f;         s_cm[2] =  kr  * cgain;
  s_cm[3] = ygain; s_cm[4] = -kgu * cgain; s_cm[5] = -kgv * cgain;
  s_cm[6] = ygain; s_cm[7] =  kbu * cgain; s_cm[8] = 0.0f;
}

/* Read the clip into RAM up front, on this thread, before any decoding starts.
 * A few MB, and it means no SD read ever happens mid-playback -- this port has
 * already had the engine park inside a blocking filesystem call for 48 seconds,
 * and doing it while a video is on screen would be worse than not playing one. */
static uint8_t *read_clip(const DecodeArgs *a, int *out_size) {
  FILE *f = fopen(a->path, "rb");
  if (!f)
    return NULL;
  long sz;
  if (a->size) {
    fseek(f, 0, SEEK_END);
    const long end = ftell(f);
    if ((long)(a->offset + a->size) > end) {
      debugPrintf("[video] %s: range %llu+%llu runs past the end of the file "
                  "(%ld) -- assets replaced without a rescan?\n", a->label,
                  (unsigned long long)a->offset, (unsigned long long)a->size, end);
      fclose(f);
      return NULL;
    }
    fseek(f, (long)a->offset, SEEK_SET);
    sz = (long)a->size;
  } else {
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
  }
  if (sz <= 1024 || sz > 256L * 1024 * 1024) {
    fclose(f);
    return NULL;
  }
  uint8_t *d = malloc((size_t)sz);
  if (!d) {
    fclose(f);
    return NULL;
  }
  size_t got = fread(d, 1, (size_t)sz, f);
  fclose(f);
  if (got != (size_t)sz) {
    free(d);
    return NULL;
  }
  *out_size = (int)sz;
  return d;
}

static void *decode_thread(void *ud) {
  (void)ud;
  diag_thread_register(NULL, 0);
  diag_set_name(NULL, "cloverpit-video");

  AVFormatContext *fmt = NULL;
  AVIOContext     *avio = NULL;
  AVCodecContext  *vdec = NULL, *adec = NULL;
  struct SwsContext *sws = NULL;
  SwrContext      *swr = NULL;
  AVPacket        *pkt = NULL;
  AVFrame         *frame = NULL, *scaled = NULL;
  int16_t         *apcm = NULL;
  uint8_t         *iobuf = NULL;
  uint8_t         *mdata = NULL;
  int              msize = 0;
  int              vidx = -1, aidx = -1;
  int              sw = 0, sh = 0;          /* size we publish at */
  unsigned         published = 0, dropped = 0;
  const uint64_t   t_start = armGetSystemTick();

  mdata = read_clip(&s_args, &msize);
  if (!mdata) {
    debugPrintf("[video] cannot read %s -- nothing to play\n", s_args.path);
    goto done;
  }

  MemBuf mem = { mdata, msize, 0 };
  iobuf = av_malloc(65536);
  if (!iobuf)
    goto done;
  avio = avio_alloc_context(iobuf, 65536, 0, &mem, mem_read, NULL, mem_seek);
  if (!avio) {
    av_free(iobuf);
    iobuf = NULL;
    goto done;
  }
  iobuf = NULL;               /* avio owns it now; freed via avio->buffer */

  fmt = avformat_alloc_context();
  if (!fmt)
    goto done;
  fmt->pb = avio;
  /* No filename and no forced demuxer: let ffmpeg probe. The two clips are not
   * necessarily the same container -- their Unity m_Format fields differ (4 for
   * the publisher clip, sourced .webm; 1 for the developer clip, sourced .m4v)
   * -- so anything that assumed one container would break on the other. */
  if (avformat_open_input(&fmt, NULL, NULL, NULL) < 0) {
    debugPrintf("[video] avformat_open_input failed -- unrecognised container\n");
    fmt = NULL;
    goto done;
  }
  if (avformat_find_stream_info(fmt, NULL) < 0) {
    debugPrintf("[video] no stream info\n");
    goto done;
  }

  for (unsigned i = 0; i < fmt->nb_streams; i++) {
    enum AVMediaType t = fmt->streams[i]->codecpar->codec_type;
    if (t == AVMEDIA_TYPE_VIDEO && vidx < 0)      vidx = (int)i;
    else if (t == AVMEDIA_TYPE_AUDIO && aidx < 0) aidx = (int)i;
  }
  if (vidx < 0) {
    debugPrintf("[video] no video stream\n");
    goto done;
  }

  {
    AVCodecParameters *vp = fmt->streams[vidx]->codecpar;
    const AVCodec *vc = avcodec_find_decoder(vp->codec_id);
    if (!vc) {
      /* The single most likely failure on a fresh switch-ffmpeg: the container
       * parsed but its codec was configured out. Name it, because the fix is a
       * rebuild flag or a re-encode at staging time, not a code change. */
      debugPrintf("[video] NO DECODER for codec id %d (%s) -- switch-ffmpeg was "
                  "built without it; re-stage with --transcode-video\n",
                  (int)vp->codec_id, avcodec_get_name(vp->codec_id));
      goto done;
    }
    vdec = avcodec_alloc_context3(vc);
    if (!vdec)
      goto done;
    avcodec_parameters_to_context(vdec, vp);
    vdec->thread_count = OS_VIDEO_DECODE_THREADS;
    vdec->thread_type  = FF_THREAD_FRAME;
    if (avcodec_open2(vdec, vc, NULL) < 0) {
      debugPrintf("[video] avcodec_open2 failed for %s\n", vc->name);
      goto done;
    }

    sw = vp->width;
    sh = vp->height;
    if (sw <= 0 || sh <= 0)
      goto done;
    if (sw > OS_VIDEO_MAX_W || sh > OS_VIDEO_MAX_H) {
      /* Fit inside the cap, preserving aspect, and keep both dimensions even so
       * the chroma planes stay exactly half size. */
      double k = (double)OS_VIDEO_MAX_W / sw;
      double k2 = (double)OS_VIDEO_MAX_H / sh;
      if (k2 < k) k = k2;
      sw = ((int)(vp->width * k) / 2) * 2;
      sh = ((int)(vp->height * k) / 2) * 2;
      if (sw < 2) sw = 2;
      if (sh < 2) sh = 2;
    }
    debugPrintf("[video] %s: %s %dx%d -> %dx%d, %d thread(s)\n",
                s_args.label, vc->name, vp->width, vp->height, sw, sh,
                vdec->thread_count);
    colour_setup(vdec->colorspace, vdec->color_range, vp->height);
  }

  for (int i = 0; i < NSLOT; i++)
    if (!slot_reserve(&s_slot[i], sw, sh)) {
      debugPrintf("[video] out of memory reserving frame slots (%dx%d)\n", sw, sh);
      goto done;
    }

  /* Audio. A sink is optional by design: the FMOD pump only opens its device
   * after FMOD_WARMUP_FRAMES, so an early splash legitimately has nowhere to
   * put PCM, and a silent intro is better than a second audio device. */
  if (aidx >= 0) {
    int rate = opensles_movie_begin(48000);
    if (rate > 0) {
      AVCodecParameters *ap = fmt->streams[aidx]->codecpar;
      const AVCodec *ac = avcodec_find_decoder(ap->codec_id);
      if (ac && (adec = avcodec_alloc_context3(ac)) != NULL) {
        avcodec_parameters_to_context(adec, ap);
        if (avcodec_open2(adec, ac, NULL) == 0) {
          AVChannelLayout out_ch = AV_CHANNEL_LAYOUT_STEREO;
          if (swr_alloc_set_opts2(&swr, &out_ch, AV_SAMPLE_FMT_S16, rate,
                                  &adec->ch_layout, adec->sample_fmt,
                                  adec->sample_rate, 0, NULL) == 0 && swr &&
              swr_init(swr) == 0) {
            apcm = malloc((size_t)8192 * 2 * sizeof(int16_t));
          }
          if (!apcm) {
            if (swr) swr_free(&swr);
            avcodec_free_context(&adec);
          }
        } else {
          avcodec_free_context(&adec);
        }
      }
      if (adec && swr && apcm) {
        s_audio_sink_rate = rate;
        opensles_movie_set_paused(0);
        debugPrintf("[video] audio: %s -> %d Hz stereo, mixed into the FMOD block\n",
                    ac ? ac->name : "?", rate);
      } else {
        opensles_movie_end();
        aidx = -1;
        debugPrintf("[video] audio decoder unavailable -- playing silent\n");
      }
    } else {
      aidx = -1;
      debugPrintf("[video] no audio sink yet (FMOD device not open) -- playing "
                  "silent, paced off wall time\n");
    }
  }

  pkt = av_packet_alloc();
  frame = av_frame_alloc();
  if (!pkt || !frame)
    goto done;

  const double tb_v = av_q2d(fmt->streams[vidx]->time_base);
  const double tickHz = (double)armGetSystemTickFreq();
  const uint64_t t0 = armGetSystemTick();
  double pts_base = -1.0;

  while (!s_stop && av_read_frame(fmt, pkt) >= 0) {
    if (aidx >= 0 && pkt->stream_index == aidx) {
      if (avcodec_send_packet(adec, pkt) == 0) {
        while (avcodec_receive_frame(adec, frame) == 0) {
          uint8_t *outp = (uint8_t *)apcm;
          int outn = swr_convert(swr, &outp, 8192,
                                 (const uint8_t **)frame->extended_data,
                                 frame->nb_samples);
          if (outn > 0)
            opensles_movie_queue(apcm, outn);
        }
      }
    } else if (pkt->stream_index == vidx) {
      if (avcodec_send_packet(vdec, pkt) == 0) {
        while (!s_stop && avcodec_receive_frame(vdec, frame) == 0) {
          AVFrame *src = frame;

          /* Anything that is not 8-bit planar 4:2:0 at the publish size goes
           * through swscale. With the shipped clips this branch never runs:
           * both are 1920x1080 yuv420p and OS_VIDEO_MAX_W/H default to exactly
           * that, so the decoder output is packed straight into a slot. */
          const int needs_scale =
              (frame->format != AV_PIX_FMT_YUV420P &&
               frame->format != AV_PIX_FMT_YUVJ420P) ||
              frame->width != sw || frame->height != sh;

          if (needs_scale) {
            if (!sws) {
              sws = sws_getContext(frame->width, frame->height,
                                   (enum AVPixelFormat)frame->format,
                                   sw, sh, AV_PIX_FMT_YUV420P,
                                   SWS_BILINEAR, NULL, NULL, NULL);
              if (!sws) {
                debugPrintf("[video] sws_getContext failed\n");
                goto done;
              }
              scaled = av_frame_alloc();
              if (!scaled)
                goto done;
              scaled->format = AV_PIX_FMT_YUV420P;
              scaled->width  = sw;
              scaled->height = sh;
              if (av_frame_get_buffer(scaled, 32) < 0) {
                debugPrintf("[video] cannot allocate scaled frame\n");
                goto done;
              }
            }
            sws_scale(sws, (const uint8_t *const *)frame->data, frame->linesize,
                      0, frame->height, scaled->data, scaled->linesize);
            src = scaled;
          }

          int si = slot_acquire();
          if (si < 0) { dropped++; av_frame_unref(frame); continue; }
          slot_fill(&s_slot[si], src);

          double pts = (frame->best_effort_timestamp != AV_NOPTS_VALUE)
                         ? (double)frame->best_effort_timestamp * tb_v
                         : 0.0;
          s_slot[si].pts = pts;

          /* PACE AGAINST WALL TIME, NOT THE AUDIO CLOCK.
           *
           * This used to read opensles_movie_samples_played() when an audio
           * sink existed, copied from cr3_nx. In this player that is a circular
           * dependency and it cost a hardware cycle:
           *
           *   a video frame waits for the audio clock to reach its pts
           *     -> the audio clock only advances when mix_movie() drains the ring
           *       -> the ring only has PCM if an audio packet has been read
           *         -> audio packets are read by THIS loop, which is asleep
           *            waiting for the audio clock.
           *
           * The loop is sequential -- one thread reads packets, decodes both
           * streams and paces video -- so blocking video on a clock that only
           * this loop can advance deadlocks until the spin times out. Measured:
           * 3 frames in 7 seconds for the H.264 clip, 18 in 12 for the VP8 one,
           * while the engine held a steady 59.8 fps and zero frames were
           * dropped. The decoder was never the bottleneck.
           *
           * Wall time always advances, so there is nothing to deadlock on. The
           * audio device consumes at its own realtime rate and video follows
           * realtime, so the two stay together to within the ring depth without
           * either having to observe the other. */
          if (pts_base < 0.0)
            pts_base = pts;              /* MP4 edit lists need not start at 0 */
          const double target = pts - pts_base;

          for (;;) {
            const double now = (double)(armGetSystemTick() - t0) / tickHz;
            double wait = target - now;
            if (wait <= 0.0 || s_stop)
              break;
            if (wait > 0.5)
              wait = 0.5;                /* a runaway timestamp cannot park us */
            if (wait > 0.008)
              wait = 0.008;              /* stay responsive to Stop() */
            svcSleepThread((uint64_t)(wait * 1e9));
          }

          /* If we are far enough behind that this frame's moment has passed,
           * decode it but do not show it. THIS is what makes the design
           * degrade by dropping frames rather than by drifting out of sync --
           * previously `dropped` only counted slot exhaustion, which never
           * happens, so a slow decode would have shown as sluggish video with
           * no counter to prove it. */
          {
            const double now = (double)(armGetSystemTick() - t0) / tickHz;
            if (now > target + 0.15 && published > 0) {
              dropped++;
              av_frame_unref(frame);
              continue;
            }
          }

          slot_publish(si);
          published++;
          av_frame_unref(frame);
        }
      }
    }
    av_packet_unref(pkt);
  }

  /* Drain. With FF_THREAD_FRAME the decoder holds back thread_count-1 frames,
   * and av_read_frame returning EOF does not release them -- measured on the
   * shipped clips: 656 frames out at thread_count 1, 655 at 2, 654 at 3. Send
   * the flush packet so the tail actually reaches the screen and the
   * "finished: N frame(s)" line matches the clip's real frame count, which is
   * what makes that line usable as a diagnostic. */
  if (!s_stop && avcodec_send_packet(vdec, NULL) == 0) {
    while (!s_stop && avcodec_receive_frame(vdec, frame) == 0) {
      if (frame->format != AV_PIX_FMT_YUV420P &&
          frame->format != AV_PIX_FMT_YUVJ420P)
        break;                                    /* scaler already torn down */
      if (frame->width != sw || frame->height != sh)
        break;
      int si = slot_acquire();
      if (si < 0) { dropped++; av_frame_unref(frame); continue; }
      slot_fill(&s_slot[si], frame);
      slot_publish(si);
      published++;
      av_frame_unref(frame);
      svcSleepThread(16000000ull);                /* ~one frame at 60 Hz */
    }
  }

  s_eof = 1;
  s_eof_tick = tick_ns();

done:
  /* Logging here is fine: this is our own thread, not SDL's audio callback and
   * not FMOD's mixer. */
  debugPrintf("[video] finished: %u shown, %u dropped in %.2fs (%.1f fps); "
              "audio queued %llu played %llu frames%s\n",
              published, dropped,
              (double)(armGetSystemTick() - t_start) / (double)armGetSystemTickFreq(),
              published / ((double)(armGetSystemTick() - t_start) /
                           (double)armGetSystemTickFreq() + 1e-6),
              (unsigned long long)opensles_movie_samples_queued(),
              (unsigned long long)opensles_movie_samples_played(),
              s_stop ? " (stopped early)" : "");

  if (s_audio_sink_rate) {
    opensles_movie_end();
    s_audio_sink_rate = 0;
  }
  if (pkt)    av_packet_free(&pkt);
  if (frame)  av_frame_free(&frame);
  if (scaled) av_frame_free(&scaled);
  if (swr)    swr_free(&swr);
  if (sws)    sws_freeContext(sws);
  if (vdec)   avcodec_free_context(&vdec);
  if (adec)   avcodec_free_context(&adec);
  if (fmt)    avformat_close_input(&fmt);
  if (avio) { av_freep(&avio->buffer); avio_context_free(&avio); }
  if (iobuf)  av_free(iobuf);
  free(mdata);

  s_playing = 0;
  return NULL;
}

/* ------------------------------------------------------------------ control */

static void join_thread(void) {
  if (!s_thread_live)
    return;
  s_stop = 1;
  pthread_join(s_thread, NULL);
  s_thread_live = 0;
}

void os_video_play(const char *path) {
  if (!s_inited) {
    debugPrintf("[video] play(%s) before init -- ignored\n", path ? path : "?");
    return;
  }
  if (!path || !*path) {
    debugPrintf("[video] play() with an empty path -- ignored\n");
    return;
  }

  join_thread();          /* bounded: the decode loop checks s_stop every 2 ms */

  /* Resolve to something we can open. The engine passes what the managed side
   * gave Handheld.PlayFullScreenMovie, which for this game is a StreamingAssets
   * -relative name like "4-3/Ending.mp4". Try, in order:
   *   <root>/assets/<path>     where the APK's assets/ was copied
   *   <root>/<path>            if the user flattened it
   *   <path>                   already absolute
   * Nothing is normalised beyond that -- if none of them open, decode_thread
   * logs the failure and the ending is skipped, exactly as it is today. */
  memset(&s_args, 0, sizeof s_args);
  snprintf(s_args.label, sizeof s_args.label, "%s", path);

  struct stat st;
  char cand[512];
  int  found = 0;
  if (path[0] == '/' || strstr(path, ":/")) {
    snprintf(cand, sizeof cand, "%s", path);
    found = (stat(cand, &st) == 0);
  }
  if (!found) {
    snprintf(cand, sizeof cand, "%s/assets/%s", s_game_root, path);
    found = (stat(cand, &st) == 0);
  }
  if (!found) {
    snprintf(cand, sizeof cand, "%s/%s", s_game_root, path);
    found = (stat(cand, &st) == 0);
  }
  if (!found) {
    debugPrintf("[video] no file for \"%s\" under %s -- ending will be skipped "
                "(tried assets/ and the root)\n", path, s_game_root);
    return;
  }
  snprintf(s_args.path, sizeof s_args.path, "%s", cand);
  s_args.offset = 0;
  s_args.size   = 0;     /* 0 = whole file */

  /* main.c rewrites boot.config's gfx-threading-mode to 0, so the engine
   * presents from its own main thread -- the same thread that runs this
   * coroutine and therefore this hook. os_video_draw, os_video_play and
   * os_video_stop are consequently all on one thread today and s_hold is
   * always -1 here. The wait costs nothing in that case and keeps the slot
   * handover correct if multithreaded rendering is ever restored. */
  for (int spin = 0; spin < 20; spin++) {
    int held;
    mutexLock(&s_lock);
    held = s_hold;
    mutexUnlock(&s_lock);
    if (held < 0)
      break;
    svcSleepThread(1000000ull);   /* 1 ms */
  }

  mutexLock(&s_lock);
  s_pub = -1;
  s_hold = -1;
  mutexUnlock(&s_lock);

  s_stop = 0;
  s_eof = 0;
  s_eof_tick = 0;
  s_audio_mixed_blocks = 0;
  s_playing = 1;

  /* EXPLICIT STACK SIZE. ffmpeg's H.264 and VP8 decoders keep their state on
   * the heap but still use a few tens of KB of stack in the inner loops, and
   * devkitPro's newlib picks a small default for pthreads (the FMOD pump gets
   * away with NULL attrs, but it only ever calls one engine function). A stack
   * overflow here would be a hard crash with no useful log, which is the most
   * expensive possible failure on a console that costs a build cycle to test.
   * 512 KB is address space, not committed memory. */
  pthread_attr_t attr;
  pthread_attr_t *pattr = NULL;
  if (pthread_attr_init(&attr) == 0) {
    if (pthread_attr_setstacksize(&attr, 512 * 1024) == 0)
      pattr = &attr;
    else
      pthread_attr_destroy(&attr);
  }

  if (pthread_create(&s_thread, pattr, decode_thread, NULL) != 0) {
    if (pattr) pthread_attr_destroy(pattr);
    s_playing = 0;
    debugPrintf("[video] pthread_create failed -- intro will be black\n");
    return;
  }
  if (pattr) pthread_attr_destroy(pattr);
  s_thread_live = 1;
  debugPrintf("[video] play %s (%lld bytes)\n", s_args.path, (long long)st.st_size);
}

void os_video_stop(void) {
  if (!s_thread_live && !s_playing)
    return;
  join_thread();
  s_playing = 0;
  s_eof = 0;                 /* cancel the end-of-clip hold: hide immediately */
  mutexLock(&s_lock);
  s_pub = -1;
  mutexUnlock(&s_lock);
}

/* ---------------------------------------------------------------- GL overlay */

/* Modelled directly on nx_pointer.c's nxp_draw: the same save-everything-we-
 * touch discipline, for the same reason. The engine sets its attribute
 * pointers once and reuses them across frames, so leaving slot 0 or 1 pointing
 * at our quad makes every subsequent engine draw read garbage geometry. */

static GLuint s_prog, s_texY, s_texU, s_texV;
static GLint  s_u_m0, s_u_m1, s_u_m2, s_u_off, s_u_scale;
static GLint  s_u_ty, s_u_tu, s_u_tv;
static int    s_gl_failed;
static int    s_tex_w, s_tex_h;
static uint32_t s_drawn_serial;

typedef struct {
  GLint enabled, size, type, norm, stride, buf;
  void *ptr;
} AttribState;

static void attrib_save(GLuint i, AttribState *a) {
  glGetVertexAttribiv(i, GL_VERTEX_ATTRIB_ARRAY_ENABLED, &a->enabled);
  glGetVertexAttribiv(i, GL_VERTEX_ATTRIB_ARRAY_SIZE, &a->size);
  glGetVertexAttribiv(i, GL_VERTEX_ATTRIB_ARRAY_TYPE, &a->type);
  glGetVertexAttribiv(i, GL_VERTEX_ATTRIB_ARRAY_NORMALIZED, &a->norm);
  glGetVertexAttribiv(i, GL_VERTEX_ATTRIB_ARRAY_STRIDE, &a->stride);
  glGetVertexAttribiv(i, GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING, &a->buf);
  glGetVertexAttribPointerv(i, GL_VERTEX_ATTRIB_ARRAY_POINTER, &a->ptr);
}

static void attrib_restore(GLuint i, const AttribState *a) {
  glBindBuffer(GL_ARRAY_BUFFER, (GLuint)a->buf);
  if (a->size > 0)
    glVertexAttribPointer(i, a->size, (GLenum)a->type,
                          (GLboolean)(a->norm ? GL_TRUE : GL_FALSE),
                          a->stride, a->ptr);
  if (a->enabled) glEnableVertexAttribArray(i);
  else            glDisableVertexAttribArray(i);
}

static GLuint mkshader(GLenum t, const char *src) {
  GLuint s = glCreateShader(t);
  glShaderSource(s, 1, &src, NULL);
  glCompileShader(s);
  GLint ok = 0;
  glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
  if (!ok) {
    char log[256];
    glGetShaderInfoLog(s, sizeof log, NULL, log);
    debugPrintf("[video] shader compile failed: %s\n", log);
    glDeleteShader(s);
    return 0;
  }
  return s;
}

static GLuint mktex(int w, int h) {
  GLuint t = 0;
  glGenTextures(1, &t);
  glBindTexture(GL_TEXTURE_2D, t);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  /* Allocate the storage ONCE, here. Per-frame updates then go through
   * glTexSubImage2D, which writes into the existing allocation. Using
   * glTexImage2D every frame instead would re-specify the texture 60 times a
   * second -- on mesa/nouveau that means a fresh BO and a fresh allocation each
   * time, which is precisely the churn cloverpit_gpuarena.c exists to stop. */
  glTexImage2D(GL_TEXTURE_2D, 0, GL_LUMINANCE, w, h, 0, GL_LUMINANCE,
               GL_UNSIGNED_BYTE, NULL);
  return t;
}

static int gl_setup(void) {
  if (s_prog)
    return 1;
  if (s_gl_failed)
    return 0;

  static const char *vs =
    "attribute vec2 aPos;\n"
    "varying vec2 vUV;\n"
    "uniform vec2 uScale;\n"      /* letterbox: fraction of the screen used */
    "void main() {\n"
    "  vUV = vec2(aPos.x * 0.5 + 0.5, 0.5 - aPos.y * 0.5);\n"
    "  gl_Position = vec4(aPos * uScale, 0.0, 1.0);\n"
    "}\n";
  /* GL_LUMINANCE puts the single channel in .r (and .g/.b), so .r is correct
   * and portable across the GLES2/GLES3 contexts mesa may hand out. */
  static const char *fs =
    "precision mediump float;\n"
    "varying vec2 vUV;\n"
    "uniform sampler2D uY;\n"
    "uniform sampler2D uU;\n"
    "uniform sampler2D uV;\n"
    "uniform vec3 uM0;\n"
    "uniform vec3 uM1;\n"
    "uniform vec3 uM2;\n"
    "uniform vec3 uOff;\n"
    "void main() {\n"
    "  vec3 t = vec3(texture2D(uY, vUV).r,\n"
    "                texture2D(uU, vUV).r,\n"
    "                texture2D(uV, vUV).r) - uOff;\n"
    "  gl_FragColor = vec4(dot(uM0, t), dot(uM1, t), dot(uM2, t), 1.0);\n"
    "}\n";

  GLuint v = mkshader(GL_VERTEX_SHADER, vs);
  GLuint f = mkshader(GL_FRAGMENT_SHADER, fs);
  if (!v || !f) {
    if (v) glDeleteShader(v);
    if (f) glDeleteShader(f);
    s_gl_failed = 1;
    return 0;
  }
  GLuint p = glCreateProgram();
  glAttachShader(p, v);
  glAttachShader(p, f);
  glBindAttribLocation(p, 0, "aPos");
  glLinkProgram(p);
  glDeleteShader(v);
  glDeleteShader(f);
  GLint ok = 0;
  glGetProgramiv(p, GL_LINK_STATUS, &ok);
  if (!ok) {
    glDeleteProgram(p);
    s_gl_failed = 1;
    debugPrintf("[video] shader link failed -- intro will be black\n");
    return 0;
  }
  s_prog    = p;
  s_u_m0    = glGetUniformLocation(p, "uM0");
  s_u_m1    = glGetUniformLocation(p, "uM1");
  s_u_m2    = glGetUniformLocation(p, "uM2");
  s_u_off   = glGetUniformLocation(p, "uOff");
  s_u_scale = glGetUniformLocation(p, "uScale");
  s_u_ty    = glGetUniformLocation(p, "uY");
  s_u_tu    = glGetUniformLocation(p, "uU");
  s_u_tv    = glGetUniformLocation(p, "uV");
  return 1;
}

/* Give the GPU memory back as soon as the clip is over. The intro happens once
 * and the game then runs for hours; 3.1 MB of texture is not worth holding in a
 * port that reserves GFX_RESERVE_MB by hand. */
static void gl_release(void) {
  if (s_texY) { glDeleteTextures(1, &s_texY); s_texY = 0; }
  if (s_texU) { glDeleteTextures(1, &s_texU); s_texU = 0; }
  if (s_texV) { glDeleteTextures(1, &s_texV); s_texV = 0; }
  if (s_prog) { glDeleteProgram(s_prog); s_prog = 0; }
  s_tex_w = s_tex_h = 0;
  s_drawn_serial = 0;
  s_gl_failed = 0;
  for (int i = 0; i < NSLOT; i++) {
    free(s_slot[i].buf);
    s_slot[i].buf = NULL;
    s_slot[i].cap = 0;
  }
}

/* Keep the last frame up briefly after the clip ends, so a clip that finishes a
 * few frames before IntroScript's timer does not flash black. Bounded, and
 * cancelled outright by an explicit Stop(). */
#define EOF_HOLD_NS 750000000ull

void os_video_draw(void) {
  if (!s_playing) {
    int hold = s_eof && s_eof_tick &&
               (tick_ns() - s_eof_tick) < EOF_HOLD_NS;
    if (!hold) {
      if (s_prog || s_texY)
        gl_release();
      return;
    }
  }

  int si;
  uint32_t serial;
  mutexLock(&s_lock);
  si = s_pub;
  serial = s_pub_serial;
  if (si >= 0)
    s_hold = si;
  mutexUnlock(&s_lock);

  if (si < 0)
    return;
  if (!gl_setup()) {
    mutexLock(&s_lock); s_hold = -1; mutexUnlock(&s_lock);
    return;
  }

  const VidSlot *sl = &s_slot[si];
  const int w = sl->w, h = sl->h;
  const int cw = (w + 1) / 2, ch = (h + 1) / 2;
  if (!sl->buf || w <= 0 || h <= 0) {
    mutexLock(&s_lock); s_hold = -1; mutexUnlock(&s_lock);
    return;
  }

  /* ---- save every bit of state we touch ---- */
  AttribState a0;
  attrib_save(0, &a0);
  GLint prev_prog = 0, prev_buf = 0, prev_active = 0, prev_align = 4;
  GLint vp[4] = { 0, 0, 0, 0 };
  GLint tex0 = 0, tex1 = 0, tex2 = 0;
  glGetIntegerv(GL_CURRENT_PROGRAM, &prev_prog);
  glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &prev_buf);
  glGetIntegerv(GL_ACTIVE_TEXTURE, &prev_active);
  glGetIntegerv(GL_UNPACK_ALIGNMENT, &prev_align);
  glGetIntegerv(GL_VIEWPORT, vp);
  const GLboolean was_blend   = glIsEnabled(GL_BLEND);
  const GLboolean was_depth   = glIsEnabled(GL_DEPTH_TEST);
  const GLboolean was_cull    = glIsEnabled(GL_CULL_FACE);
  const GLboolean was_scissor = glIsEnabled(GL_SCISSOR_TEST);
  glActiveTexture(GL_TEXTURE0); glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex0);
  glActiveTexture(GL_TEXTURE1); glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex1);
  glActiveTexture(GL_TEXTURE2); glGetIntegerv(GL_TEXTURE_BINDING_2D, &tex2);

  glDisable(GL_DEPTH_TEST);
  glDisable(GL_CULL_FACE);
  glDisable(GL_SCISSOR_TEST);
  glDisable(GL_BLEND);
  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);

  int need_upload = (serial != s_drawn_serial);
  if (s_tex_w != w || s_tex_h != h) {
    if (s_texY) { glDeleteTextures(1, &s_texY); s_texY = 0; }
    if (s_texU) { glDeleteTextures(1, &s_texU); s_texU = 0; }
    if (s_texV) { glDeleteTextures(1, &s_texV); s_texV = 0; }
    glActiveTexture(GL_TEXTURE0); s_texY = mktex(w, h);
    glActiveTexture(GL_TEXTURE1); s_texU = mktex(cw, ch);
    glActiveTexture(GL_TEXTURE2); s_texV = mktex(cw, ch);
    s_tex_w = w;
    s_tex_h = h;
    need_upload = 1;      /* the fresh allocations have no contents yet */
  }

  const uint8_t *py = sl->buf;
  const uint8_t *pu = py + (size_t)w * h;
  const uint8_t *pv = pu + (size_t)cw * ch;

  if (need_upload) {
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, s_texY);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, w, h, GL_LUMINANCE,
                    GL_UNSIGNED_BYTE, py);
    glActiveTexture(GL_TEXTURE1);
    glBindTexture(GL_TEXTURE_2D, s_texU);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, cw, ch, GL_LUMINANCE,
                    GL_UNSIGNED_BYTE, pu);
    glActiveTexture(GL_TEXTURE2);
    glBindTexture(GL_TEXTURE_2D, s_texV);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, cw, ch, GL_LUMINANCE,
                    GL_UNSIGNED_BYTE, pv);
    s_drawn_serial = serial;
  } else {
    glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, s_texY);
    glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, s_texU);
    glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, s_texV);
  }

  /* The slot is copied into GL now, so let the decoder have it back. */
  mutexLock(&s_lock);
  s_hold = -1;
  mutexUnlock(&s_lock);

  /* Letterbox inside the port's own render resolution rather than whatever
   * sub-rect viewport the engine happened to leave set. */
  const int scr_w = screen_width  > 0 ? screen_width  : vp[2];
  const int scr_h = screen_height > 0 ? screen_height : vp[3];
  float ex = 1.0f, ey = 1.0f;
  if (scr_w > 0 && scr_h > 0) {
    const float sa = (float)scr_w / (float)scr_h;
    const float va = (float)w / (float)h;
    if (va > sa) ey = sa / va;
    else         ex = va / sa;
  }

  static const GLfloat quad[] = {
    -1.0f,  1.0f,
    -1.0f, -1.0f,
     1.0f,  1.0f,
     1.0f, -1.0f,
  };

  glViewport(0, 0, scr_w > 0 ? scr_w : vp[2], scr_h > 0 ? scr_h : vp[3]);
  glUseProgram(s_prog);
  glUniform1i(s_u_ty, 0);
  glUniform1i(s_u_tu, 1);
  glUniform1i(s_u_tv, 2);
  glUniform3f(s_u_m0, s_cm[0], s_cm[1], s_cm[2]);
  glUniform3f(s_u_m1, s_cm[3], s_cm[4], s_cm[5]);
  glUniform3f(s_u_m2, s_cm[6], s_cm[7], s_cm[8]);
  glUniform3f(s_u_off, s_coff[0], s_coff[1], s_coff[2]);
  glUniform2f(s_u_scale, ex, ey);

  glBindBuffer(GL_ARRAY_BUFFER, 0);          /* client-side array */
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, quad);
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

  /* ---- restore ---- */
  attrib_restore(0, &a0);
  glBindBuffer(GL_ARRAY_BUFFER, (GLuint)prev_buf);
  glUseProgram((GLuint)prev_prog);
  glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, (GLuint)tex2);
  glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, (GLuint)tex1);
  glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, (GLuint)tex0);
  glActiveTexture((GLenum)prev_active);
  glPixelStorei(GL_UNPACK_ALIGNMENT, prev_align);
  glViewport(vp[0], vp[1], vp[2], vp[3]);
  if (was_blend)   glEnable(GL_BLEND);
  if (was_depth)   glEnable(GL_DEPTH_TEST);
  if (was_cull)    glEnable(GL_CULL_FACE);
  if (was_scissor) glEnable(GL_SCISSOR_TEST);
}

#else  /* !OS_VIDEO */

void os_video_init(const char *game_root) { (void)game_root; }
void os_video_play(const char *path) { (void)path; }
void os_video_stop(void) { }
void os_video_draw(void) { }
int  os_video_mix_audio(short *dst, int frames, int channels) {
  (void)dst; (void)frames; (void)channels; return 0;
}
int  os_video_is_playing(void) { return 0; }

#endif /* OS_VIDEO */
