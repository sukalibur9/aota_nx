/* os_video.h -- full-screen movie playback for The Room Three's endings.
 *
 * The game uses Handheld.PlayFullScreenMovie, which on Android is handed to
 * android.media.MediaPlayer through
 *     com.unity3d.player.UnityPlayer.showVideoPlayer(String, IIIZII)Z
 * There is no MediaPlayer here, so jni_fake.c answers that call itself and
 * routes it to os_video_play(). See os_video.c for the full derivation.
 *
 * Set OS_VIDEO to 0 in config.h to drop the feature: every function below
 * compiles to an empty stub needing no ffmpeg header and no ffmpeg library, and
 * the port behaves exactly as it did before -- endings silently skipped.
 *
 * MIT. Decoder and GL path derived from the CloverPit NX port.
 */
#ifndef OS_VIDEO_H
#define OS_VIDEO_H

/* Record the game root. Starts no threads, opens no devices, touches no GL;
 * safe to call before the engine exists. Idempotent. */
void os_video_init(const char *game_root);

/* Start playback of `path`, as handed to showVideoPlayer (e.g.
 * "4-3/Ending.mp4"). Resolved against <root>/assets/ then <root>. Returns
 * immediately -- decoding happens on a worker thread. A second call while
 * playing stops the first clip. */
void os_video_play(const char *path);

/* Stop playback and release the decoder. GL objects are freed by the next
 * os_video_draw() on the render thread, since only that thread has a context. */
void os_video_stop(void);

/* Draw the newest decoded frame, if any, over the current framebuffer. MUST be
 * called on the thread owning the GL context, immediately before
 * eglSwapBuffers. Saves and restores every piece of GL state it touches, and
 * does nothing at all when no clip is playing. */
void os_video_draw(void);

/* Mix pending movie audio into an S16 interleaved buffer already holding the
 * engine's own PCM. Called from the FMOD pump in jni_fake.c. Returns frames
 * mixed. MUST NOT LOG -- it runs on the audio pump thread. */
int os_video_mix_audio(short *dst, int frames, int channels);

/* Whether a clip is currently decoding. Diagnostic only. */
int os_video_is_playing(void);

#endif /* OS_VIDEO_H */
