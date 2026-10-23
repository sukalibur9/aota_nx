/* unity_input.h -- fake android.view.MotionEvent / KeyEvent for nativeInjectEvent
 *
 * nativeInjectEvent(env, thiz, InputEvent, deviceId) hands the engine a Java
 * input event jobject, which libunity then queries back via JNI. The exact
 * methods it resolves (confirmed from the binary) are:
 *   MotionEvent: getAction getActionMasked getActionIndex getPointerCount
 *                getPointerId getX getY getPressure getSize getOrientation
 *                getEventTime getToolType getButtonState getFlags getHistorySize
 *   KeyEvent:    getAction getKeyCode getRepeatCount getMetaState getUnicodeChar getFlags
 *   InputEvent:  getDeviceId getSource   (shared base; both kinds answer these)
 *
 * We hand back a stateful handle; its getters read values stashed by the
 * constructors. Injection is synchronous (the engine reads the event fully
 * during the nativeInjectEvent call), so a single reused handle is safe.
 *
 * INTEGRATION (two one-line delegations in jni_fake.c, mirroring unity_jni.c):
 *   in dispatch_int():   if (input_owns_class(id->cls)) return input_dispatch_int(recv,id,va);
 *   in dispatch_float(): if (input_owns_class(id->cls)) return input_dispatch_float(recv,id,va);
 * (dispatch_float already exists in cr3_nx and is wired to CallFloatMethod[V].)
 */
#ifndef UNITY_INPUT_H
#define UNITY_INPUT_H

#include <stdarg.h>
#include <stdint.h>


#define UI_MAX_POINTERS 10

/* Android action / source / keycode constants */
#define AMOTION_ACTION_DOWN          0
#define AMOTION_ACTION_UP            1
#define AMOTION_ACTION_MOVE          2
#define AMOTION_ACTION_CANCEL        3
#define AMOTION_ACTION_POINTER_DOWN  5
#define AMOTION_ACTION_POINTER_UP    6
#define AMOTION_ACTION_MASK          0xff
#define AMOTION_ACTION_PTR_IDX_SHIFT 8
#define AINPUT_SOURCE_TOUCHSCREEN    0x1002
#define AINPUT_SOURCE_KEYBOARD       0x0101
#define AINPUT_SOURCE_GAMEPAD        0x0401
#define AINPUT_SOURCE_JOYSTICK       0x01000010
#define AMOTION_TOOL_TYPE_FINGER     1
#define AKEY_ACTION_DOWN             0
#define AKEY_ACTION_UP               1
#define AKEYCODE_BACK                4

/* Android MotionEvent axis ids (the ones a gamepad reports). [inp144] */
#define UI_AXIS_X         0
#define UI_AXIS_Y         1
#define UI_AXIS_Z         11
#define UI_AXIS_RX        12
#define UI_AXIS_RY        13
#define UI_AXIS_RZ        14
#define UI_AXIS_HAT_X     15
#define UI_AXIS_HAT_Y     16
#define UI_AXIS_LTRIGGER  17
#define UI_AXIS_RTRIGGER  18
#define UI_AXIS_COUNT     48   /* covers GENERIC_1..16 (32..47) too */

/* constructors -> opaque jobject (the reused handle). action already encodes the
 * pointer index in its high byte for POINTER_DOWN/UP. */
void *unity_motionevent(int action, int count,
                        const int *ids, const float *xs, const float *ys);
void *unity_keyevent(int action, int keycode);
/* [inp144] gamepad constructors: a SOURCE_JOYSTICK motion event carrying the
 * full axis set (read back via getAxisValue), and a key event with an explicit
 * source/device so gamepad buttons arrive as SOURCE_GAMEPAD, device 1. */
void *unity_joystick_event(const float *axes /* UI_AXIS_COUNT, or NULL */);
void *unity_keyevent_ex(int action, int keycode, int source, int device);
/* MotionEvent.obtain(src) copy factory -- returns a separate UEvent copy of src
 * (or src unchanged if it isn't one of ours). */
void *unity_motionevent_obtain(void *src);

/* dispatch hooks (called from jni_fake.c's dispatch_int / dispatch_float) */
int       input_owns_class(const char *cls);
int       input_owns_recv (const void *recv);   /* true if recv is our event handle */
int       input_recv_is_motion(const void *recv); /* true if recv is a MotionEvent */
uint64_t  input_dispatch_int  (void *recv, const void *id, va_list va); /* int + long */
float     input_dispatch_float(void *recv, const void *id, va_list va);

/* ---- touch diagnostics ---------------------------------------------------
 * The host wires input_log_fn -> debugPrintf (NULL keeps this file host-
 * compilable and silent). input_log_budget gates per-gesture spam: the host
 * resets it to N on each touch DOWN; every logged getter call decrements it.
 * This lets us SEE, for one tap, the exact ordered set of MotionEvent methods
 * the engine queries back -- i.e. whether nativeInjectEvent reached the reader
 * at all, and which getters it actually calls. */
extern int  (*input_log_fn)(char *fmt, ...);
extern int   input_log_budget;

#endif /* UNITY_INPUT_H */
