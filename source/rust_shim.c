/* Minimal Rust runtime for mesa's NAK shader compiler (no_std + alloc).
 *
 * libnak_rs.a was built by rustc as a no_std staticlib: the final binary must
 * provide the allocation hooks (__rdl_*), the panic entry points, and the
 * unwinder personality. Panics abort: NAK runs inside vkCreateShaderModule,
 * and a shader-compile panic is unrecoverable anyway.
 *
 * The __rdl_* symbols are referenced by their mangled ___rustc paths
 * (rustc's allocation shim); define them under the exact mangled names the
 * SDK objects expect.
 */
#include <stddef.h>
#include <stdlib.h>

/* ---- global allocator hooks (___rustc::__rdl_*) ---- */
void *_RNvCsgd1yFkIsQtl_7___rustc11___rdl_alloc(size_t size, size_t align) {
  (void)align;
  return malloc(size ? size : 1);
}
void _RNvCsgd1yFkIsQtl_7___rustc13___rdl_dealloc(void *ptr, size_t size,
                                                size_t align) {
  (void)size; (void)align;
  free(ptr);
}
void *_RNvCsgd1yFkIsQtl_7___rustc13___rdl_realloc(void *ptr, size_t old_size,
                                                 size_t align, size_t new_size) {
  (void)old_size; (void)align;
  return realloc(ptr, new_size ? new_size : 1);
}
void *_RNvCsgd1yFkIsQtl_7___rustc18___rdl_alloc_zeroed(size_t size,
                                                      size_t align) {
  (void)align;
  return calloc(1, size ? size : 1);
}

/* ---- panic runtime (___rustc::*) ---- */
void _RNvCsgd1yFkIsQtl_7___rustc18___rust_start_panic(void *payload) {
  (void)payload;
  abort();
}
void _RNvCsgd1yFkIsQtl_7___rustc17___rust_drop_panic(void) {
  abort();
}
void _RNvCsgd1yFkIsQtl_7___rustc20___rust_panic_cleanup(void) {
  abort();
}

/* ---- unwinder personality (referenced, never unwound: panic=abort) ---- */
int rust_eh_personality(int version, int actions, unsigned long long ex_class,
                        void *ex, void *ctx) {
  (void)version; (void)actions; (void)ex_class; (void)ex; (void)ctx;
  abort();
  return 0;
}
