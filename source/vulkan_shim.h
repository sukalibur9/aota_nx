#pragma once
/*
 * vulkan_shim.h - Vulkan WSI translation layer for Unity (Android build) on Switch.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve a "vk*" symbol that Unity asked for through dlsym() on the fake
 * libvulkan.so handle. Returns the function pointer, or NULL if the symbol is
 * not handled (dlsym should then fail). Always NULL when the build has no
 * -DHAVE_NVK=1 (libvulkan.a not linked). */
void* vulkan_shim_resolve(const char* symbol);

/* 1 if the symbol name starts with "vk", else 0. */
int vulkan_shim_is_vulkan_symbol(const char* symbol);

/* 1 if this build has NVK linked in (-DHAVE_NVK=1), else 0. Use it to decide
 * whether dlopen("libvulkan.so") should succeed. */
int vulkan_shim_available(void);

#ifdef __cplusplus
}
#endif
