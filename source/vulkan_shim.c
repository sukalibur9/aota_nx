/*
 * vulkan_shim.c - Vulkan WSI translation layer for Unity (Android build) on Switch.
 *
 * Unity enables VK_KHR_android_surface and calls vkCreateAndroidSurfaceKHR.
 * mesa-switch's NVK has no Android WSI. Its Horizon WSI is VK_NN_vi_surface /
 * vkCreateViSurfaceNN, and the window is a libnx NWindow*. In this loader
 * ANativeWindow* == NWindow*, so the window pointer passes through unchanged.
 *
 * What gets translated (everything else goes straight to NVK):
 *
 *   vkEnumerateInstanceExtensionProperties
 *       lists VK_KHR_android_surface when NVK reports VK_NN_vi_surface.
 *   vkCreateInstance
 *       rewrites VK_KHR_android_surface -> VK_NN_vi_surface in
 *       ppEnabledExtensionNames. NVK (vk_instance_init) rejects any extension
 *       it does not know with VK_ERROR_EXTENSION_NOT_PRESENT, so without this
 *       Unity's instance creation fails.
 *   vkCreateAndroidSurfaceKHR
 *       -> vkCreateViSurfaceNN.
 *   vkGetInstanceProcAddr
 *       hands out the shims above (and itself), passes the rest to NVK.
 *
 * Build modes:
 *   -DHAVE_NVK=1   libvulkan.a from the mesa-switch SDK is linked. The real
 *                  Vulkan headers from the SDK are used (no hand-copied
 *                  structs/enums), and the vk* functions are referenced
 *                  STRONGLY so the linker pulls them out of libvulkan.a.
 *                  (Weak references would not: ld never extracts an archive
 *                  member to satisfy a weak undefined symbol.)
 *   (default)      inert stub: vulkan_shim_resolve() returns NULL.
 */

#include <stdint.h>
#include <string.h>

#include "vulkan_shim.h"
#include "util.h" /* debugPrintf */

int vulkan_shim_is_vulkan_symbol(const char* symbol) {
  return symbol != NULL && symbol[0] == 'v' && symbol[1] == 'k';
}

#ifndef HAVE_NVK

int vulkan_shim_available(void) { return 0; }

void* vulkan_shim_resolve(const char* symbol) {
  (void)symbol;
  return NULL;
}

#else /* HAVE_NVK */

#if defined(__has_include)
#  if !__has_include(<vulkan/vulkan.h>)
#    error "HAVE_NVK is set but <vulkan/vulkan.h> was not found: add -I<mesa-sdk>/include"
#  endif
#endif

#define VK_USE_PLATFORM_VI_NN 1
#define VK_USE_PLATFORM_ANDROID_KHR 1
#include <vulkan/vulkan.h>

/* Upper bounds for the on-stack scratch arrays. Unity enables a handful of
 * instance extensions and NVK exposes ~30; anything above the cap is passed
 * through untouched instead of being translated. */
#define SHIM_MAX_INSTANCE_EXTS 128

static int streq(const char* a, const char* b) {
  return a != NULL && b != NULL && strcmp(a, b) == 0;
}

/* ---------------------------------------------------------------------------
 * vkCreateAndroidSurfaceKHR -> vkCreateViSurfaceNN
 * -------------------------------------------------------------------------*/
static VKAPI_ATTR VkResult VKAPI_CALL shim_CreateAndroidSurfaceKHR(
    VkInstance instance, const VkAndroidSurfaceCreateInfoKHR* pCreateInfo,
    const VkAllocationCallbacks* pAllocator, VkSurfaceKHR* pSurface) {
  if (pCreateInfo == NULL || pSurface == NULL ||
      pCreateInfo->sType != VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR ||
      pCreateInfo->window == NULL) {
    debugPrintf("[vulkan] vkCreateAndroidSurfaceKHR: invalid arguments\n");
    return VK_ERROR_INITIALIZATION_FAILED;
  }

  VkViSurfaceCreateInfoNN vi_info;
  memset(&vi_info, 0, sizeof(vi_info));
  vi_info.sType = VK_STRUCTURE_TYPE_VI_SURFACE_CREATE_INFO_NN;
  vi_info.pNext = pCreateInfo->pNext;
  vi_info.flags = 0; /* reserved */
  vi_info.window = (void*)pCreateInfo->window; /* ANativeWindow* == NWindow* */

  VkResult res = vkCreateViSurfaceNN(instance, &vi_info, pAllocator, pSurface);
  debugPrintf("[vulkan] vkCreateAndroidSurfaceKHR(window=%p) -> vkCreateViSurfaceNN = %d (surface=%p)\n",
              (void*)pCreateInfo->window, (int)res,
              res == VK_SUCCESS ? (void*)*pSurface : NULL);
  return res;
}

/* ---------------------------------------------------------------------------
 * vkCreateInstance: VK_KHR_android_surface -> VK_NN_vi_surface
 * -------------------------------------------------------------------------*/
static VKAPI_ATTR VkResult VKAPI_CALL shim_CreateInstance(
    const VkInstanceCreateInfo* pCreateInfo,
    const VkAllocationCallbacks* pAllocator, VkInstance* pInstance) {
  if (pCreateInfo == NULL || pCreateInfo->enabledExtensionCount == 0 ||
      pCreateInfo->ppEnabledExtensionNames == NULL ||
      pCreateInfo->enabledExtensionCount > SHIM_MAX_INSTANCE_EXTS) {
    return vkCreateInstance(pCreateInfo, pAllocator, pInstance);
  }

  const char* names[SHIM_MAX_INSTANCE_EXTS];
  uint32_t count = 0;
  int have_vi = 0;
  int translated = 0;

  for (uint32_t i = 0; i < pCreateInfo->enabledExtensionCount; i++) {
    if (streq(pCreateInfo->ppEnabledExtensionNames[i], VK_NN_VI_SURFACE_EXTENSION_NAME))
      have_vi = 1;
  }

  for (uint32_t i = 0; i < pCreateInfo->enabledExtensionCount; i++) {
    const char* name = pCreateInfo->ppEnabledExtensionNames[i];
    if (streq(name, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME)) {
      translated = 1;
      if (have_vi) continue; /* the native extension is already requested */
      name = VK_NN_VI_SURFACE_EXTENSION_NAME;
      have_vi = 1;
    }
    names[count++] = name;
  }

  if (!translated) return vkCreateInstance(pCreateInfo, pAllocator, pInstance);

  debugPrintf("[vulkan] vkCreateInstance: %s -> %s (%u extensions)\n",
              VK_KHR_ANDROID_SURFACE_EXTENSION_NAME,
              VK_NN_VI_SURFACE_EXTENSION_NAME, (unsigned)count);

  VkInstanceCreateInfo info = *pCreateInfo;
  info.enabledExtensionCount = count;
  info.ppEnabledExtensionNames = names;
  return vkCreateInstance(&info, pAllocator, pInstance);
}

/* ---------------------------------------------------------------------------
 * vkEnumerateInstanceExtensionProperties: advertise VK_KHR_android_surface
 * -------------------------------------------------------------------------*/
static VKAPI_ATTR VkResult VKAPI_CALL shim_EnumerateInstanceExtensionProperties(
    const char* pLayerName, uint32_t* pPropertyCount,
    VkExtensionProperties* pProperties) {
  if (pLayerName != NULL || pPropertyCount == NULL)
    return vkEnumerateInstanceExtensionProperties(pLayerName, pPropertyCount, pProperties);

  uint32_t n = 0;
  VkResult res = vkEnumerateInstanceExtensionProperties(NULL, &n, NULL);
  if (res != VK_SUCCESS || n > SHIM_MAX_INSTANCE_EXTS)
    return vkEnumerateInstanceExtensionProperties(NULL, pPropertyCount, pProperties);

  /* One spare slot for the translated entry. */
  VkExtensionProperties* all =
      (VkExtensionProperties*)__builtin_alloca(((size_t)n + 1) * sizeof(*all));
  res = vkEnumerateInstanceExtensionProperties(NULL, &n, all);
  if (res != VK_SUCCESS) return res;

  int has_vi = 0;
  int has_android = 0;
  for (uint32_t i = 0; i < n; i++) {
    if (streq(all[i].extensionName, VK_NN_VI_SURFACE_EXTENSION_NAME)) has_vi = 1;
    if (streq(all[i].extensionName, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME)) has_android = 1;
  }
  if (has_vi && !has_android) {
    memset(&all[n], 0, sizeof(all[n]));
    strncpy(all[n].extensionName, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME,
            VK_MAX_EXTENSION_NAME_SIZE - 1);
    all[n].specVersion = VK_KHR_ANDROID_SURFACE_SPEC_VERSION;
    n++;
  }

  if (pProperties == NULL) {
    *pPropertyCount = n;
    return VK_SUCCESS;
  }

  uint32_t out = *pPropertyCount < n ? *pPropertyCount : n;
  memcpy(pProperties, all, (size_t)out * sizeof(*all));
  *pPropertyCount = out;
  return out < n ? VK_INCOMPLETE : VK_SUCCESS;
}

/* ---------------------------------------------------------------------------
 * vkGetInstanceProcAddr: hand out the shims, forward the rest to NVK
 * -------------------------------------------------------------------------*/
static VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
shim_GetInstanceProcAddr(VkInstance instance, const char* pName);

static PFN_vkVoidFunction shim_lookup(const char* name) {
  if (streq(name, "vkGetInstanceProcAddr"))
    return (PFN_vkVoidFunction)shim_GetInstanceProcAddr;
  if (streq(name, "vkCreateInstance"))
    return (PFN_vkVoidFunction)shim_CreateInstance;
  if (streq(name, "vkEnumerateInstanceExtensionProperties"))
    return (PFN_vkVoidFunction)shim_EnumerateInstanceExtensionProperties;
  if (streq(name, "vkCreateAndroidSurfaceKHR"))
    return (PFN_vkVoidFunction)shim_CreateAndroidSurfaceKHR;
  return NULL;
}

static VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
shim_GetInstanceProcAddr(VkInstance instance, const char* pName) {
  PFN_vkVoidFunction fn = shim_lookup(pName);
  if (fn != NULL) {
    debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> SHIM %p\n", pName, fn);
    return fn;
  }
  PFN_vkVoidFunction real = vkGetInstanceProcAddr(instance, pName);
  // Log only surface/swapchain/device-related lookups to avoid spam
  if (pName && (strstr(pName, "Surface") || strstr(pName, "Swapchain") ||
                strstr(pName, "Device") || strstr(pName, "PhysicalDevice"))) {
    debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> NVK %p\n", pName, real);
  }
  return real;
}

/* ---------------------------------------------------------------------------
 * dlsym routing (called from dlsym_fake for "vk*" symbols)
 *
 * Besides the shimmed entry points, expose the other global-level functions a
 * loader normally exports. Everything else Unity needs it fetches through
 * vkGetInstanceProcAddr / vkGetDeviceProcAddr, which land in NVK.
 * -------------------------------------------------------------------------*/
int vulkan_shim_available(void) { return 1; }

void* vulkan_shim_resolve(const char* symbol) {
  PFN_vkVoidFunction fn = shim_lookup(symbol);
  if (fn == NULL) {
    if (streq(symbol, "vkGetDeviceProcAddr"))
      fn = (PFN_vkVoidFunction)vkGetDeviceProcAddr;
    else if (streq(symbol, "vkEnumerateInstanceLayerProperties"))
      fn = (PFN_vkVoidFunction)vkEnumerateInstanceLayerProperties;
    else if (streq(symbol, "vkEnumerateInstanceVersion"))
      fn = (PFN_vkVoidFunction)vkEnumerateInstanceVersion;
  }
  debugPrintf("[vulkan] dlsym(%s) -> %p\n", symbol != NULL ? symbol : "(null)", (void*)fn);
  return (void*)fn;
}

#endif /* HAVE_NVK */
