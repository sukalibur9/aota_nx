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

/* --- Call-tracing wrappers for surface functions (build #54) ---
 * Wrap NVK surface entry points to log the CALL (not just the lookup).
 * If Unity crashes inside one of these, the last log line identifies it. */

static PFN_vkGetPhysicalDeviceSurfaceSupportKHR g_real_GetSurfaceSupport = NULL;
static PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR g_real_GetSurfaceCaps = NULL;
static PFN_vkGetPhysicalDeviceSurfaceFormatsKHR g_real_GetSurfaceFormats = NULL;
static PFN_vkGetPhysicalDeviceSurfacePresentModesKHR g_real_GetPresentModes = NULL;
static PFN_vkCreateSwapchainKHR g_real_CreateSwapchain = NULL;

static VKAPI_ATTR VkResult VKAPI_CALL
trace_GetSurfaceSupport(VkPhysicalDevice pd, uint32_t qi, VkSurfaceKHR s, VkBool32* sup) {
  debugPrintf("[vulkan] CALL vkGetPhysicalDeviceSurfaceSupportKHR(pd=%p qi=%u surf=%p)\n",
              (void*)pd, qi, (void*)s);
  VkResult r = g_real_GetSurfaceSupport(pd, qi, s, sup);
  debugPrintf("[vulkan] RET vkGetPhysicalDeviceSurfaceSupportKHR = %d (supported=%d)\n",
              r, sup ? *sup : -1);
  return r;
}

static VKAPI_ATTR VkResult VKAPI_CALL
trace_GetSurfaceCaps(VkPhysicalDevice pd, VkSurfaceKHR s, VkSurfaceCapabilitiesKHR* caps) {
  debugPrintf("[vulkan] CALL vkGetPhysicalDeviceSurfaceCapabilitiesKHR(pd=%p surf=%p)\n",
              (void*)pd, (void*)s);
  VkResult r = g_real_GetSurfaceCaps(pd, s, caps);
  debugPrintf("[vulkan] RET vkGetPhysicalDeviceSurfaceCapabilitiesKHR = %d\n", r);
  if (r == 0 && caps) {
    debugPrintf("[vulkan]   caps: minImg=%u maxImg=%u curExtent=%ux%u\n",
                caps->minImageCount, caps->maxImageCount,
                caps->currentExtent.width, caps->currentExtent.height);
    debugPrintf("[vulkan]   caps: maxExtent=%ux%u transform=0x%x alpha=0x%x usage=0x%x\n",
                caps->maxImageExtent.width, caps->maxImageExtent.height,
                caps->supportedTransforms, caps->supportedCompositeAlpha, caps->supportedUsageFlags);
  }
  return r;
}

static VKAPI_ATTR VkResult VKAPI_CALL
trace_GetSurfaceFormats(VkPhysicalDevice pd, VkSurfaceKHR s, uint32_t* n, VkSurfaceFormatKHR* f) {
  debugPrintf("[vulkan] CALL vkGetPhysicalDeviceSurfaceFormatsKHR(pd=%p surf=%p)\n",
              (void*)pd, (void*)s);
  VkResult r = g_real_GetSurfaceFormats(pd, s, n, f);
  debugPrintf("[vulkan] RET vkGetPhysicalDeviceSurfaceFormatsKHR = %d (count=%u)\n",
              r, n ? *n : 0);
  if (r == 0 && f && n) {
    for (uint32_t i = 0; i < *n && i < 8; i++) {
      debugPrintf("[vulkan]   format[%u]: format=%d colorspace=%d\n",
                  i, (int)f[i].format, (int)f[i].colorSpace);
    }
  }
  return r;
}

static VKAPI_ATTR VkResult VKAPI_CALL
trace_GetPresentModes(VkPhysicalDevice pd, VkSurfaceKHR s, uint32_t* n, VkPresentModeKHR* m) {
  debugPrintf("[vulkan] CALL vkGetPhysicalDeviceSurfacePresentModesKHR(pd=%p surf=%p)\n",
              (void*)pd, (void*)s);
  VkResult r = g_real_GetPresentModes(pd, s, n, m);
  debugPrintf("[vulkan] RET vkGetPhysicalDeviceSurfacePresentModesKHR = %d (count=%u)\n",
              r, n ? *n : 0);
  if (r == 0 && m && n) {
    for (uint32_t i = 0; i < *n && i < 8; i++) {
      debugPrintf("[vulkan]   presentMode[%u]: %d\n", i, (int)m[i]);
    }
  }
  return r;
}

static VKAPI_ATTR VkResult VKAPI_CALL
trace_CreateSwapchain(VkDevice dev, const VkSwapchainCreateInfoKHR* ci, const VkAllocationCallbacks* al, VkSwapchainKHR* sc) {
  VkSwapchainCreateInfoKHR fixed;
  const VkSwapchainCreateInfoKHR* use_ci = ci;
  if (ci) {
    debugPrintf("[vulkan] CALL vkCreateSwapchainKHR(dev=%p surf=%p)\n", (void*)dev, (void*)ci->surface);
    debugPrintf("[vulkan]   extent=%ux%u format=%d colorspace=%d presentMode=%d\n",
                ci->imageExtent.width, ci->imageExtent.height,
                (int)ci->imageFormat, (int)ci->imageColorSpace, (int)ci->presentMode);
    debugPrintf("[vulkan]   imageCount=%u arrayLayers=%u usage=0x%x sharingMode=%d\n",
                ci->minImageCount, ci->imageArrayLayers, ci->imageUsage, (int)ci->imageSharingMode);
    debugPrintf("[vulkan]   preTransform=%d compositeAlpha=0x%x clipped=%d oldSwapchain=%p\n",
                (int)ci->preTransform, ci->compositeAlpha, ci->clipped, (void*)ci->oldSwapchain);
    /* Build #56 fix: Unity passes VK_FORMAT_UNDEFINED (0). NVK rejects it.
     * Substitute a widely-supported format. */
    if (ci->imageFormat == 0 /* VK_FORMAT_UNDEFINED */) {
      fixed = *ci;
      fixed.imageFormat = 44 /* VK_FORMAT_B8G8R8A8_UNORM */;
      use_ci = &fixed;
      debugPrintf("[vulkan]   FIX: format 0 -> 44 (B8G8R8A8_UNORM)\n");
    }
    /* Build #57 fix: NVK returns -8 (FEATURE_NOT_PRESENT) for usage=0x93.
     * Strip to COLOR_ATTACHMENT only, which all swapchains support. */
    if (use_ci->imageUsage != 0x10) {
      if (use_ci != &fixed) fixed = *use_ci;
      fixed.imageUsage = 0x10 /* VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT */;
      use_ci = &fixed;
      debugPrintf("[vulkan]   FIX: usage 0x%x -> 0x10 (COLOR_ATTACHMENT)\n", ci->imageUsage);
    }
  } else {
    debugPrintf("[vulkan] CALL vkCreateSwapchainKHR(dev=%p, ci=NULL!)\n", (void*)dev);
  }
  VkResult r = g_real_CreateSwapchain(dev, use_ci, al, sc);
  debugPrintf("[vulkan] RET vkCreateSwapchainKHR = %d (swapchain=%p)\n", r, (void*)(sc ? *sc : 0));
  return r;
}

static VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
shim_GetInstanceProcAddr(VkInstance instance, const char* pName) {
  PFN_vkVoidFunction fn = shim_lookup(pName);
  if (fn != NULL) {
    debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> SHIM %p\n", pName, fn);
    return fn;
  }
  PFN_vkVoidFunction real = vkGetInstanceProcAddr(instance, pName);
  // Intercept surface/swapchain calls with tracing wrappers (build #54)
  if (pName) {
    if (streq(pName, "vkGetPhysicalDeviceSurfaceSupportKHR")) {
      g_real_GetSurfaceSupport = (PFN_vkGetPhysicalDeviceSurfaceSupportKHR)real;
      debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> TRACE_WRAPPER\n", pName);
      return (PFN_vkVoidFunction)trace_GetSurfaceSupport;
    }
    if (streq(pName, "vkGetPhysicalDeviceSurfaceCapabilitiesKHR")) {
      g_real_GetSurfaceCaps = (PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR)real;
      debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> TRACE_WRAPPER\n", pName);
      return (PFN_vkVoidFunction)trace_GetSurfaceCaps;
    }
    if (streq(pName, "vkGetPhysicalDeviceSurfaceFormatsKHR")) {
      g_real_GetSurfaceFormats = (PFN_vkGetPhysicalDeviceSurfaceFormatsKHR)real;
      debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> TRACE_WRAPPER\n", pName);
      return (PFN_vkVoidFunction)trace_GetSurfaceFormats;
    }
    if (streq(pName, "vkGetPhysicalDeviceSurfacePresentModesKHR")) {
      g_real_GetPresentModes = (PFN_vkGetPhysicalDeviceSurfacePresentModesKHR)real;
      debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> TRACE_WRAPPER\n", pName);
      return (PFN_vkVoidFunction)trace_GetPresentModes;
    }
    if (streq(pName, "vkCreateSwapchainKHR")) {
      g_real_CreateSwapchain = (PFN_vkCreateSwapchainKHR)real;
      debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> TRACE_WRAPPER\n", pName);
      return (PFN_vkVoidFunction)trace_CreateSwapchain;
    }
    // Log other surface/swapchain/device lookups to avoid spam
    if (strstr(pName, "Surface") || strstr(pName, "Swapchain") ||
        strstr(pName, "Device") || strstr(pName, "PhysicalDevice")) {
      debugPrintf("[vulkan] GetInstanceProcAddr(%s) -> NVK %p\n", pName, real);
    }
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
