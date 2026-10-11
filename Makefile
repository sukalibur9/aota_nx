#---------------------------------------------------------------------------------
# THE ROOM: OLD SINS -- Nintendo Switch homebrew loader
# Fireproof Games / Unity 2021.3.8f1 / IL2CPP / arm64
# (forked from the The Room Three port -- same studio, same engine version,
#  every offset re-derived against this game's own binaries.)
#
# Requires devkitA64 plus these devkitPro portlibs:
#   pacman -S switch-dev
#   pacman -S switch-mesa switch-libdrm_nouveau switch-sdl2 switch-libpng switch-zlib
#
# Every .c under source/ is compiled automatically, so adding a file needs no
# edit here. nx_patch_os.h and unity_entrypoints.h are headers included by main.c.
#---------------------------------------------------------------------------------
.SUFFIXES:
ifeq ($(strip $(DEVKITPRO)),)
$(error "Set DEVKITPRO in your environment. (export DEVKITPRO=/opt/devkitpro)")
endif
TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules

TARGET      := aota_nx
APP_TITLE   := Tyrion Cuthbert: Attorney of the Arcane
APP_AUTHOR  := Muse
APP_VERSION := 1.0.0

# Icon: ours if present, else libnx's default, else no icon at all.
# elf2nro aborts with "Failed to open input icon!" if --icon points at a file
# that does not exist, so the flag is never passed unconditionally.
# Replace icon.jpg with your own any time -- 256x256 JPEG, RGB (not CMYK, not
# progressive), which is what the NRO asset section requires.
ifneq ($(wildcard $(TOPDIR)/icon.jpg),)
    APP_ICON := $(TOPDIR)/icon.jpg
else ifneq ($(wildcard $(LIBNX)/default_icon.jpg),)
    APP_ICON := $(LIBNX)/default_icon.jpg
endif
export APP_TITLE APP_AUTHOR APP_VERSION APP_ICON

BUILD    := build
SOURCES  := source
INCLUDES := source

ARCH    := -march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE

CFLAGS  := -g -Wall -O2 -ffunction-sections $(ARCH) $(DEFINES) \
           $(INCLUDE) -D__SWITCH__
CFLAGS  += -DLOAD_ADDRESS=0xC0000000
CXXFLAGS := $(CFLAGS) -fno-rtti -fno-exceptions -std=gnu++17
ASFLAGS := -g $(ARCH)
# --wrap routes allocations into the GPU arena in gpu_arena.c, and the nwindow
# calls through the buffer-queue logging in imports.c. THIS LIST AND THOSE
# FUNCTIONS MUST AGREE: a --wrap with no __wrap_ function is an
# undefined-reference error out of libEGL.a (mesa calls malloc/free too), and a
# __wrap_ function with no --wrap is silently dead code.
LDFLAGS  = -specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map) \
           -Wl,--wrap,free -Wl,--wrap,malloc -Wl,--wrap,memalign -Wl,--wrap,calloc \
           -Wl,--wrap,realloc -Wl,--wrap,memmove -Wl,--wrap,memcpy \
           -Wl,--wrap,nwindowDequeueBuffer -Wl,--wrap,nwindowQueueBuffer \
           -Wl,--wrap,nwindowCancelBuffer

# ---- ffmpeg, for the two cutscenes (os_video.c) -----------------------------
# The Room: Old Sins plays Ending.mp4 and Eyeball_argument.mp4 through the
# game's own iOSVideoManager -> Handheld.PlayFullScreenMovie, which on Android
# is handed to android.media.MediaPlayer. There is no MediaPlayer here, so the
# clips are decoded with ffmpeg instead.
#
#     sudo dkp-pacman -S switch-ffmpeg
#
# Set OS_VIDEO to 0 in source/config.h to drop the feature: os_video.c compiles
# to empty stubs needing no ffmpeg header and no ffmpeg library, FFMPEG_LINK
# becomes empty, and the two cutscenes are skipped. Nothing else uses ffmpeg.
OS_VIDEO_ON := $(shell grep -qE '^\s*#define\s+OS_VIDEO\s+1' $(TOPDIR)/source/config.h && echo 1)
ifeq ($(OS_VIDEO_ON),1)
  ifeq ($(wildcard $(DEVKITPRO)/portlibs/switch/include/libavcodec/avcodec.h),)
    $(warning ==============================================================)
    $(warning  switch-ffmpeg not found. Install it with:)
    $(warning     sudo dkp-pacman -S switch-ffmpeg)
    $(warning  Or build without the two cutscenes: set OS_VIDEO to 0 in)
    $(warning  source/config.h.)
    $(warning ==============================================================)
    $(error switch-ffmpeg missing -- see above)
  endif
  PKGCONF     := $(DEVKITPRO)/portlibs/switch/bin/aarch64-none-elf-pkg-config
  FFMPEG_PKGS := libavformat libavcodec libswresample libswscale libavutil
  FFMPEG_LIBS := $(shell $(PKGCONF) --static --libs $(FFMPEG_PKGS) 2>/dev/null)
  ifeq ($(strip $(FFMPEG_LIBS)),)
    FFMPEG_LIBS := -lavformat -lavcodec -lswresample -lswscale -lavutil \
                   -ldav1d -lass -lfribidi -lharfbuzz -lfreetype -lbz2
  endif
  # ffmpeg goes in a --start-group: the codec libraries reference each other
  # both ways and a single pass does not resolve them.
  FFMPEG_LINK := -Wl,--start-group $(FFMPEG_LIBS) -Wl,--end-group
else
  FFMPEG_LINK :=
endif

# mesa GLES3 + EGL + nouveau, SDL2 for window/HID/audio, libpng for the optional
# cursor.png (nx_pointer.c), zlib. -lpng must precede -lz: libpng calls into it.
# ffmpeg goes in a --start-group: the codec libraries reference each other both
# ways and a single pass does not resolve them.
# ---- Vulkan: mesa-switch NVK (statis, tanpa loader) --------------------------
# VULKAN_SDK harus berisi lib/libvulkan.a dan include/vulkan/vulkan.h.
VULKAN_SDK ?= $(HOME)/workspace/mesa-sdk
ifneq ($(wildcard $(VULKAN_SDK)/lib/libvulkan.a),)
  $(info [build] mesa-switch Vulkan SDK found: $(VULKAN_SDK))
  # -DHAVE_NVK=1 mengaktifkan shim (referensi strong -> linker menarik NVK dari
  # libvulkan.a) dan memakai header Vulkan asli dari SDK.
  VULKAN_CFLAGS := -DHAVE_NVK=1 -I$(VULKAN_SDK)/include
  # Urutan link mengikuti metadata SDK sendiri (vulkan.pc / VulkanConfig.cmake):
  # libvulkan.a adalah archive gabungan; dependensinya harus ikut di grup.
  # -lelf hanya ditambahkan kalau switch-libelf terpasang (libvulkan.a hasil
  # build mesa-switch tidak mereferensikan simbol elf_* sama sekali, jadi aman
  # dilewati kalau tidak ada).
  ELF_LIB := $(if $(wildcard $(DEVKITPRO)/portlibs/switch/lib/libelf.a),-lelf,)
  # libvulkan.a "unified" dari SDK tidak bisa di-link langsung (anggotanya
  # duplikat: objek Rust std/core terkompilasi dua kali dengan hash berbeda).
  # Pakai arsip komponennya sebagai g gantinya, dalam satu --start-group.
  VULKAN_LIBS := -Wl,--start-group -L$(VULKAN_SDK)/lib \
                 -lnvk -lnak_rs -lnak -lvulkan_util -lcompiler \
                 -lcompiler_c_helpers -lnir -lmesa_util -lmesa_util_c11 \
                 -lmesa_util_simd -lblake3 -lnouveau_ws -lnouveau_mme \
                 -lnouveau_horizon -lnil -llibnil_format_table -lvtn -lxmlconfig \
                 -lnvidia_headers_c \
                 $(ELF_LIB) -lexpat -lzstd -lz -lnx -lstdc++ -lm -Wl,--end-group -Wl,--allow-multiple-definition
else
  $(info [build] mesa-switch Vulkan SDK not found: shim Vulkan tidak aktif)
  VULKAN_CFLAGS :=
  VULKAN_LIBS   :=
endif
CFLAGS += $(VULKAN_CFLAGS)

LIBS := -lSDL2 -lGLESv2 -lEGL -lglapi -ldrm_nouveau \
        $(FFMPEG_LINK) \
        $(VULKAN_LIBS) \
        -lpng -lbz2 -lz -lnx -lm

LIBDIRS := $(PORTLIBS) $(LIBNX)

ifneq ($(BUILD),$(notdir $(CURDIR)))
export OUTPUT  := $(CURDIR)/$(TARGET)
export TOPDIR  := $(CURDIR)
export VPATH   := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir))
export DEPSDIR := $(CURDIR)/$(BUILD)

CFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES   := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))

export LD := $(CXX)
export OFILES := $(addsuffix .o,$(SFILES)) $(CPPFILES:.cpp=.o) $(CFILES:.c=.o)
export INCLUDE := $(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
                  $(foreach dir,$(LIBDIRS),-I$(dir)/include) \
                  -I$(PORTLIBS)/include/SDL2 -I$(CURDIR)/$(BUILD)
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

.PHONY: all clean
all: $(BUILD)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile
$(BUILD):
	@mkdir -p $@
clean:
	@rm -fr $(BUILD) $(TARGET).nro $(TARGET).nacp $(TARGET).elf
else
DEPENDS := $(OFILES:.o=.d)
NROFLAGS := --nacp=$(OUTPUT).nacp
ifneq ($(strip $(APP_ICON)),)
    NROFLAGS += --icon=$(APP_ICON)
endif
all : $(OUTPUT).nro
$(OUTPUT).nro : $(OUTPUT).elf $(OUTPUT).nacp
$(OUTPUT).elf : $(OFILES)
-include $(DEPENDS)
endif
