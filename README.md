# aota_nx

**aota_nx** is a Nintendo Switch homebrew wrapper for **Tyrion Cuthbert: Attorney of the Arcane**, a Unity IL2CPP application.

It loads and adapts the game's Android-side runtime, Unity, native libraries, audio, graphics, input, and assets to run under Nintendo Switch libnx. This repository contains the native wrapper and compatibility layer; it does not include the game's proprietary files or installation media.

> **Project status:** experimental. Compatibility, performance, and feature support may vary.

## Features

The wrapper provides Nintendo Switch-facing implementations for several Android/Unity subsystems, including:

- ARM64 shared-library loading and Unity entry points
- SDL2, OpenGL ES/EGL, and optional Vulkan/NVK graphics paths
- Audio through AAudio/OpenSLES compatibility shims
- Native input and surface glue
- Asset-pack and game-root discovery
- FFmpeg-backed video playback when enabled
- Diagnostics and exception-dump support
- GPU-backed memory/allocation handling

## Requirements

### Building

- A Nintendo Switch development environment
- devkitA64 / devkitPro
- `switch-dev`
- Port libraries:
  - `switch-mesa`
  - `switch-libdrm_nouveau`
  - `switch-sdl2`
  - `switch-libpng`
  - `switch-zlib`
- Optional: `switch-ffmpeg` for video playback
- Optional: a compatible mesa-switch/Vulkan SDK for the Vulkan/NVK path

Set `DEVKITPRO` and install the dependencies:

```bash
export DEVKITPRO=/opt/devkitpro
sudo dkp-pacman -S switch-dev switch-mesa switch-libdrm_nouveau switch-sdl2 switch-libpng switch-zlib
```

Install FFmpeg if video playback is needed:

```bash
sudo dkp-pacman -S switch-ffmpeg
```

## Building

```bash
git clone https://github.com/sukalibur9/aota_nx.git
cd aota_nx
make
```

The Makefile compiles every `.c` file in `source/` automatically and produces:

```text
aota_nx.nro
build/
```

Remove generated artifacts with:

```bash
make clean
```

By default, `Makefile` uses the libnx icon if `icon.jpg` is not present. A custom icon may be placed at `icon.jpg` in the repository root. It must be a 256×256 RGB JPEG.

## Configuration

Build and feature settings are in [`source/config.h`](source/config.h).

Video playback is controlled by:

```c
#define OS_VIDEO 1
```

Set it to `0` to build without FFmpeg and disable video playback:

```c
#define OS_VIDEO 0
```

Vulkan support is detected automatically when a compatible mesa-switch SDK is found at:

```text
~/workspace/mesa-sdk
```

Override that location with `VULKAN_SDK`:

```bash
make VULKAN_SDK=/path/to/mesa-sdk
```

## Installation

This project does not redistribute or generate the original game's content. Obtain the Android game files legally and provide only assets/data that you are entitled to use.

Install `aota_nx.nro` in the Switch homebrew applications directory:

```text
sdmc:/switch/aota_nx/aota_nx.nro
```

The wrapper may require appropriately obtained game assets and shared libraries in the location recognized by `source/game_root.c` and `source/asset_pack.c`. See those files and `source/config.h` for the expected layout.

Do not commit proprietary game files, private keys, dumps, or paid assets.

## Project Layout

```text
.
├── Makefile                 # devkitA64/libnx build configuration
└── source/
    ├── main.c               # NRO entry point
    ├── config.h             # Feature switches and configuration
    ├── so_util.*            # Shared-object loading utilities
    ├── unity_*.*            # Unity entry-point and Android/JNI glue
    ├── gpu_arena.c          # GPU-backed allocation arena
    ├── aaudio_shim.*        # Android AAudio compatibility
    ├── opensles.*           # OpenSLES compatibility
    ├── os_video.*           # FFmpeg-based video playback
    ├── vulkan_shim.*        # Vulkan compatibility/shim support
    ├── nx_fonts.*           # Nintendo Switch font handling
    ├── nx_exception_dump.c  # Exception diagnostics
    └── ...                  # Additional Android/native compatibility layers
```

## Development Notes

- The build target is `arm64`/`aarch64` and uses `-march=armv8-a+crc+crypto -mtp=soft`.
- The loader is configured for a base address of `0xC0000000`.
- Allocation and selected libnx window-buffer functions are wrapped to route through the wrapper implementation.
- Add new `.c` or `.cpp` source files beneath `source/`; the Makefile discovers them automatically.
- Start with `main.c`, `game_root.c`, `config.h`, and `unity_entrypoints.h` when tracing startup.

## Troubleshooting

### `DEVKITPRO` is not set

```bash
export DEVKITPRO=/opt/devkitpro
```

### `switch-ffmpeg` is missing

Install it:

```bash
sudo dkp-pacman -S switch-ffmpeg
```

or disable videos in `source/config.h`:

```c
#define OS_VIDEO 0
```

### Vulkan build falls back

A missing mesa-switch/Vulkan SDK is safe: the build logs this and uses the non-NVK path. Set `VULKAN_SDK` only when the SDK is installed correctly.

### The game cannot find assets

Verify that:

1. The game data was obtained legally and is complete.
2. The asset location matches the paths used by the wrapper.
3. SD card permissions and file names are correct.
4. The wrapper configuration matches the target game build.

## Contributing

Contributions are welcome for compatibility fixes, build-system improvements, diagnostics, and documentation.

Please do not submit copyrighted game data, decrypted assets, private keys, credentials, or unrelated proprietary files.

## License

No license is currently specified for this repository. Until a license is added, use and redistribution rights are not explicitly granted.

## Disclaimer

This project is an unofficial compatibility wrapper and is not affiliated with or endorsed by the game developers or publisher. Nintendo Switch is a trademark of Nintendo.
