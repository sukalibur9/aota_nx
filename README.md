# AOTA NX

**AOTA NX** is an experimental Nintendo Switch homebrew wrapper for **Tyrion Cuthbert: Attorney of the Arcane**, a Unity IL2CPP game.

The project provides the native runtime compatibility layer needed to launch and run the Android game assets on Switch, including Unity/IL2CPP loading, JNI and libc compatibility shims, graphics and audio bridges, configuration, logging, and exception diagnostics.

> [!WARNING]
> This repository is provided for interoperability and research purposes. You need a legally obtained copy of the game and must supply compatible Android game files yourself. The repository does not contain game binaries or copyrighted assets.

## Features

- Nintendo Switch/NRO build using devkitA64 and libnx
- Unity and IL2CPP shared-library loading
- Android JNI compatibility layer
- GLES/EGL and Vulkan/OpenGL compatibility shims
- SDL2 input and presentation support
- Audio compatibility through OpenSLES and AAudio shims
- Runtime configuration and debug logging
- Asset loading and file-system compatibility
- Exception dumps and diagnostic tracing

## Requirements

### For building

- Nintendo Switch homebrew development environment
- [devkitPro](https://devkitpro.org/) with `DEVKITPRO=/opt/devkitpro`
- `switch-dev`
- `switch-mesa`
- `switch-libdrm_nouveau`
- `switch-sdl2`
- `switch-libpng`
- `switch-zlib`

Install the base requirements with devkitPro's package manager:

```sh
pacman -S switch-dev
pacman -S switch-mesa switch-libdrm_nouveau switch-sdl2 switch-libpng switch-zlib
```

Optional video support requires `switch-ffmpeg`:

```sh
pacman -S switch-ffmpeg
```

Video playback is disabled by default (`OS_VIDEO 0` in `source/config.h`). To enable it, set `OS_VIDEO` to `1` and install `switch-ffmpeg`.

A Mesa-switch Vulkan SDK is optional. If available, set `VULKAN_SDK` to the SDK directory; the Makefile otherwise builds the Vulkan shim without its stronger NVK path:

```sh
export VULKAN_SDK=$HOME/workspace/mesa-sdk
```

## Building

Set `DEVKITPRO` and build the project:

```sh
export DEVKITPRO=/opt/devkitpro
make
```

The build produces:

```text
aota_nx.nro
aota_nx.nacp
aota_nx.elf
```

Clean generated files with:

```sh
make clean
```

All C source files in `source/` are discovered automatically by the Makefile.

## Installation

1. Build `aota_nx.nro` or obtain a release package.
2. Copy the NRO to a Nintendo Switch SD-card location, such as:

   ```text
   sdmc:/switch/aota_nx/aota_nx.nro
   ```

3. Place the required game files in a compatible `aota` directory, or next to the NRO. The loader resolves the game root dynamically and can detect a matching installation below `sdmc:/switch`.
4. Launch the NRO through your homebrew launcher.

Debug output is written to `debug.log` beside the NRO when `DEBUG_LOG` is enabled.

## Configuration

Runtime settings can be saved in `config.txt`. The build also contains compile-time tuning in `source/config.h`, including:

- handheld and docked resolution
- target frame rate
- memory and graphics reserve values
- game package and folder identity
- debug and tracing switches
- optional full-screen video playback
- language behavior

Change these values only after understanding their memory and runtime implications. Several settings are tightly coupled to Unity's allocator and graphics behavior.

## Project layout

```text
source/
├── main.c                 NRO entry point and runtime initialization
├── config.*               Runtime and compile-time configuration
├── unity_*.*              Unity and IL2CPP integration
├── jni_*.*                Android/JNI compatibility
├── aaudio_shim.*          Android audio compatibility
├── opensles.*             OpenSL ES compatibility
├── os_video.*             Optional full-screen video playback
├── vulkan_shim.*          Vulkan compatibility shims
├── gpu_arena.c            GPU allocation arena
├── libc_shim.c            libc and allocator compatibility
└── nx_exception_dump.c    On-device exception diagnostics
```

## Development notes

- The Makefile compiles every `.c` file under `source/` automatically.
- Release NROs and build artifacts are intentionally excluded by `.gitignore`.
- Game binaries, extracted assets, reverse-engineering scratch files, and runtime logs belong outside version control.
- Bundle I/O and memory-protection tracing are disabled in normal builds because they can significantly slow loading.

## License

No license file is currently included in this repository. Check with the repository owner before reusing or redistributing this project.
