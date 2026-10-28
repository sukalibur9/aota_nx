# aota_nx — Switch wrapper for Tyrion Cuthbert: Attorney of the Arcane

Loader-style homebrew wrapper that runs the Android game
"Tyrion Cuthbert: Attorney of the Arcane" v57 (Unity 6000.5.8f1, IL2CPP)
on Nintendo Switch (CFW). Contains no game code — the user supplies
their own legally-owned APK dump.

## Status

⚠️ **Not yet playable.** The game boots on Switch but currently stops at a black screen and crashes while loading — playable gameplay has not been reached yet. Development is ongoing, and **your help is greatly needed**: if you have experience with Switch homebrew, Unity IL2CPP internals, or native crash debugging, any help — code, testing, or analysis — is very welcome.

## Building (GitHub Actions — works from a phone, no PC needed)

One-time setup:

1. **Publish the SDK as a Release asset** in the `sukalibur9/mesa-switch`
   repo (the workflow fetches it from there):
   - Open the repo in a mobile browser → **Releases** → **Draft a new release**.
   - Tag: `sdk-26.2.3`, title anything, e.g. "Mesa Switch SDK 26.2.3".
   - Upload the 48 MB SDK zip (`mesa-26.2.3-switch-unified-horizon-sdk.zip`
     from the Artifacts of run 38102248894) — **name it `mesa-sdk.zip`**.
   - **Publish release**.
2. **Create a new repo**, e.g. `sukalibur9/aota_nx` (public or private, your choice).
3. In the new repo: **Add file → Upload files**, then drag the entire contents
   of this folder (`source/`, `Makefile`, `README.md`, `.github/`) → **Commit changes**.
   (Web upload supports many files at once, including the `.github` folder.)

Every time you want to build:

4. Open the **Actions** tab → **Build aota_nx NRO** → **Run workflow** → **Run workflow**.
5. Wait about 10–20 minutes until it finishes (green).
6. Download the **`aota_nx-vulkan-nro`** artifact → you get `aota_nx.nro`, ready to test on Switch.

The build uses:
- The `devkitpro/devkita64` Docker image (official devkitPro toolchain —
  no newlib/libnx ABI mismatch issues like on the VM)
- The mesa-switch SDK (NVK Vulkan driver) from the public Release asset above

## Local build (requires a PC + devkitPro)

```
export VULKAN_SDK=/path/to/mesa-sdk
make clean && make
```

`VULKAN_SDK` must contain `lib/libvulkan.a` and `include/vulkan/vulkan.h`.

## Vulkan WSI shim (v2)

`source/vulkan_shim.c` translates Unity's Android WSI calls
(`VK_KHR_android_surface` / `vkCreateAndroidSurfaceKHR`) to NVK's
Horizon WSI (`VK_NN_vi_surface` / `vkCreateViSurfaceNN`).

Verified with 45 host-side unit tests (`test/run_tests.sh` in the
original patch package).
