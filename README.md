# aota_nx — Switch wrapper for Tyrion Cuthbert: Attorney of the Arcane

Loader-style homebrew wrapper that runs the Android game
"Tyrion Cuthbert: Attorney of the Arcane" v57 (Unity 6000.5.8f1, IL2CPP)
on Nintendo Switch (CFW). Contains no game code — the user supplies
their own legally-owned APK dump.

## Building (GitHub Actions — bisa dari HP, tanpa PC)

Persiapan sekali saja:

1. **Publikasikan SDK sebagai Release asset** di repo `sukalibur9/mesa-switch`
   (workflow mengambilnya dari sini):
   - Buka repo di browser HP → **Releases** → **Draft a new release**.
   - Tag: `sdk-26.2.3`, title bebas mis. "Mesa Switch SDK 26.2.3".
   - Upload file zip SDK 48 MB (`mesa-26.2.3-switch-unified-horizon-sdk.zip`
     dari Artifacts run 38102248894) — **beri nama `mesa-sdk.zip`**.
   - **Publish release**.
2. **Buat repo baru** mis. `sukalibur9/aota_nx` (public atau private, bebas).
3. Di repo baru: **Add file → Upload files**, lalu drag semua isi folder ini
   (`source/`, `Makefile`, `README.md`, `.github/`) → **Commit changes**.
   (Upload web mendukung banyak file sekaligus, termasuk folder `.github`.)

Setiap kali mau build:

4. Buka tab **Actions** → **Build aota_nx NRO** → **Run workflow** → **Run workflow**.
5. Tunggu ±10–20 menit sampai selesai (hijau).
6. Download artifact **`aota_nx-vulkan-nro`** → dapat `aota_nx.nro` siap dites di Switch.

Build memakai:
- `devkitpro/devkita64` Docker image (toolchain devkitPro resmi — tidak ada
  masalah ABI newlib/libnx seperti di VM)
- mesa-switch SDK (driver Vulkan NVK) dari Release asset publik di atas

## Local build (butuh PC + devkitPro)

```
export VULKAN_SDK=/path/to/mesa-sdk
make clean && make
```

`VULKAN_SDK` harus berisi `lib/libvulkan.a` dan `include/vulkan/vulkan.h`.

## Vulkan WSI shim (v2)

`source/vulkan_shim.c` translates Unity's Android WSI calls
(`VK_KHR_android_surface` / `vkCreateAndroidSurfaceKHR`) to NVK's
Horizon WSI (`VK_NN_vi_surface` / `vkCreateViSurfaceNN`).

Verified with 45 host-side unit tests (`test/run_tests.sh` in the
original patch package).
