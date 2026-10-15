# iPhone OS 1.0 binary emulation lab

This lab targets the original iPhone (`iPhone1,1`, `m68ap`), iPhone OS **1.0 / 1A543a**. It uses Apple's original ARM binaries with an experimental S5L8900 machine based on devos50's first-generation iPod touch QEMU branch. **A full boot to the original SpringBoard UI has not been verified.**

## What has been verified

| Path | Evidence | Verified result and boundary |
| --- | --- | --- |
| Firmware acquisition and extraction | `firmware-source.json`; `firmware/1A543a/extraction-report.json` | Exact Apple-hosted IPSW, size and SHA-256 checked; firmware wrappers, root filesystem decryption, and HFSX expansion checked. |
| Four-bank NAND input | `reports/nand-m68-4bank-generation.json`; `reports/nand-m68-4bank-verification.json` | Synthetic C000 metadata uses four active banks and 512 virtual pages/block, matching the original device-tree disk bank mask `0x0f`. All 94,538 HFS data pages reconstruct the input filesystem SHA-256 exactly. This byte verifier does not run a guest. |
| Original iBoot-159 storage boot | `reports/iboot-fourbank-*.json`; `reports/m68-fourbank-iboot-debug/` | Original storage initialization, mount and kernel-read return values are zero on the four-bank input. iBoot reads 3,260,467 bytes of the original system kernelcache and enters the genuine system kernel. The normal capture records QEMU SHA-256 `2c7f61f5912109dd80454f33db52cf6a96b72262515c34222c57eff3dc2248a6`. |
| Kernel root filesystem and userland | `reports/m68-fourbank-iboot-debug/serial.log`; `reports/m68-userland-processes-early.json`; `reports/m68-userland-threads.json` | ARM1176 runs Darwin 9.0.0d1 / xnu-933.0.0.178. The kernel discovers `disk0s1`, mounts it as `/`, and starts genuine userland. Guest process inspection finds `launchd` PID 1 and `SpringBoard` PID 12. Process/thread presence does not establish UI rendering. |
| Normal boot framebuffer | `reports/adm-c000-layout-analysis.json`; `reports/m68-userland-long/` | The corrected CLCD window-2 model captures the original Apple boot logo at 320 × 480, 1,280 bytes/row, pixel format 6 / BGRX storage. The 600-second normal capture still shows that logo, including after a modeled Home-key request. SpringBoard UI remains unverified. |
| Direct original-kernel diagnostic | `reports/lcd-handoff-analysis.json`; `reports/m68-fourbank-direct/` | Corrected synthesized LCD handoff produces a valid `0x96000`-byte framebuffer range and AppleMBX registers AppleH1CLCD. The four-bank direct-entry capture still waits for `disk0s1`. It bypasses iBoot and does not reproduce the successful normal storage handoff. |
| Writable NAND overlay | `reports/nand-overlay-tests.json` | 3,306 production page, persistence, publication and FIFO assertions plus seven rejected-input cases pass with AddressSanitizer and UndefinedBehaviorSanitizer. Guest writes use a separate per-run overlay. Concurrent publication, controller timing, FTL consistency and DMA are outside this unit check. |
| Zephyr 1 SPI parser | `reports/zephyr1-packet-tests.json` | 170 packet/state assertions and four explicit rejection cases pass with AddressSanitizer and UndefinedBehaviorSanitizer. GPIO chip-select, interrupts, timing, controller firmware execution and touch interaction are not covered. |
| Original touchscreen driver initialization | `reports/m68-normal-current/serial.log` | AppleMultitouchSPI reports downloading 44,752 bytes of its original firmware through the integrated model. Touch-controller firmware CPU execution and usable touch interaction are not established. |
| Complete original UI | No acceptance evidence yet | SpringBoard rendering and usable touch/Home interaction remain unverified. |

The normal path now reaches the original userland after correcting the C000 ADM/FMC layout and active NAND geometry. Live inspection found a sustained **UART1 interrupt 25** in `reports/m68-userland-vic-samples.json`; this is not a GPIO interrupt. Temporarily masking it as a diagnostic stops the interrupt storm, but does not produce SpringBoard UI. A source correction for the older UART behavior is pending a fresh runtime check, so the existing captures do not establish its effect.

Source changes awaiting a new build add the original S5L8900 UART interrupt layout, timer4 countdown/readback, and GPIO level/polarity handling. `reports/m68-uart-legacy-analysis.json`, `reports/m68-timer-fidelity.json`, and `reports/m68-button-polarity.json` preserve their binary and device-tree evidence. Original Home and Power descriptors use high-level interrupts with guest-managed polarity flipping; the modeled inputs now start low and become high on a press. The N45-only TVOut memory workaround is also excluded from M68 RAM. These prepared changes have not yet been exercised in a rebuilt guest.

Static display analysis confirms that LayerKit's default software surface is BGRA, which the current LCD model accepts. A failed MBXConnect clock-gating property request can also enable an automatic OGL route for certain render flags; that route has not been observed in this guest. `reports/m68-display-static-contract.json` and `reports/mbx-clockgate-auto-ogl-analysis.json` identify the return, flag and draw-call probes needed before changing graphics configuration. Multiple-plane composition and 16-bit pixel formats remain model limits, with no evidence yet tying them to the retained logo.

Timing fidelity is also incomplete. A normal boot with `--icount 6` hits the USB Wrangler notification-order panic in `reports/m68-userland-clock6/`; the current default `--icount 2` reaches userland without that observed panic. Changing the clock mode is an experimental diagnostic, not a resolution of the underlying race. The earlier analysis is in `reports/usb-wrangler-panic.json`.

The historical framebuffer capture is omitted from this public source snapshot.

Historical report tags can refer to older emulator binaries. `boot.py` now records the QEMU binary SHA-256 and preserves earlier captures if a later capture fails. A successful QEMU build, a QMP `running` response, a successful screenshot request, or exit code zero after the capture script sends `quit` does **not** establish guest boot. The script deliberately records `full_boot_verified: false`; assess serial output, guest registers, framebuffer contents and interaction separately. The updated capture helper returns a nonzero script status for QEMU/capture/protocol failures; this tooling change also awaits the next run.

## Current local layout

| Location | Purpose |
| --- | --- |
| `firmware/` | Verified IPSW, separate S5L8900 BootROM artifact, extracted Apple components and original HFSX image. |
| `tools/` | Acquisition, extraction, storage generation, bounded boot capture and static/debug inspection tools. |
| `vendor/qemu/` | Pinned upstream QEMU source with local emulator changes. |
| `patches/qemu-iphoneos1.patch` | Consolidated emulator patch against commit `501c85c4f8a3503965e38d5d4f30a02c4bc9171c`. Apply this to a clean checkout; individual patches are overlapping historical snapshots. |
| `reports/` | Commands, captured logs, register/memory observations and analysis. |
| `/path/to/developer/iphoneos1-qemu-source` | Symlink to the source, because QEMU 6.2 rejects whitespace in configure paths. |
| `/path/to/developer/iphoneos1-qemu-build` | Host build; `qemu-system-arm` and `qemu-img`. |
| `/path/to/developer/iphoneos1-lab-runtime/1A543a` | Runtime iBoot, synthetic NOR/NAND and direct-kernel loader inputs. |
| `/path/to/developer/iphoneos1-lab-runtime/1A543a/nand-m68-4bank` | Default four-bank M68 base pages; retained without guest writes. |
| `/path/to/developer/iphoneos1-lab-runtime/evidence/<tag>` | Live logs and framebuffer captures, copied to `reports/<tag>` after the process ends. |
| `/path/to/developer/iphoneos1-lab-runtime/evidence/<tag>/nand-overlay` | Guest-programmed pages for that run; read before the base pages and retained after exit. |

The helper scripts currently use these host-specific paths. The host build uses SDL, GLib, Pixman, `/path/to/developer/anaconda3/bin/ninja`, and OpenSSL at `/opt/homebrew/opt/openssl@3.3`. `tools/build_qemu.sh` configures only `arm-softmmu` and builds serially by default; set `IPHONEOS1_BUILD_JOBS` to a positive integer to change that. Inspect the paths before using it on another Mac. This workflow does not require Xcode or an iOS Simulator.

## Run the current lab

Run from the project directory. Choose a **new tag for every run**: the helper rejects an existing writable NAND overlay rather than reusing guest state. The M68 defaults are `arm1176`, `--icount 2` and `nand-m68-4bank`.

```sh
cd '/path/to/developer/Documents/AI Stuff/iPhoneOS1Lab'
.venv/bin/python tools/boot.py --seconds 180 --snapshot-interval 30 \
  --tag m68-normal-check-001
```

Use `--gui` to view the actual framebuffer in SDL and `--home-at 30` to send the modeled Home key. `--seconds 0` runs until interrupted. `--nand /absolute/path` selects a separate base image while preserving the per-run overlay. `--cpu`, `--icount` and `--no-icount` change diagnostic conditions; keep them with the capture evidence.

The separate direct-kernel diagnostic is:

```sh
.venv/bin/python tools/boot.py --direct-kernel --cpu arm1176 \
  --seconds 45 --tag m68-direct-check-001
```

For guest debugging, start with `--gdb 12345 --paused`. `tools/debug_gdb.py --help` describes the local GDB-remote inspection tool. Instruction tracing (`--trace`) is high-volume and can alter host timing. Keep the corresponding command and logs with every observation.

After a new guest reaches userland, capture CPU/device/process state through its owned local GDB port:

```sh
.venv/bin/python tools/inspect_runtime.py --port 12381 \
  --samples 3 --interval 5 --report reports/m68-runtime-fresh.json
```

Use the port from that guest's `--gdb` option and a fresh report path. The inspector pauses and resumes the guest for each sample, excludes interrupt-acknowledging or data-consuming MMIO reads, and separates current CPU state from saved user trap frames. It is prepared and unrun; see `reports/runtime-inspection-instructions.md` for bounds and failure handling.

`--reference` uses the separate N45AP iPod touch 1G / 3A101a control firmware, the original eight-bank reference NAND, upstream CPU `max`, and no instruction clock by default. It cannot establish behavior of the iPhone 1A543a target. `--direct-kernel --reference` is rejected.

## Rebuild and parser checks

The current `vendor/qemu` checkout already contains the local changes. Do not reapply the consolidated patch to that modified tree. To recreate it in a clean project tree, use the commands below only when the destination vendor directories do not already exist. The original branch and commits are intentional; newer iPod touch branches model different hardware and firmware.

```sh
git clone --branch ipod_touch_1g https://github.com/devos50/qemu.git vendor/qemu
git -C vendor/qemu checkout 501c85c4f8a3503965e38d5d4f30a02c4bc9171c
git -C vendor/qemu apply --check ../../patches/qemu-iphoneos1.patch
git -C vendor/qemu apply ../../patches/qemu-iphoneos1.patch
git clone https://github.com/devos50/generate-ipod-touch-1g-nand.git vendor/generate-nand
git -C vendor/generate-nand checkout 7bda431b215f8282d8ec7d6326dc40bbc4f63299
```

Do not combine the consolidated patch with the individual snapshots. The adapted NOR generator is already in `tools/nor_generator`; its vendor checkout is provenance/reference material.

```sh
bash tools/build_qemu.sh
.venv/bin/python tools/test_multitouch_packets.py \
  --report reports/zephyr1-packet-tests.json
.venv/bin/python tools/test_nand_overlay.py \
  --report reports/nand-overlay-tests.json
.venv/bin/python tools/test_uart_legacy.py \
  --report reports/uart-legacy-tests.json
.venv/bin/python tools/test_timer_readback.py \
  --report reports/timer-readback-tests.json
.venv/bin/python tools/test_sysic_gpio.py \
  --report reports/sysic-gpio-tests.json
```

The UART, timer and SYSIC harnesses are prepared and unrun. They exercise production C register logic with infrastructure stubs; they do not prove QOM wiring, guest boot, or UI interaction. After any emulator rebuild, run a fresh capture before carrying historical guest conclusions forward to the new binary.

## Recreate firmware and storage inputs

These commands describe a **clean setup**. Existing original artifacts should be retained. `prepare_rootfs.py` and `prepare_nand.py` reject existing destinations; select a new output path when regenerating an experiment.

```sh
project_root="$(pwd)"
runtime_root="${IPHONEOS1_RUNTIME:-$HOME/iphoneos1-lab-runtime}/1A543a"
cd "$project_root"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools/download_firmware.py
.venv/bin/python tools/extract_firmware.py \
  'firmware/iPhone1,1_1.0_1A543a_Restore.ipsw' firmware/1A543a
curl --fail --location \
  'https://github.com/devos50/qemu-ios/releases/download/n45ap_v1/bootrom_s5l8900' \
  --output firmware/bootrom_s5l8900
shasum -a 256 firmware/bootrom_s5l8900
mkdir -p "$runtime_root"
cp firmware/1A543a/iboot.bin "$runtime_root/iboot.bin"
.venv/bin/python tools/generate_nor.py \
  --assets firmware/1A543a/img2 --output "$runtime_root/nor.bin" \
  --openssl-prefix /opt/homebrew/opt/openssl@3.3 \
  --report reports/nor-generation.json
.venv/bin/python tools/prepare_rootfs.py \
  firmware/1A543a/rootfs.hfs "$runtime_root/rootfs-emulation.hfs"
.venv/bin/python tools/prepare_nand.py \
  "$runtime_root/rootfs-emulation.hfs" "$runtime_root/nand-m68-4bank" \
  --banks 4 --report reports/nand-m68-4bank-generation.json
```

Accept the separate BootROM only if it is 65,536 bytes and the printed SHA-256 is `220027d6f8ea24603f8c5ad5e920ab553d85a9cd809d79c7e6f6f0eefdc2bc95`.

The NAND generator checkout must be at `7bda431b215f8282d8ec7d6326dc40bbc4f63299`. `prepare_nand.py` changes upstream FIL metadata from `C002` to the `C000` layout expected by iBoot-159, uses four active banks / 512 virtual pages per block, zeroes output page allocations for deterministic metadata, and initializes C000 bad-block-table size and usable-block records for each active bank. Fixed-capacity WMR structure arrays retain their original size. It does not patch Apple executable instructions. The historical eight-bank `nand` input is retained for diagnosis, but is no longer the M68 default.

`--stock-rootfs` selects `nand-stock-m68-4bank`, which has not yet been generated in this workspace. To create that separate diagnostic, use the original filesystem with the same four-bank metadata:

```sh
.venv/bin/python tools/prepare_nand.py \
  firmware/1A543a/rootfs.hfs "$runtime_root/nand-stock-m68-4bank" \
  --banks 4 --report reports/nand-stock-m68-4bank-generation.json
```

The original filesystem expects a separate `/private/var` data partition that this simplified NAND does not provide; this is not an established stock-device boot configuration. The older eight-bank `nand-stock` directory also retains historical unfixed BBT records and is not a storage-equivalent control for the current default. Keep it and its evidence separate.

The default emulation filesystem is a separate copy. Its recorded changes are one writable system partition in `fstab`, `LK_ENABLE_MBX2D=0` in the SpringBoard environment, and needed data directories. SHA-256 checks confirm SpringBoard, launchd, dyld and LayerKit executable bytes stayed unchanged. `reports/rootfs-emulation.changes.json` records the configuration and hashes; the NAND byte-verification report reconstructs that exact prepared filesystem. The software-graphics setting is a request to the original framework, not proof that SpringBoard renders successfully.

`extract_firmware.py` produces `kernel.macho` from the **restore** kernelcache. The **system** kernel used for direct entry is separately extracted from the original HFSX filesystem at `/System/Library/Caches/com.apple.kernelcaches/kernelcache.release.s5l8900xrb`. Its decoded SHA-256 is `42e9f3c18d4a4d5c956acdcded0c3f8f247fe3e7fc96d14cfa3aedcd77c292c9`; see `firmware/1A543a/system-kernels.json`. To reconstruct that step on this macOS host, mount the original HFSX image read-only, decode both system kernelcache files, then detach it:

```sh
mkdir -p /tmp/iphoneos1-rootfs-1A543a
diskutil image attach --nobrowse --mountPoint /tmp/iphoneos1-rootfs-1A543a \
  --mountOptions ro,noowners --plist "$project_root/firmware/1A543a/rootfs.hfs"
.venv/bin/python - <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'tools')
from extract_firmware import artifact, unwrap_8900, unwrap_comp
source = Path('/tmp/iphoneos1-rootfs-1A543a/System/Library/Caches/com.apple.kernelcaches')
output = Path('firmware/1A543a')
records = []
for name in ('kernelcache.release.s5l8900xrb', 'kernelcache.s5l8900xrb'):
    payload, _ = unwrap_8900((source / name).read_bytes())
    kernel, _ = unwrap_comp(payload)
    target = output / (name + '.macho')
    target.write_bytes(kernel)
    records.append(artifact(target, source=str(source / name), layers=['8900', 'LZSS']))
(output / 'system-kernels.json').write_text(json.dumps(records, indent=2) + '\n')
PY
hdiutil detach /tmp/iphoneos1-rootfs-1A543a
```

With that verified system kernel available, recreate the direct loader inputs with:

```sh
.venv/bin/python tools/prepare_kernel_boot.py \
  firmware/1A543a/kernelcache.release.s5l8900xrb.macho \
  firmware/1A543a/devicetree.bin "$runtime_root/direct-kernel"
```

This maps unchanged kernel segments, populates a separate device-tree template, constructs boot arguments and emits a small ARM trampoline with a minimal LCD handoff. It does not reproduce the complete original bootloader state.

## Next acceptance steps

1. Build the prepared UART, timer and GPIO corrections and run their production-source harnesses, then capture a fresh normal boot. Check UART1 IRQ 25, actual timer settings and userland progress without debugger masking.
2. Inspect SpringBoard's rendering and service waits after the interrupt storm is addressed. Process presence alone is insufficient.
3. Verify touchscreen interrupt/frame delivery and actual Home-key behavior in the original UI.
4. Capture the original SpringBoard framebuffer and exercise touch and Home. Only then report full boot and usable original UI.

See [SOURCES.md](SOURCES.md) for exact firmware/source provenance, identity hashes and the boundary between genuine Apple inputs and synthetic emulator state.


## Public snapshot

See [PUBLICATION.md](PUBLICATION.md) for publication exclusions and setup requirements.
