# Sources and provenance

## Target firmware

The target is `iPhone1,1` / `m68ap`, iPhone OS `1.0`, build `1A543a`. The IPSW was obtained from [Apple's firmware CDN](https://secure-appldnld.apple.com/iPhone/061-3538.20070629.B7vXa/iPhone1,1_1.0_1A543a_Restore.ipsw). The accepted identity is:

```text
filename  iPhone1,1_1.0_1A543a_Restore.ipsw
bytes     95604348
SHA-256   468d8b10061642b32f79046d6266a775cb26f02879839d8d445bdec82085c51a
SHA-1     fb8bb3ee2e9a997affbb97868599f2995c78209c
```

`firmware-source.json` records the acquisition metadata. `download_firmware.py` checks size and SHA-256 for both downloads and an existing accepted IPSW. It accepts the Apple download host and preserves partial/failed files for inspection. `firmware/1A543a/extraction-report.json` records component sizes, hashes, wrapper checks and HFSX checksum verification.

| Original decoded artifact | SHA-256 |
| --- | --- |
| `iboot.bin` | `df8d4ba04f31c79ddfde8ade52a22bf8f17e85bd41e6f6eaf327185bc6750170` |
| `devicetree.bin` | `f079c354a36e565409273c1581ed327a0e885ec2b90746189f48985223c115d3` |
| `rootfs.hfs` | `becfbdd087706677cca92038767542fa707122ea217b3bb527427991dba90bdc` |
| Restore `kernel.macho` | `80784375a332af15dca55a3b494d55ade03c5cfca41fafbe2ecef1cd0871af31` |
| System `kernelcache.release.s5l8900xrb.macho` | `42e9f3c18d4a4d5c956acdcded0c3f8f247fe3e7fc96d14cfa3aedcd77c292c9` |

The system kernelcache comes from the original root filesystem, rather than the restore kernel at the IPSW top level. Both original system kernelcache names decode to the same system-kernel hash in `firmware/1A543a/system-kernels.json`.

The S5L8900 BootROM is a **separate input**, not extracted from this IPSW. Its acquisition source is [devos50's `n45ap_v1` release asset](https://github.com/devos50/qemu-ios/releases/download/n45ap_v1/bootrom_s5l8900). The local `firmware/bootrom_s5l8900` is 65,536 bytes with SHA-256 `220027d6f8ea24603f8c5ad5e920ab553d85a9cd809d79c7e6f6f0eefdc2bc95`. This records the acquired asset's identity; it does not establish a full original BootROM boot chain in the emulator.

The N45AP / 3A101a iPod touch 1G files in `reference-n45` are a separate control experiment. Results from them must not be attributed to iPhone OS 1.0 / 1A543a.

## Emulator and storage sources

| Source | Pinned revision | Use |
| --- | --- | --- |
| [devos50 QEMU](https://github.com/devos50/qemu/tree/501c85c4f8a3503965e38d5d4f30a02c4bc9171c) | `ipod_touch_1g`, `501c85c4f8a3503965e38d5d4f30a02c4bc9171c` | Experimental S5L8900/iPod touch 1G machine, QEMU 6.2.50. The actual local Git remote is `devos50/qemu.git`; `firmware-source.json` also names the project's `qemu-ios` landing repository. |
| [First-generation NAND generator](https://github.com/devos50/generate-ipod-touch-1g-nand/tree/7bda431b215f8282d8ec7d6326dc40bbc4f63299) | `7bda431b215f8282d8ec7d6326dc40bbc4f63299` | Base page/bank generation. `prepare_nand.py` compiles a temporary C000 adaptation with four active M68 banks, deterministic page allocations and usable-block metadata. |
| [First-generation NOR generator](https://github.com/devos50/generate-ipod-touch-1g-nor/tree/12c846dcee8ad5c2935370ee48559b82b42249a2) | `ipod_touch_1g`, `12c846dcee8ad5c2935370ee48559b82b42249a2` | Adapted implementation in `tools/nor_generator/`, with deterministic bounds/allocation and M68 inputs. |
| [openiBoot S5L8900 sources](https://github.com/iDroid-Project/openiBoot/tree/866562fdb1cfd019bcd77885c80fbf0af65d5c15) | `866562fdb1cfd019bcd77885c80fbf0af65d5c15` | Public hardware/protocol references for LCD, clocks, GPIO and Zephyr 1 multitouch. This lab does not substitute openiBoot for Apple's operating system. |

The consolidated `patches/qemu-iphoneos1.patch` describes local emulator changes against the pinned QEMU base. Its scope includes modern Clang SHA-1 compatibility, original plaintext 8900 kernelcache handling, M68 board/DMA/PMU/LCD wiring, C000 ADM/FMC layouts and four-bank availability, NAND page overlays, UART modem CTS and opt-in S5L8900 interrupt/FIFO behavior, timer4 countdown/readback, GPIO polarity/masks and Zephyr 1 protocol and GPIO/SPI transaction integration. The latest UART, timer and SYSIC changes are source-only until a new build, harness run and guest capture record them. Apply it only to a clean base revision. Individual patches record earlier overlapping changes and are not a sequential patch series. While source work continues, regenerate the consolidated diff from the modified vendor tree before treating it as a complete reproduction of that tree; a source change requires fresh build and guest evidence.

The inherited machine is still called `iPod-Touch`; `iphone-2g=true` selects the experimental M68 adaptation. `boot.py` now defaults to ARM1176 and instruction clock shift 2 for M68, while the separate N45 control retains upstream CPU `max` and its eight-bank base pages. Selecting the board or ISA does not prove hardware completeness.

The normal four-bank capture in `reports/m68-fourbank-iboot-debug/outcome.json` records QEMU SHA-256 `2c7f61f5912109dd80454f33db52cf6a96b72262515c34222c57eff3dc2248a6`. Its serial output establishes kernel root discovery and mount; `reports/m68-userland-processes-early.json` identifies genuine launchd and SpringBoard processes through the original kernel's process-list fields, and `reports/m68-userland-threads.json` records guest thread/context inspection. `reports/m68-userland-long/` captures 600 seconds while the framebuffer retains the original boot logo. None of these establishes rendered SpringBoard UI or usable touch interaction.

## Extraction and reverse-engineering references

`tools/extract_firmware.py` references [xpwn 8900 headers](https://github.com/planetbeing/xpwn/blob/master/includes/xpwn/8900.h), [IMG2 headers](https://github.com/planetbeing/xpwn/blob/master/includes/xpwn/img2.h), [FileVault code](https://github.com/planetbeing/xpwn/blob/master/dmg/filevault.c) and [UDIF declarations](https://github.com/planetbeing/xpwn/blob/master/includes/dmg/dmg.h). The implementation declares GPL-3.0-or-later and identifies its Okumura LZSS algorithm basis. The published root filesystem key reference is [The Apple Wiki's 1A543a key page](https://theapplewiki.com/wiki/Keys:Heavenly_1A543a_(iPhone1,1)). The script validates the decoded formats and checksums rather than assuming decryption succeeded.

`tools/prepare_kernel_boot.py` identifies its [Apple ARM boot-argument structure reference](https://github.com/apple-oss-distributions/xnu/blob/e6231be02a03711ca404e5121a151b24afbff733/pexpert/pexpert/arm/boot.h), plus pinned openiBoot [clock](https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/clock.c), [LCD](https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/lcd.c) and [pixel-format](https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/includes/lcd.h) references. `reports/lcd-handoff-analysis.json` combines those references with original-kernel instruction and live-memory observations.

`reports/m68-button-polarity.json` records untouched 1A543a device-tree offsets and interrupt descriptors, compared with pinned openiBoot [GPIO](https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/gpio.c) and [button](https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/buttons.c) code. It supports Home/Power high-level interrupts and guest-managed polarity auto-flip, plus the original multitouch edge-low descriptor. `reports/m68-timer-fidelity.json` combines original kernel helper disassembly with public timer divider definitions and states the remaining clock/interrupt uncertainties. `tools/inspect_prelink.py` decodes the original kernel's serialized prelink metadata, resolves reference IDs, and checks descriptor kmod names and loaded ranges; `reports/prelink-kexts.json` records 70 original extensions. Static metadata and saved user register frames do not prove current runtime execution.

`reports/m68-display-static-contract.json` identifies the original CPU renderer and framebuffer-swap calls, default BGRA surface format, and CLCD programming. `reports/mbx-clockgate-auto-ogl-analysis.json` traces the MBXConnect clock-gating property's error return and LayerKit's conditional automatic OGL route. `reports/mbxconnect-hfs-extraction.json` records a bounded catalog/extent read directly from the unchanged HFSX image for the original 20,232-byte MBXConnect framework, SHA-256 `18dcfe631ab9307abf4d190065b1ce4463464e632e7734e18a79d7d9d14d4728`. These identify guest probes; they do not establish that SpringBoard has reached either renderer. The N45 status-bar-only screenshot and its missing plane state are separately bounded in `reports/n45-partial-ui-composition-analysis.json`.

`reports/usb-wrangler-panic.json` uses the original kernel's instruction trace and public [IOService notification code](https://github.com/apple-oss-distributions/xnu/blob/xnu-1228.0.2/iokit/Kernel/IOService.cpp). That generic source supports the synchronous-notification explanation; it is not a claim that the later source revision exactly equals the 1A543a kernel.

## Genuine inputs and synthetic state

Apple iBoot and kernel instruction bytes are preserved. A separately prepared filesystem modifies configuration, not the checked SpringBoard, launchd, dyld or LayerKit executable bytes. `reports/rootfs-emulation.changes.json` records the two configuration changes and four before/after executable hashes. The original `rootfs.hfs` is retained and checked separately.

The NOR is a synthetic 1 MiB emulator image. Its image payloads match the extracted Apple IMG2 payloads, but its allocation/checksums, startup variables, model `MA712`, serial `QEMU-M68AP`, and UID-derived hash schedule are emulator inputs. It is not an original device flash dump. NAND bank/page organization, C000 FIL metadata, bad-block tables and the simplified partition layout are also synthetic storage state.

The current M68 NAND input, `nand-m68-4bank`, uses the original device-tree disk `reg=0x0f` and the original ADMFMC bank-discovery instructions as geometry evidence. The modeled geometry is four active banks, 128 physical pages per block, 512 interleaved virtual pages per block, 4,096 physical blocks per bank, and 2,048 data bytes plus 64 spare bytes per page. These are generated emulator pages, not an original iPhone flash dump. The generator preserves fixed-capacity WMR structure arrays while changing only active geometry. `reports/nand-m68-4bank-generation.json` records the temporary source/compiler parameters; `reports/nand-m68-4bank-verification.json` verifies four BBT records and all 94,538 HFS pages, reconstructing SHA-256 `7257bdb9037f3eb0caed0a7823f4deef5c5a1ee77271129e2146c61f4bb77448`, equal to the prepared filesystem input.

Guest-programmed NAND pages are retained in `evidence/<tag>/nand-overlay`; reads prefer that overlay and fall back to the base pages. Each `boot.py` run requires a new overlay/tag, protecting earlier evidence and the generated base input. Overlay page files persist on the host after exit, but the helper does not yet provide a resume-state mode. `reports/nand-overlay-tests.json` validates production file/FIFO behavior with 3,306 sanitizer-backed assertions and seven explicit rejection cases; it excludes concurrent publication, controller timing, DMA and FTL consistency. The older eight-bank `nand` and `nand-stock` layouts remain historical diagnostics, not current M68 storage controls.

Battery values, touchscreen sensor constants, baseband CTS availability and several peripheral responses are modeled. Parsing and checksumming the original touchscreen firmware upload does not execute its controller CPU instructions. Wi-Fi, cellular/baseband service, audio, USB, complete MBX rendering and touch interaction are not established by the current evidence. Live UART1 IRQ-25 inspection and temporary debugger masks are diagnostic observations, not original firmware changes or a proven fix. A clock-shift-6 run also exposes a USB Wrangler panic that the current shift-2 capture avoids; that does not establish timing fidelity.

Direct kernel entry additionally creates a populated device-tree copy, boot arguments, a trampoline and minimal LCD registers. These are diagnostic inputs, not a captured original iBoot handoff. No observation of that path should be described as a successful original boot chain.

Upstream license notices remain in source files and vendor checkouts; QEMU's README describes the whole project as GPL version 2 and points to its license files. This lab does not relicense the Apple firmware or treat an available download as a redistribution grant. Firmware, raw Apple binaries and generated runtime storage remain local research artifacts; source provenance is separate from firmware ownership.
