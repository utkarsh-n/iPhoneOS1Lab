# Public source snapshot

This repository contains a reviewed source snapshot. Original Git history, credentials, personal records, local signing identities, device diagnostics, build outputs, downloaded model weights, firmware, and unreviewed media are excluded. Existing upstream license and attribution files apply to their respective components. Publication does not grant a new license to third-party content.

Configure your own Apple signing team to run native apps on a physical device. Downloaded datasets, binary runtimes, fonts, demo media, and models may need to be obtained separately using the documented upstream sources or fetch/build tools. This publication review does not certify that this snapshot builds or runs.

## Snapshot notes

Apple firmware, decrypted binaries, BootROM, generated flash storage, runtime captures, vendor checkouts, compiled tools, and adapted NOR-generator source without a declared upstream license are omitted. tools/generate_nor.py intentionally exits with an explanation. The upstream NOR reference is devos50/qemu-ios-generate-nor, revision 12c846dcee8ad5c2935370ee48559b82b42249a2. Supply IPHONEOS1_HEADER_KEY (16 bytes as hex) and IPHONEOS1_ROOT_KEY (36 bytes as hex) in your local environment only when you have appropriate firmware access. Keys are neither bundled nor written to reports. QEMU-derived patches retain upstream GPL2 coverage; tools/extract_firmware.py declares GPL-3.0-or-later. License texts and source attribution cover those components only; no project-wide license is asserted for user-authored source. Historical references to reports/ describe local research evidence omitted from this snapshot. Full emulator/firmware boot was not validated for publication.
