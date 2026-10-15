#!/usr/bin/env python3
"""Record the original 1A543a LCD handoff requirement and its live diagnosis."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    data = args.kernel.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != "42e9f3c18d4a4d5c956acdcded0c3f8f247fe3e7fc96d14cfa3aedcd77c292c9":
        parser.error("This diagnosis applies only to the verified original 1A543a system kernel")
    segments, offset = [], 28
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, offset)
        if command == 1:
            _, address, _, file_offset, file_size, *_ = struct.unpack_from("<16s8I", data, offset + 8)
            segments.append((address, file_offset, file_size))
        offset += size

    def read(address, length):
        base, start, _ = next(s for s in segments if s[0] <= address and address + length <= s[0] + s[2])
        return data[start + address - base:start + address - base + length]

    ranges = {
        "active_window_selection": (0xc03007c4, 0xc030086c, CS_MODE_ARM),
        "pixel_format_and_dimensions": (0xc03008c4, 0xc0300968, CS_MODE_ARM),
        "physical_memory_descriptor_creation": (0xc0300a54, 0xc0300a78, CS_MODE_ARM),
        "descriptor_32bit_range_overflow": (0xc0147bfe, 0xc0147c7e, CS_MODE_THUMB),
    }
    instructions = {}
    for label, (start, end, mode) in ranges.items():
        instructions[label] = [{"address": hex(i.address), "mnemonic": i.mnemonic, "operands": i.op_str}
                               for i in Cs(CS_ARCH_ARM, mode).disasm(read(start, end - start), start)]
    report = {
        "kernel": str(args.kernel.resolve()), "kernel_sha256": digest,
        "status": "Baseline panic explained and absent after diagnostic LCD handoff; full boot unproven",
        "binary_evidence": instructions,
        "pixel_format_constants": {hex(address): hex(struct.unpack("<I", read(address, 4))[0])
                                   for address in (0xc0300ac8, 0xc0300acc, 0xc0300ad0, 0xc0300ad4)},
        "baseline": {
            "breakpoint": "0xc0147c36",
            "physical_address": "0x00000000c0301f2c", "segment_length": "0x8e790000",
            "address_plus_length": "0x000000014ea91f2c",
            "dma_walk": {"offset": "0", "address": "0xc0301f2c", "length": "0x8e790000", "mapped": 1},
            "descriptor": "0xc0b6bd80", "framebuffer_object": "0xc0b67a00",
            "controller_object": "0xc0856200",
            "evidence": ["lcd-segment-overflow.json", "lcd-real-descriptor.json",
                         "lcd-physical-descriptor-construction.json", "lcd-PE-state-overflow.json"],
        },
        "cause": "The original LCD driver chooses window 1/2/3/4 from control register bits 0x40/0x20/0x10/0x8. With every window disabled at reset it falls through without assigning the physical base on its stack, fp bytes-per-row, or r8 dimensions. The saved caller LR c0301f2c becomes the base. This is an invalid synthesized bootloader handoff, not evidence of an original kernel defect.",
        "corrected_handoff": {
            "method": "ARM stores in the separate diagnostic trampoline before entering the unchanged system kernel",
            "physical_register_base": "0x38900000",
            "writes": {"0x58": "0x500", "0x5c": "0x600", "0x60": "0xfe00000",
                       "0x64": "0x14001e0", "0x68": "0x140", "0x08": "0x40"},
            "live_values": {"width": 320, "height": 480, "row_bytes": 1280,
                            "physical_address": "0xfe00000", "length": "0x96000", "format": "ARGB"},
            "evidence": ["lcd-corrected-descriptor-construction.json", "lcd-corrected-stack.json",
                         "lcd-corrected-framebuffer.json", "m68-lcd-handoff/serial.log", "m68-lcd-handoff/host.log"],
            "progress": ["AppleMBX: Added swap device: AppleH1CLCD", "AppleMBX: Using AppleH1CLCD as legacy swap device"],
            "next_failure": "Old host build aborted on unimplemented command 0xc2 at guest PC c040ef40, after the prior LCD panic was passed",
        },
        "sources": [
            "https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/lcd.c",
            "https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/includes/lcd.h",
        ],
        "limits": ["This enters the original system kernel directly and bypasses original BootROM/iBoot startup.",
                   "The register values are an evidence-derived minimal handoff, not a captured original iBoot register dump.",
                   "Panel initialization, hardware timing, root disk discovery and original UI remain unverified.",
                   "There are no original kernel instruction patches; the device tree is a separately populated template copy."],
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(args.report)


if __name__ == "__main__":
    main()
