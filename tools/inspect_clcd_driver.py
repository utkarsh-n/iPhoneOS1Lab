#!/usr/bin/env python3
"""Record the original 1A543a AppleH1CLCD interrupt instructions."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    data = args.input.read_bytes()
    if struct.unpack_from("<II", data) != (0xFEEDFACE, 12):
        parser.error("Expected little-endian 32-bit ARM Mach-O")
    segments = []
    offset = 28
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, length = struct.unpack_from("<II", data, offset)
        if command == 1:
            name, address, _, file_offset, file_size, *_ = struct.unpack_from("<16s8I", data, offset + 8)
            segments.append((name.rstrip(b"\0").decode(), address, file_offset, file_size))
        offset += length

    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    ranges = {
        "interrupt_filter_and_ack_all": (0xC0300AE8, 0xC0300B38),
        "frame_done_handler": (0xC0300B40, 0xC0300BC4),
        "clear_frame_done_then_enable": (0xC0301C10, 0xC0301C50),
        "initial_interrupt_mask": (0xC0301E80, 0xC0301EB0),
    }
    output = {}
    for label, (start, end) in ranges.items():
        _, vm_address, file_offset, file_size = next(s for s in segments if s[1] <= start and end <= s[1] + s[3])
        position = file_offset + start - vm_address
        output[label] = [
            {"address": hex(i.address), "mnemonic": i.mnemonic, "operands": i.op_str}
            for i in decoder.disasm(data[position:position + end - start], start)
        ]
    report = {
        "input": str(args.input.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "scope": "Static instructions from the original 1A543a system kernel; no guest execution",
        "register_interpretation": {
            "0x14": "Interrupt enable mask, matching driver object mask at offset 0x1e4",
            "0x18": "Pending status; driver acknowledges by writing ones",
            "pending_bit_0": "Frame completion, tested and acknowledged by interrupt handler",
        },
        "instructions": output,
        "model_defect": "The upstream model stores writes to status verbatim and raises LCD IRQ every refresh regardless of the enable mask. An acknowledgement of 0xff therefore becomes synthetic pending status 0xff.",
        "correction": "Clear written bits from status, set frame-completion pending on refresh, and drive the IRQ from the intersection of pending and enabled bits.",
        "limits": "Other LCD interrupt causes and exact hardware scanout timing remain unmodeled. This report does not prove a complete boot or UI.",
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Recorded CLCD driver instructions in {args.report}")


if __name__ == "__main__":
    main()
