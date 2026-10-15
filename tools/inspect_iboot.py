#!/usr/bin/env python3
"""Record the verified mixed ARM/Thumb startup of the extracted iBoot-159.

Requires Capstone. Function ranges below were checked against the original
1A543a binary. This does not claim automatic recovery of every function.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_OP_MEM
from capstone.arm import ARM_REG_PC


BASE = 0x18000000
FUNCTIONS = [
    (0x0000, 0x0020, "arm", "exception_vectors"),
    (0x0040, 0x00EC, "arm", "reset_and_mode_setup"),
    (0x4F20, 0x4F50, "thumb", "entry"),
    (0x3ECC, 0x3F52, "thumb", "cpu_cp15_setup"),
    (0x4E60, 0x4E8A, "thumb", "heap_and_core_init"),
    (0x0E60, 0x0EB2, "thumb", "early_hardware_init"),
    (0x22EC, 0x22FA, "thumb", "initial_power_control"),
    (0x2300, 0x2320, "thumb", "power_state_poll"),
    (0x234E, 0x237A, "thumb", "system_controller_init"),
    (0x1580, 0x15C4, "thumb", "clock_frequency_table_init"),
    (0x3AC8, 0x3B76, "thumb", "interrupt_controller_init"),
    (0x20AC, 0x2114, "thumb", "gpio_interrupt_init"),
    (0x30D4, 0x31E2, "thumb", "timer_init"),
    (0x38C0, 0x3920, "thumb", "usb_phy_init"),
    (0x1CDC, 0x1D0C, "thumb", "i2c_init"),
    (0x50D8, 0x51B6, "thumb", "automatic_boot_dispatch"),
    (0x528C, 0x5302, "thumb", "recovery_poweroff_thread"),
    (0x0560, 0x0584, "thumb", "power_button_read"),
    (0x1EF0, 0x1F0E, "thumb", "gpio_input_read"),
    (0x9590, 0x9668, "thumb", "pmu_adc_query"),
    (0x13074, 0x13134, "thumb", "nand_block_device_init"),
    (0x13234, 0x132A0, "thumb", "nand_init_wrapper"),
    (0x16060, 0x1616C, "thumb", "whimory_init"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--disassembly", required=True, type=Path)
    args = parser.parse_args()
    data = args.input.read_bytes()
    if data[:4] != bytes.fromhex("0e0000ea") or b"iBoot-159\x00" not in data:
        parser.error("Expected the original iBoot-159 reset vector and build marker")
    blocks = []
    text = []
    for start, end, mode, label in FUNCTIONS:
        disassembler = Cs(CS_ARCH_ARM, (CS_MODE_ARM if mode == "arm" else CS_MODE_THUMB) | CS_MODE_LITTLE_ENDIAN)
        disassembler.detail = True
        instructions = []
        text.append(f"[{label}] {mode} {BASE + start:#010x}")
        for instruction in disassembler.disasm(data[start:end], BASE + start):
            item = {"address": hex(instruction.address), "mnemonic": instruction.mnemonic,
                    "operands": instruction.op_str}
            line = f"{instruction.address:08x}  {instruction.mnemonic:8} {instruction.op_str}"
            if instruction.mnemonic == "ldr" and len(instruction.operands) > 1:
                operand = instruction.operands[1]
                if operand.type == CS_OP_MEM and operand.mem.base == ARM_REG_PC:
                    literal = ((instruction.address + (8 if mode == "arm" else 4)) & ~3) + operand.mem.disp
                    if BASE <= literal < BASE + len(data) - 3:
                        value = struct.unpack_from("<I", data, literal - BASE)[0]
                        item["literal_address"] = hex(literal)
                        item["literal_value"] = hex(value)
                        line += f" ; [{literal:08x}]={value:08x}"
            instructions.append(item)
            text.append(line)
        text.append("")
        blocks.append({"label": label, "mode": mode, "instructions": instructions})
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{8,}", data):
        value = match.group().decode("ascii")
        if "kernelcache" in value or value == "iBoot-159":
            strings.append({"address": hex(BASE + match.start()), "value": value})
    report = {
        "input": str(args.input), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "build_marker": "iBoot-159", "base": hex(BASE), "reset_pc": hex(BASE),
        "reset_mode": "ARM", "thumb_entry": "0x18004f20", "thumb_entry_pointer": "0x18004f21",
        "bss_start": "0x18021980", "bss_end": "0x18026000", "svc_stack": "0x18022980",
        "kernelcache_path": "/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8900xrb",
        "required_automatic_boot_nvram": {"auto-boot": "true", "boot-command": "fsboot", "bootdelay": "0"},
        "recovery_wait": {"function": "0x1800528c", "label": "poweroff thread",
                          "observation": "Missing auto-boot takes the recovery branch at 0x180051b6"},
        "modeled_battery_adc": {"status_register": "0x57", "ready_bit": 128,
                                "value_register": "0x55", "sample": {"0x57": 130, "0x55": 170},
                                "raw_value": 682, "voltage_mv": 4000,
                                "boundary": "Suggested synthetic peripheral response, not measured hardware"},
        "nand_metadata_identity": {"original_iboot_fil_id": "0x43303030",
                                   "neighbor_n45_generator_fil_id": "0x43303032",
                                   "comparison_instruction": "0x180160f8",
                                   "validation_boundary": "Version mismatch found statically; see separate live NAND reports for runtime failure"},
        "early_poll": {
            "pc": "0x1800236c", "state_register": "0x39a00008", "requested_register": "0x39a00014",
            "mask": "0x11ec", "condition": "wait until (state & mask) == (requested & mask)",
            "qemu_source_observation": "Both registers read the same power_state in upstream ipod_touch_sysic.c",
            "runtime_status": "Static analysis only; this report does not assert boot success",
        },
        "blocks": blocks, "strings": strings,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.disassembly.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    args.disassembly.write_text("\n".join(text) + "\n")
    print(f"iBoot-159 ARM reset {BASE:#x} -> Thumb 0x18004f20; wrote {args.report}")


if __name__ == "__main__":
    main()
