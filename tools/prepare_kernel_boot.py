#!/usr/bin/env python3
"""Prepare an experimental direct launch of the ORIGINAL 1A543a ARMv6 kernel.

No instruction patches and no QEMU board edits. Extracts LC_SEGMENT contents,
zero-fills virtual-size tails, populates a COPY of the original device-tree
template, and synthesizes a 32-bit Apple boot_args plus a tiny ARM trampoline.
This is a diagnostic handoff, not evidence of a successful boot or original
iBoot/BootROM execution. The report distinguishes binary evidence from inputs.
"""

import argparse
import hashlib
import json
import shlex
import struct
from pathlib import Path

EXPECTED_KERNEL = "42e9f3c18d4a4d5c956acdcded0c3f8f247fe3e7fc96d14cfa3aedcd77c292c9"
EXPECTED_TREE = "f079c354a36e565409273c1581ed327a0e885ec2b90746189f48985223c115d3"
BOOTARGS_SOURCE = "https://github.com/apple-oss-distributions/xnu/blob/e6231be02a03711ca404e5121a151b24afbff733/pexpert/pexpert/arm/boot.h"
CLOCK_SOURCE = "https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/clock.c"
LCD_SOURCE = "https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/plat-s5l8900/lcd.c"
LCD_FORMAT_SOURCE = "https://github.com/iDroid-Project/openiBoot/blob/866562fdb1cfd019bcd77885c80fbf0af65d5c15/includes/lcd.h"
VBASE, PBASE, RAM_SIZE = 0xc0000000, 0x08000000, 128 * 1024 * 1024
FRAMEBUFFER_ADDRESS = 0x0fe00000
FRAMEBUFFER_SIZE = 320 * 480 * 4


def align(value, boundary=4096):
    return (value + boundary - 1) & -boundary


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(out, filename, data, address):
    path = out / filename
    path.write_bytes(data)
    return {"path": str(path), "size": len(data), "sha256": sha(data),
            "physical_address": address, "physical_address_hex": hex(address)}


def parse_macho(data):
    if data[:4] != b"\xce\xfa\xed\xfe":
        raise ValueError("Expected little-endian 32-bit Mach-O")
    _, cpu, subtype, filetype, ncmds, sizeofcmds, _ = struct.unpack_from("<7I", data)
    if cpu != 12 or subtype & 0xffffff != 6 or filetype != 2:
        raise ValueError("Expected ARMv6 executable kernel")
    if 28 + sizeofcmds > len(data):
        raise ValueError("Mach-O commands extend beyond input")
    commands, segments, entry = 28, [], None
    for _ in range(ncmds):
        kind, size = struct.unpack_from("<2I", data, commands)
        if size < 8 or commands + size > 28 + sizeofcmds:
            raise ValueError("Invalid Mach-O command length")
        if kind == 1:
            name = data[commands + 8:commands + 24].split(b"\0", 1)[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4I", data, commands + 24)
            if filesize > vmsize or fileoff + filesize > len(data):
                raise ValueError("Mach-O segment extends beyond its storage")
            if vmaddr >= VBASE and vmsize:
                segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                                 "fileoff": fileoff, "filesize": filesize})
        elif kind == 5:
            flavor, count = struct.unpack_from("<2I", data, commands + 8)
            if flavor != 1 or count != 17 or size < 84:
                raise ValueError("Unsupported LC_UNIXTHREAD state")
            state = struct.unpack_from("<17I", data, commands + 16)
            entry = state[15]
        commands += size
    if entry is None or not any(s["vmaddr"] <= entry < s["vmaddr"] + s["vmsize"] for s in segments):
        raise ValueError("Entry point does not reside in a loaded segment")
    return segments, entry


def tree_properties(data):
    """Return exact property-name/value offsets; preserve all untouched bytes."""
    properties = {}

    def parse(offset, parent):
        if offset + 8 > len(data):
            raise ValueError("Truncated device-tree node")
        property_count, child_count = struct.unpack_from("<2I", data, offset)
        offset += 8
        node_properties, node_name = [], "?"
        for _ in range(property_count):
            if offset + 36 > len(data):
                raise ValueError("Truncated device-tree property")
            name_offset = offset
            name = data[offset:offset + 32].split(b"\0", 1)[0].decode()
            length = struct.unpack_from("<I", data, offset + 32)[0] & 0x7fffffff
            offset += 36
            if offset + length > len(data):
                raise ValueError("Truncated device-tree property value")
            value_offset = offset
            value = data[offset:offset + length]
            node_properties.append((name, name_offset, value_offset, length))
            if name == "name":
                node_name = value.split(b"\0", 1)[0].decode()
            offset += align(length, 4)
        path = parent + "/" + node_name
        for name, name_offset, value_offset, length in node_properties:
            properties[(path, name)] = (name_offset, value_offset, length)
        for _ in range(child_count):
            offset = parse(offset, path)
        return offset

    if parse(0, "") != len(data):
        raise ValueError("Device tree has unexpected trailing bytes")
    return properties


def prepare(kernel, tree, out, command_line, machine_type, video_display, lcd_handoff=True):
    kernel_data, original_tree = kernel.read_bytes(), tree.read_bytes()
    if sha(kernel_data) != EXPECTED_KERNEL or sha(original_tree) != EXPECTED_TREE:
        raise ValueError("Inputs do not match the verified original 1A543a system kernel/device tree")
    if len(command_line.encode()) >= 256:
        raise ValueError("Command line must fit Apple's 256-byte buffer")
    segments, entry_virtual = parse_macho(kernel_data)
    out.mkdir(parents=True, exist_ok=True)
    report = {"status": "prepared diagnostic inputs; boot unproven", "firmware": "1A543a",
              "kernel": str(kernel), "kernel_sha256": sha(kernel_data),
              "original_device_tree": str(tree), "device_tree_sha256": sha(original_tree),
              "sources": [BOOTARGS_SOURCE, CLOCK_SOURCE, LCD_SOURCE, LCD_FORMAT_SOURCE], "loads": [], "tree_changes": []}
    occupied = []
    for segment in segments:
        address = segment["vmaddr"] - VBASE + PBASE
        if address < PBASE or address + segment["vmsize"] > PBASE + RAM_SIZE:
            raise ValueError("Kernel segment lies outside modeled RAM")
        if any(address < end and start < address + segment["vmsize"] for start, end in occupied):
            raise ValueError("Kernel segment physical ranges overlap")
        occupied.append((address, address + segment["vmsize"]))
        payload = kernel_data[segment["fileoff"]:segment["fileoff"] + segment["filesize"]]
        payload += bytes(segment["vmsize"] - segment["filesize"])
        report["loads"].append({**write(out, segment["name"] + ".bin", payload, address), **segment})
    kernel_end = align(max(end for _, end in occupied))
    tree_address = kernel_end
    args_address = align(tree_address + len(original_tree))
    trampoline_address = args_address + 4096
    page_tables = align(trampoline_address + 4096, 0x4000)
    if page_tables + 0x5000 >= PBASE + RAM_SIZE:
        raise ValueError("Handoff and page tables extend beyond modeled RAM")

    populated_tree = bytearray(original_tree)
    properties = tree_properties(original_tree)

    def replace(path, name, value, reason, new_name=None):
        name_offset, value_offset, length = properties[(path, name)]
        if len(value) != length:
            raise ValueError(f"Replacement changes property length: {path}/{name}")
        before = bytes(populated_tree[value_offset:value_offset + length])
        populated_tree[value_offset:value_offset + length] = value
        if new_name:
            encoded = new_name.encode()
            if len(encoded) >= 32:
                raise ValueError("Device-tree property name exceeds 31 bytes")
            populated_tree[name_offset:name_offset + 32] = encoded.ljust(32, b"\0")
        report["tree_changes"].append({"node": path, "property": name, "new_name": new_name,
                                      "before_hex": before.hex(), "after_hex": value.hex(), "reason": reason})

    replace("/device-tree/memory", "reg", struct.pack("<2I", PBASE, RAM_SIZE), "Modeled RAM address and size")
    cpu_path = "/device-tree/cpus/cpu0"
    # Frequencies reproduce the current QEMU clock model via public openiBoot formulas.
    frequencies = {"clock-frequency": 412000000, "memory-frequency": 206000000,
                   "bus-frequency": 137333333, "peripheral-frequency": 68666666,
                   "fixed-frequency": 24000000, "timebase-frequency": 6000000}
    for name, value in frequencies.items():
        replace(cpu_path, name, struct.pack("<I", value), "Diagnostic value derived from emulator PLL/divisor registers")
    mmap = "/device-tree/chosen/memory-map"
    replace(mmap, "DeviceTree", struct.pack("<2I", tree_address, len(original_tree)), "Load address of this populated template")
    for index, segment in enumerate(report["loads"]):
        replace(mmap, "MemoryMapReserved-" + str(index),
                struct.pack("<2I", segment["physical_address"], segment["vmsize"]),
                "Original kernel segment physical mapping", "Kernel-" + segment["name"])
    replace(mmap, "MemoryMapReserved-7", struct.pack("<2I", args_address, 0x140), "Synthesized boot argument buffer", "BootArgs")
    if lcd_handoff:
        replace(mmap, "MemoryMapReserved-6", struct.pack("<2I", FRAMEBUFFER_ADDRESS, align(FRAMEBUFFER_SIZE)),
                "Diagnostic framebuffer physical range; synthesized handoff, not captured iBoot state", "Framebuffer")
    report["loads"].append(write(out, "devicetree.populated.bin", populated_tree, tree_address))

    fields = [("Revision", 0x00, 2, 1), ("Version", 0x02, 2, 1),
              ("virtBase", 0x04, 4, VBASE), ("physBase", 0x08, 4, PBASE),
              ("memSize", 0x0c, 4, RAM_SIZE), ("topOfKernelData", 0x10, 4, page_tables),
              ("Video.v_baseAddr", 0x14, 4, FRAMEBUFFER_ADDRESS), ("Video.v_display", 0x18, 4, video_display),
              ("Video.v_rowBytes", 0x1c, 4, 1280), ("Video.v_width", 0x20, 4, 320),
              ("Video.v_height", 0x24, 4, 480), ("Video.v_depth", 0x28, 4, 32),
              ("machineType", 0x2c, 4, machine_type),
              ("deviceTreeP", 0x30, 4, tree_address - PBASE + VBASE),
              ("deviceTreeLength", 0x34, 4, len(populated_tree)),
              ("bootFlags", 0x138, 4, 0), ("memSizeActual", 0x13c, 4, RAM_SIZE)]
    bootargs = bytearray(0x140)
    for name, offset, width, value in fields:
        struct.pack_into("<H" if width == 2 else "<I", bootargs, offset, value)
    command_bytes = command_line.encode()
    bootargs[0x38:0x38 + len(command_bytes)] = command_bytes
    report["bootargs_fields"] = [{"name": name, "offset": offset, "offset_hex": hex(offset),
                                  "width": width, "value": value, "value_hex": hex(value)}
                                 for name, offset, width, value in fields]
    report["bootargs_command_line"] = {"offset": 0x38, "capacity": 256, "value": command_line}
    report["loads"].append(write(out, "bootargs.bin", bootargs, args_address))
    entry_physical = entry_virtual - VBASE + PBASE
    # Emit original-ISA ARM loads/stores into the diagnostic trampoline. These
    # initialize the state normally inherited from iBoot, without changing one
    # instruction in the original kernel. All four LCD window enable bits at
    # reset are zero; AppleH1CLCD at c03007c4 then falls through to uninitialized
    # framebuffer values. Window 1 avoids that proved invalid handoff.
    words, literals, fixups = [0xe321f0d3], [], []

    def load_literal(register, value):
        fixups.append((len(words), register, len(literals)))
        words.append(0)
        literals.append(value)

    lcd_writes = [(0x58, 1280, "Window 1 bytes per row"),
                  (0x5c, 6 << 8, "RGB888 format 6, stored in 32-bit pixels"),
                  (0x60, FRAMEBUFFER_ADDRESS, "Window 1 physical framebuffer"),
                  (0x64, (320 << 16) | 480, "Window 1 width and height"),
                  (0x68, 320, "Window 1 32-bit words per row"),
                  (0x08, 0x40, "Enable Window 1 after its fields are initialized")]
    if lcd_handoff:
        load_literal(2, 0x38900000)
        for offset, value, _ in lcd_writes:
            load_literal(3, value)
            words.append(0xe5823000 | offset)  # str r3,[r2,#offset]
    load_literal(0, args_address)
    load_literal(1, entry_physical)
    words.append(0xe12fff11)
    literal_start = len(words) * 4
    for instruction, register, literal in fixups:
        displacement = literal_start + literal * 4 - (instruction * 4 + 8)
        if not 0 <= displacement <= 4095:
            raise ValueError("Trampoline literal lies outside ARM load range")
        words[instruction] = 0xe59f0000 | register << 12 | displacement
    trampoline = struct.pack("<" + "I" * (len(words) + len(literals)), *(words + literals))
    report["lcd_handoff"] = {
        "enabled": lcd_handoff,
        "register_base": "0x38900000",
        "writes": [{"offset": hex(offset), "value": hex(value), "meaning": reason}
                   for offset, value, reason in lcd_writes] if lcd_handoff else [],
        "evidence": "Original AppleH1CLCD c03007c4 reads enable bit 0x40 then registers 0x58-0x64; c0300904 unpacks dimensions, c03008c4 decodes mode 6 as ARGB. Public openiBoot setWindow confirms field encoding and RGB888=6.",
        "boundary": "Minimal synthesized scanout handoff, not a full hardware LCD initialization or captured original iBoot register state."
    }
    report["loads"].append(write(out, "trampoline.bin", trampoline, trampoline_address))
    report["entry_virtual"] = hex(entry_virtual)
    report["entry_physical"] = hex(entry_physical)
    report["page_table_reservation"] = {"physical_address": hex(page_tables), "size": 0x5000,
        "evidence": "Original __start uses bootargs+0x10 for TTBR0/TTBR1 and clears 5120 words; arm_vm_init reserves 0x5000."}
    report["known_uncertainties"] = [
        "Bootloader handoff is synthesized; this does not execute BootROM or iBoot.",
        "BootArgs structure is from public Apple ARM source and key offsets are confirmed in this binary; trailing newer fields are zero/nonessential for Revision 1.",
        "machineType defaults to zero because its exact original iBoot value is not yet captured.",
        "Device-tree clock values follow the present emulator, not a measurement from original iPhone hardware.",
        "Most CPU/SoC state begins at emulator reset; iBoot hardware initialization is skipped apart from the explicitly synthesized LCD window handoff.",
        "The device tree still contains identity, trust, security and iBoot placeholders that could require additional populated values.",
        "Video properties match QEMU's 320x480 BGRA memory renderer; only the minimum LCD window handoff is synthesized, and panel/timing initialization remains unverified.",
        "Generic loader reset ordering and complete userland startup remain unverified until the parent executes and inspects this fallback."]
    argv = []
    for item in report["loads"]:
        spec = f"loader,file={item['path']},addr={item['physical_address_hex']},force-raw=on"
        if item["path"].endswith("trampoline.bin"):
            spec += ",cpu-num=0"
        argv += ["-device", spec]
    report["qemu_loader_argv"] = argv
    (out / "loader-argv.json").write_text(json.dumps(argv, indent=2) + "\n")
    separator = " " + chr(92) + "\n  "
    (out / "loader-args.txt").write_text(separator.join(shlex.quote(arg) for arg in argv) + "\n")
    (out / "direct-kernel-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if sha(kernel.read_bytes()) != EXPECTED_KERNEL or sha(tree.read_bytes()) != EXPECTED_TREE:
        raise ValueError("Original inputs changed unexpectedly")
    print(json.dumps({"output": str(out), "kernel_entry_virtual": hex(entry_virtual),
                      "kernel_entry_physical": hex(entry_physical), "bootargs_physical": hex(args_address),
                      "trampoline_physical": hex(trampoline_address), "loads": len(report["loads"]),
                      "status": report["status"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("devicetree", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--command-line", default="-v rd=disk0s1 serial=3 debug=0x14e")
    parser.add_argument("--machine-type", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--video-display", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--skip-lcd-handoff", action="store_true", help="Reproduce the invalid reset-state LCD diagnostic for comparison")
    args = parser.parse_args()
    prepare(args.kernel.resolve(), args.devicetree.resolve(), args.output.resolve(),
            args.command_line, args.machine_type, args.video_display, not args.skip_lcd_handoff)


if __name__ == "__main__":
    main()
