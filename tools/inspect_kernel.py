#!/usr/bin/env python3
"""Inspect original 32-bit ARM Mach-O kernel load commands and symbols."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN


SELECTED_SYMBOLS = {
    "__start", "_BootArgs", "_BootArgs_phys_ptr", "_arm_init", "_PE_init_platform",
    "_panic", "_pmap_bootstrap", "_StartIOKit", "_machine_startup", "_bsd_init",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    data = args.input.read_bytes()
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from("<7I", data)
    if magic != 0xFEEDFACE or cpu != 12:
        parser.error("Expected little-endian 32-bit ARM Mach-O")
    segments = []
    symbols = {}
    symbol_modes = {}
    entry = None
    symtab = None
    offset = 28
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > 28 + sizeofcmds:
            raise ValueError("Invalid load command bounds")
        if cmd == 1:
            name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, sgflags = struct.unpack_from("<16s8I", data, offset + 8)
            segments.append({
                "name": name.rstrip(b"\0").decode("ascii"), "vmaddr": vmaddr,
                "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize,
                "sections": nsects,
            })
        elif cmd == 2:
            symtab = struct.unpack_from("<4I", data, offset + 8)
        elif cmd == 5:
            flavor, count = struct.unpack_from("<II", data, offset + 8)
            if flavor == 1 and count == 17:
                entry = struct.unpack_from("<17I", data, offset + 16)[15]
        offset += size
    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        for i in range(nsyms):
            strx, typ, sect, desc, value = struct.unpack_from("<IBBHI", data, symoff + i * 12)
            if strx >= strsize:
                continue
            end = data.find(b"\0", stroff + strx, stroff + strsize)
            name = data[stroff + strx:end].decode("utf-8", "replace")
            if name in SELECTED_SYMBOLS:
                symbols[name] = hex(value)
                symbol_modes[name] = "Thumb" if desc & 8 else "ARM or data"
    else:
        nsyms = 0
    version = next((m.group().decode("ascii") for m in re.finditer(rb"Darwin Kernel Version[^\x00]+", data)), None)
    startup = []
    if entry:
        segment = next(s for s in segments if s["vmaddr"] <= entry < s["vmaddr"] + s["filesize"])
        fileoff = segment["fileoff"] + entry - segment["vmaddr"]
        disassembler = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
        startup = [{"address": hex(i.address), "mnemonic": i.mnemonic, "operands": i.op_str}
                   for i in disassembler.disasm(data[fileoff:fileoff + 0x18C], entry)]
    report = {
        "input": str(args.input), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "cpu_type": cpu, "cpu_subtype": subtype, "file_type": filetype,
        "kernel_version": version, "entry_virtual": hex(entry) if entry else None,
        "symbol_count": nsyms, "selected_symbols": symbols,
        "selected_symbol_modes": symbol_modes,
        "segments": [{**s, "vmaddr": hex(s["vmaddr"]), "vmsize": hex(s["vmsize"]),
                      "fileoff": hex(s["fileoff"]), "filesize": hex(s["filesize"])} for s in segments],
        "boot_args_startup_fields": {
            "pointer_register": "r0", "virtual_base_offset": 4, "physical_base_offset": 8,
            "ram_size_offset": 12, "top_of_kernel_data_offset": 16,
            "physical_symbol_translation": "virtual_address - boot_args.virtual_base + boot_args.physical_base",
        },
        "startup_disassembly": startup,
        "validation_boundary": "Static binary structure and instructions; no runtime boot assertion",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"ARM kernel entry {entry:#x}; {nsyms} symbols; wrote {args.report}")


if __name__ == "__main__":
    main()
