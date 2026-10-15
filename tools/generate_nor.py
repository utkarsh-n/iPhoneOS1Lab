#!/usr/bin/env python3
"""Build and validate synthetic m68ap NOR using the original 1G layout.

The C implementation retains devos50's QEMU hash schedule, including its
synthetic UID. This is an emulator input; it is not a device flash image.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import zlib


SOURCE_COMMIT = "12c846dcee8ad5c2935370ee48559b82b42249a2"
ASSETS = (
    "DeviceTree.m68ap.img2", "batterycharging.img2", "applelogo.img2",
    "needservice.img2", "batterylow0.img2", "batterylow1.img2", "recoverymode.img2",
)


def chrp_checksum(header):
    value = header[0] + sum(header[2:16])
    while value > 255:
        value = (value >> 8) + (value & 255)
    return value


def inspect_nor(output, assets):
    data = output.read_bytes()
    if len(data) != 1024 * 1024:
        raise ValueError("NOR must be exactly 1 MiB")
    header = data[0x8400:0x8434]
    if struct.unpack_from("<I", header)[0] != 0x494D4732:
        raise ValueError("Invalid NOR image-table magic")
    if struct.unpack_from("<I", header, 0x30)[0] != zlib.crc32(header[:0x30]):
        raise ValueError("Invalid NOR image-table CRC32")
    images = []
    offset = 1040 * 0x40
    for name in ASSETS:
        original = (assets / name).read_bytes()
        embedded = data[offset:offset + len(original)]
        if embedded[:4] != b"2gmI":
            raise ValueError(f"Invalid IMG2 magic for {name}")
        expected_crc = struct.unpack_from("<I", embedded, 0x64)[0]
        if expected_crc != zlib.crc32(embedded[:0x64]):
            raise ValueError(f"Invalid IMG2 header CRC32 for {name}")
        flags = struct.unpack_from("<I", embedded, 0x1C)[0]
        if flags & (1 << 30):
            size = struct.unpack_from("<I", embedded, 0x60)[0]
            extension_crc = struct.unpack_from("<I", embedded, 0x68)[0]
            if extension_crc != zlib.crc32(embedded[0x6C:0x6C + size]):
                raise ValueError(f"Invalid IMG2 extension CRC32 for {name}")
        if embedded[0x400:] != original[0x400:]:
            raise ValueError(f"IMG2 payload changed for {name}")
        block_length = struct.unpack_from("<I", embedded, 0x18)[0]
        images.append({
            "name": name, "offset": offset, "length": len(original),
            "type": embedded[4:8][::-1].decode("ascii"), "blocks": block_length,
            "source_sha256": hashlib.sha256(original).hexdigest(),
            "payload_preserved": True,
        })
        offset += block_length * 0x40
    nvram = data[0xFC000:0xFE000]
    for start in (0, 0x20, 0x820, 0x1030):
        part = nvram[start:start + 16]
        if part[1] != chrp_checksum(part):
            raise ValueError(f"Invalid NVRAM CHRP checksum at {start:#x}")
    if struct.unpack_from("<I", nvram, 0x10)[0] != zlib.adler32(nvram[0x14:]):
        raise ValueError("Invalid NVRAM Adler32")
    variables = dict(entry.decode("ascii").split("=", 1)
                     for entry in nvram[0x30:0x820].split(b"\0") if entry)
    for key, value in {"auto-boot": "true", "boot-command": "fsboot", "bootdelay": "0"}.items():
        if variables.get(key) != value:
            raise ValueError(f"Missing iBoot-159 startup variable {key}")
    return {
        "format": "synthetic-m68ap-qemu-nor-v1", "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "images": images,
        "checks": ["image table CRC32", "IMG2 header CRC32", "IMG2 extension CRC32",
                   "unchanged IMG2 payloads", "NVRAM CHRP checksums", "NVRAM Adler32"],
        "syscfg": {"model": "MA712", "serial": "QEMU-M68AP", "synthetic": True},
        "nvram_variables": variables,
        "hash_schedule": "devos50 QEMU synthetic UID; not hardware UID",
        "upstream": "https://github.com/devos50/generate-ipod-touch-1g-nor/tree/" + SOURCE_COMMIT,
    }


def main():
    raise SystemExit("NOR generator implementation is omitted from this public snapshot; see PUBLICATION.md for upstream provenance.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--boot-args", default="debug=0x8 kextlog=0xfff cpus=1 rd=disk0s1 serial=1 io=0xffff8fff")
    parser.add_argument("--openssl-prefix", type=Path, default=Path("/opt/homebrew/opt/openssl@3"))
    args = parser.parse_args()
    source = Path(__file__).resolve().parent / "nor_generator"
    build = source.parent.parent / "build" / "tools"
    build.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    missing = [str(args.assets / name) for name in ASSETS if not (args.assets / name).is_file()]
    if missing:
        parser.error("Missing unwrapped IMG2 assets: " + ", ".join(missing))
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if not compiler:
        parser.error("C compiler not found")
    binary = build / "generate_nor"
    command = [compiler, "-std=gnu11", "-Wno-deprecated-declarations",
               str(source / "generate_nor.c"), str(source / "aes.c"), "-o", str(binary),
               "-I" + str(args.openssl_prefix / "include"),
               "-L" + str(args.openssl_prefix / "lib"), "-lcrypto"]
    subprocess.run(command, check=True)
    subprocess.run([str(binary), str(args.assets), str(args.output), args.boot_args], check=True)
    report = inspect_nor(args.output, args.assets)
    report["boot_args"] = args.boot_args
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
