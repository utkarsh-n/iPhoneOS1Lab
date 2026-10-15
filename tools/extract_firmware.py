#!/usr/bin/env python3
"""Extract Apple's original iPhone OS 1.0 IPSW without modifying its binaries.

Format references: planetbeing/xpwn (GPL-3.0), includes/xpwn/{8900,img2,
lzssfile}.h, dmg/filevault.c, includes/dmg/dmg.h. The LZSS decoder implements
Haruhiko Okumura's freely distributable 1989 algorithm. Requires cryptography.
This implementation is GPL-3.0-or-later. Outputs are local research artifacts.
"""

import argparse
import hashlib
import hmac
import json
import os
import plistlib
import struct
import zipfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


IPSW_SHA256 = "468d8b10061642b32f79046d6266a775cb26f02879839d8d445bdec82085c51a"
def firmware_key(variable, expected_bytes):
    """Read caller-supplied firmware key material without saving it in reports."""
    value = os.environ.get(variable, "")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{variable} must contain hexadecimal key material") from error
    if len(decoded) != expected_bytes:
        raise ValueError(f"Set {variable} to a {expected_bytes}-byte hexadecimal key from your authorized firmware source")
    return decoded

SOURCE_URL = "https://secure-appldnld.apple.com/iPhone/061-3538.20070629.B7vXa/iPhone1,1_1.0_1A543a_Restore.ipsw"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact(path, **extra):
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": sha256(path), **extra}


def aes_cbc(data, key, iv):
    if len(data) % 16:
        raise ValueError("AES-CBC input is not a multiple of 16 bytes")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def unwrap_8900(data):
    if data[:4] != b"8900" or len(data) < 0x800:
        raise ValueError("Missing 8900 firmware header")
    if data[4:7] != b"1.0" or data[7] not in (3, 4):
        raise ValueError("Unsupported 8900 version or payload format")
    data_size, signature_offset, cert_offset, cert_size = struct.unpack_from("<4I", data, 12)
    if 0x800 + data_size > len(data) or 0x800 + cert_offset + cert_size > len(data):
        raise ValueError("8900 payload or certificate extends beyond input")
    header_digest = hashlib.sha1(data[:0x40]).digest()[:16]
    if aes_cbc(data[0x40:0x50], firmware_key('IPHONEOS1_HEADER_KEY', 16), bytes(16)) != header_digest:
        raise ValueError("8900 header signature mismatch")
    result = data[0x800:0x800 + data_size]
    if data[7] == 3:
        result = aes_cbc(result, firmware_key('IPHONEOS1_HEADER_KEY', 16), bytes(16))
    return result, {"format": data[7], "payload_size": data_size,
                    "signature_offset": signature_offset,
                    "certificate_size": cert_size, "header_signature_valid": True}


def unwrap_img2(data):
    if data[:4] != b"2gmI" or len(data) < 0x400:
        raise ValueError("Missing IMG2 firmware header")
    padded_size, data_size = struct.unpack_from("<2I", data, 0x10)
    checksum = struct.unpack_from("<I", data, 0x64)[0]
    if zlib.crc32(data[:0x64]) != checksum:
        raise ValueError("IMG2 header CRC32 mismatch")
    if data_size > padded_size or 0x400 + padded_size > len(data):
        raise ValueError("IMG2 payload extends beyond input")
    return data[0x400:0x400 + data_size]


def decode_lzss(data, expected_size):
    ring = bytearray(b" " * 4096)
    cursor, flags, source = 4096 - 18, 0, 0
    output = bytearray()
    while source < len(data):
        flags >>= 1
        if not flags & 0x100:
            flags = data[source] | 0xff00
            source += 1
        if flags & 1:
            if source >= len(data):
                raise ValueError("Truncated LZSS literal")
            value = data[source]
            source += 1
            output.append(value)
            ring[cursor] = value
            cursor = (cursor + 1) & 4095
        else:
            if source + 2 > len(data):
                raise ValueError("Truncated LZSS reference")
            low, high = data[source:source + 2]
            source += 2
            position = low | ((high & 0xf0) << 4)
            length = (high & 15) + 3
            for i in range(length):
                value = ring[(position + i) & 4095]
                output.append(value)
                ring[cursor] = value
                cursor = (cursor + 1) & 4095
        if len(output) > expected_size:
            raise ValueError("LZSS output exceeds declared size")
    if len(output) != expected_size:
        raise ValueError(f"LZSS size mismatch: {len(output)} != {expected_size}")
    return bytes(output)


def unwrap_comp(data):
    if data[:8] != b"complzss" or len(data) < 0x180:
        raise ValueError("Missing complzss kernel header")
    checksum, plain_size, packed_size = struct.unpack_from(">3I", data, 8)
    if 0x180 + packed_size > len(data):
        raise ValueError("Compressed kernel extends beyond input")
    result = decode_lzss(data[0x180:0x180 + packed_size], plain_size)
    if zlib.adler32(result) != checksum:
        raise ValueError("Decompressed kernel Adler32 mismatch")
    if result[:4] != b"\xce\xfa\xed\xfe":
        raise ValueError("Decompressed kernel is not a 32-bit little-endian Mach-O")
    return result, {"compressed_size": packed_size, "uncompressed_size": plain_size,
                    "adler32": f"{checksum:08x}", "adler32_valid": True}


def decrypt_rootfs(source, destination, key_hex):
    key = bytes.fromhex(key_hex)
    if len(key) != 36:
        raise ValueError("Root filesystem key must contain 16 AES and 20 HMAC bytes")
    with source.open("rb") as f, destination.open("wb") as out:
        header = f.read(72)
        if header[:8] != b"encrcdsa" or struct.unpack_from(">I", header, 8)[0] != 2:
            raise ValueError("Root filesystem is not FileVault version 2")
        block_size, data_size, data_offset = struct.unpack_from(">IQQ", header, 52)
        if block_size % 16 or not 16 <= block_size <= 1024 * 1024:
            raise ValueError("Invalid FileVault block size")
        if data_offset + ((data_size + block_size - 1) // block_size) * block_size > source.stat().st_size:
            raise ValueError("FileVault data extends beyond input")
        f.seek(data_offset)
        for number in range((data_size + block_size - 1) // block_size):
            iv = hmac.new(key[16:], struct.pack(">I", number), hashlib.sha1).digest()[:16]
            clear = aes_cbc(f.read(block_size), key[:16], iv)
            out.write(clear[:min(block_size, data_size - number * block_size)])
    with destination.open("rb") as f:
        f.seek(-512, 2)
        if f.read(4) != b"koly":
            raise ValueError("Decryption failed: no UDIF koly footer")
    return {"format": "FileVault v2", "block_size": block_size,
            "data_size": data_size, "data_offset": data_offset,
            "key_source": "https://theapplewiki.com/wiki/Keys:Heavenly_1A543a_(iPhone1,1)"}


def extract_hfs(source, destination):
    """Expand one Apple_HFS UDIF partition, preserving the exact filesystem bytes."""
    with source.open("rb") as f:
        f.seek(-512, 2)
        footer = f.read(512)
        if footer[:4] != b"koly":
            raise ValueError("Not a UDIF disk image")
        data_fork_offset = struct.unpack_from(">Q", footer, 24)[0]
        xml_offset, xml_size = struct.unpack_from(">2Q", footer, 216)
        if xml_offset + xml_size > source.stat().st_size - 512:
            raise ValueError("UDIF XML resource extends beyond input")
        f.seek(xml_offset)
        resources = plistlib.loads(f.read(xml_size))
        partitions = resources["resource-fork"]["blkx"]
        candidates = [p for p in partitions if "Apple_HFS" in p.get("Name", "")]
        if len(candidates) != 1:
            raise ValueError(f"Expected one HFS partition, found {len(candidates)}")
        partition = candidates[0]
        table = partition["Data"]
        if table[:4] != b"mish":
            raise ValueError("Invalid UDIF block table")
        first_sector, sectors, data_start = struct.unpack_from(">3Q", table, 8)
        checksum_type, checksum_bits, checksum = struct.unpack_from(">3I", table, 64)
        run_count = struct.unpack_from(">I", table, 200)[0]
        if 204 + 40 * run_count > len(table):
            raise ValueError("UDIF block table is truncated")
        with destination.open("w+b") as out:
            out.truncate(sectors * 512)
            # UDIF CRC covers stored runs; ignored sparse ranges do not contribute.
            crc = 0
            for i in range(run_count):
                kind, _, sector, count, compressed_offset, compressed_size = struct.unpack_from(">II4Q", table, 204 + i * 40)
                if kind in (0x7ffffffe, 0xffffffff):
                    continue
                if sector + count > sectors:
                    raise ValueError("UDIF run exceeds partition size")
                if kind in (0, 2):
                    continue
                f.seek(data_fork_offset + data_start + compressed_offset)
                packed = f.read(compressed_size)
                if len(packed) != compressed_size:
                    raise ValueError("Truncated UDIF run")
                if kind == 1:
                    clear = packed
                elif kind == 0x80000005:
                    clear = zlib.decompress(packed)
                else:
                    raise ValueError(f"Unsupported UDIF compression type: {kind:#x}")
                if len(clear) != count * 512:
                    raise ValueError("UDIF run size mismatch")
                crc = zlib.crc32(clear, crc)
                out.seek(sector * 512)
                out.write(clear)
            out.seek(1024)
            hfs_signature = out.read(2)
            if hfs_signature not in (b"H+", b"HX"):
                raise ValueError("Expanded partition lacks an HFS+ volume header")
            if checksum_type == 2 and checksum_bits == 32:
                if crc != checksum:
                    raise ValueError(f"UDIF partition CRC32 mismatch: {crc:08x} != {checksum:08x}")
    return {"partition": partition["Name"], "first_sector": first_sector,
            "sector_count": sectors, "run_count": run_count,
            "hfs_signature": hfs_signature.decode(), "crc32": f"{checksum:08x}",
            "crc32_valid": checksum_type == 2 and checksum_bits == 32}


def extract(ipsw, destination):
    if sha256(ipsw) != IPSW_SHA256:
        raise ValueError("IPSW SHA256 does not match iPhone1,1 / 1.0 / 1A543a")
    destination.mkdir(parents=True, exist_ok=True)
    extracted = destination / "ipsw"
    img2_dir = destination / "img2"
    img2_dir.mkdir(exist_ok=True)
    report = {"firmware": "iPhone OS 1.0", "build": "1A543a", "device": "iPhone1,1",
              "board": "m68ap", "source": SOURCE_URL, "ipsw": artifact(ipsw),
              "components": [], "format_references": [
                  "https://github.com/planetbeing/xpwn/blob/master/includes/xpwn/8900.h",
                  "https://github.com/planetbeing/xpwn/blob/master/includes/xpwn/img2.h",
                  "https://github.com/planetbeing/xpwn/blob/master/dmg/filevault.c",
                  "https://github.com/planetbeing/xpwn/blob/master/includes/dmg/dmg.h"]}
    with zipfile.ZipFile(ipsw) as z:
        for member in z.infolist():
            parts = Path(member.filename).parts
            if member.filename.startswith("/") or ".." in parts:
                raise ValueError("Unsafe ZIP member path")
        z.extractall(extracted)
    names = {"iBoot.m68ap.RELEASE.img2": "iboot.bin", "LLB.m68ap.RELEASE.img2": "llb.bin",
             "DeviceTree.m68ap.img2": "devicetree.bin", "iBSS.m68ap.RELEASE.dfu": "ibss.bin",
             "WTF.s5l8900xall.RELEASE.dfu": "wtf.bin", "694-5259-38.dmg": "restore.dmg",
             "kernelcache.restore.release.s5l8900xrb": "kernel.macho"}
    for source in sorted(extracted.rglob("*")):
        if not source.is_file():
            continue
        data = source.read_bytes()
        if data[:4] != b"8900":
            continue
        payload, info = unwrap_8900(data)
        payload_path = img2_dir / source.name
        payload_path.write_bytes(payload)
        component = {"input": artifact(source), "unwrapped_8900": artifact(payload_path, **info)}
        if source.name in names:
            layers = ["8900"]
            if payload[:4] == b"2gmI":
                payload = unwrap_img2(payload)
                layers.append("IMG2")
            if payload[:8] == b"complzss":
                payload, compression = unwrap_comp(payload)
                component["compression"] = compression
                layers.append("LZSS")
            output = destination / names[source.name]
            output.write_bytes(payload)
            component["output"] = artifact(output, layers=layers)
        report["components"].append(component)
    root_dmg = destination / "rootfs.decrypted.dmg"
    encryption = decrypt_rootfs(extracted / "694-5262-39.dmg", root_dmg, firmware_key('IPHONEOS1_ROOT_KEY', 36).hex())
    report["rootfs_dmg"] = artifact(root_dmg, **encryption)
    root_hfs = destination / "rootfs.hfs"
    report["rootfs_hfs"] = artifact(root_hfs, **extract_hfs(root_dmg, root_hfs))
    restore_hfs = destination / "restore.hfs"
    restore = (destination / "restore.dmg").read_bytes()
    if restore[1024:1026] in (b"H+", b"HX"):
        restore_hfs.write_bytes(restore)
        report["restore_hfs"] = artifact(restore_hfs, format="raw HFS",
                                        hfs_signature=restore[1024:1026].decode())
    else:
        report["restore_hfs"] = artifact(restore_hfs, **extract_hfs(destination / "restore.dmg", restore_hfs))
    (destination / "extraction-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"build": report["build"], "outputs": destination.as_posix(),
                      "components": len(report["components"]),
                      "rootfs_hfs": report["rootfs_hfs"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipsw", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    extract(args.ipsw.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
