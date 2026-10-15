#!/usr/bin/env python3
"""Prepare a separate iPhone OS 1.0 filesystem for synthetic emulator storage.

Copies the verified raw HFS image, mounts only the copy, and changes fstab and
the SpringBoard environment. Original Apple executable bytes are preserved.
Requires macOS diskutil and the local user to be allowed to mount disk images.
"""

import argparse
import hashlib
import json
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def prepare(source, output):
    source, output = source.resolve(), output.resolve()
    if source == output:
        raise ValueError("The emulation image must be separate from the original")
    original_hash = digest(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError(f"Output already exists; choose a new image path: {output}")
    shutil.copy2(source, output)
    mount = Path(tempfile.mkdtemp(prefix="iphoneos1-emulation-"))
    attached = False
    binary_paths = ["System/Library/CoreServices/SpringBoard.app/SpringBoard",
                    "sbin/launchd", "usr/lib/dyld",
                    "System/Library/Frameworks/LayerKit.framework/LayerKit"]
    report = {"source": str(source), "source_sha256": original_hash,
              "output": str(output), "configuration_changes": [], "directories_created": []}
    try:
        command = ["diskutil", "image", "attach", "--nobrowse", "--mountPoint", str(mount),
                   "--mountOptions", "rw,noowners", "--plist", str(output)]
        result = subprocess.run(command, check=True, capture_output=True)
        report["attach_command"] = command
        report["attach_result"] = plistlib.loads(result.stdout)
        attached = True
        system = plistlib.loads((mount / "System/Library/CoreServices/SystemVersion.plist").read_bytes())
        if system.get("ProductBuildVersion") != "1A543a" or system.get("ProductVersion") != "1.0":
            raise ValueError("Mounted image is not iPhone OS 1.0 / 1A543a")
        report["system_version"] = system
        before = {name: digest(mount / name) for name in binary_paths}

        fstab = mount / "private/etc/fstab"
        old_fstab = fstab.read_text()
        new_fstab = "/dev/disk0s1 / hfs rw 0 1\n"
        fstab.write_text(new_fstab)
        report["configuration_changes"].append({"path": "/private/etc/fstab", "before": old_fstab,
            "after": new_fstab, "reason": "The synthetic NAND has one writable system partition."})

        relative_plist = "System/Library/LaunchDaemons/com.apple.SpringBoard.plist"
        springboard = mount / relative_plist
        original = plistlib.loads(springboard.read_bytes())
        updated = {**original, "EnvironmentVariables": {
            **original.get("EnvironmentVariables", {}), "LK_ENABLE_MBX2D": "0"}}
        springboard.write_bytes(plistlib.dumps(updated, sort_keys=False))
        report["configuration_changes"].append({"path": "/" + relative_plist,
            "before": original, "after": updated,
            "reason": "Request the LayerKit software graphics path while MBX GPU emulation is incomplete."})

        for name in ["private/var/root/Library/Preferences", "private/var/root/Library/AddressBook",
                     "private/var/root/Library/Lockdown", "private/var/root/Media",
                     "private/var/run", "private/var/tmp", "private/var/log", "private/var/db"]:
            directory = mount / name
            if not directory.exists():
                directory.mkdir(parents=True, mode=0o755)
                report["directories_created"].append("/" + name)
        after = {name: digest(mount / name) for name in binary_paths}
        if before != after:
            raise ValueError("Apple executable bytes changed unexpectedly")
        report["executables_unchanged"] = before
    finally:
        if attached:
            # diskutil image has attach but no detach subcommand on this macOS.
            subprocess.run(["hdiutil", "detach", str(mount)], check=True, capture_output=True)
        if mount.exists():
            mount.rmdir()
    if digest(source) != original_hash:
        raise ValueError("Original filesystem changed unexpectedly")
    report["output_sha256"] = digest(output)
    report["output_size"] = output.stat().st_size
    report_path = output.with_suffix(".changes.json")
    report_path.write_text(json.dumps(report, indent=2, default=str) + "\n")
    print(json.dumps({"output": str(output), "report": str(report_path),
                      "sha256": report["output_sha256"], "changes": len(report["configuration_changes"])}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    prepare(args.source, args.output)


if __name__ == "__main__":
    main()
