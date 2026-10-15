#!/usr/bin/env python3
"""Record binary-proved 1A543a process/task/thread offsets and decode saved dumps.

This is offline inspection only. It never attaches to GDB or reads live memory.
User register frames are the most recently saved trap state, not a live-PC claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from prepare_kernel_boot import EXPECTED_KERNEL, parse_macho

RANGES = {
    "proc_task_from_proc_pidtaskinfo": (0xc011c166, 0xc011c184, "Thumb"),
    "proc_task_from_task_for_pid": (0xc011dbf8, 0xc011dc10, "Thumb"),
    "task_thread_count_and_head": (0xc002583e, 0xc002589e, "Thumb"),
    "thread_task_queue_next": (0xc0025900, 0xc002592e, "Thumb"),
    "thread_task_owner": (0xc002b770, 0xc002b778, "Thumb"),
    "task_bsd_proc_pointer": (0xc002b5ac, 0xc002b5ba, "Thumb"),
    "thread_wait_queue_and_event64": (0xc002a0bc, 0xc002a0f0, "Thumb"),
    "thread_block_continuation_and_parameter": (0xc00227de, 0xc00227e8, "Thumb"),
    "thread_scheduler_flags_to_mach_state": (0xc0026748, 0xc00267ee, "Thumb"),
    "machine_stack_attach_detach": (0xc0061266, 0xc0061296, "Thumb"),
    "arm_user_register_frame": (0xc0061cdc, 0xc0061d04, "Thumb"),
    "arm_kernel_switch_context": (0xc005fa20, 0xc005fa4c, "ARM"),
}

THREAD_FIELDS = {
    "wait_queue": 0x0c, "wait_event_low": 0x10, "wait_event_high": 0x14,
    "continuation": 0x44, "continuation_parameter": 0x48,
    "kernel_stack_base": 0x54, "scheduler_state_flags": 0x5c,
    "task_queue_next": 0x1ac, "task_queue_previous": 0x1b0,
    "arm_user_frame_pointer": 0x28c, "arm_kernel_context_pointer": 0x29c,
    "owning_task": 0x2fc,
}


def word(data, offset):
    if offset + 4 > len(data):
        raise ValueError(f"Dump is too short for field at {offset:#x}")
    return struct.unpack_from("<I", data, offset)[0]


def mach_run_state(flags):
    # Branch order and results from original _thread_info_internal.
    for bit, state in [(0x10, 5), (0x4, 1), (0x8, 4), (0x2, 2), (0x1, 3)]:
        if flags & bit:
            return state
    return 0


def decode_snapshot(path):
    snapshot = json.loads(path.read_text())
    decoded = []
    for task in snapshot["tasks"]:
        result = {key: task[key] for key in ("pid", "name", "proc", "task")}
        raw_task = bytes.fromhex(task["task_hex"])
        result["thread_count"] = word(raw_task, 0x30)
        result["first_thread"] = hex(word(raw_task, 0x28))
        result["threads"] = []
        for thread in task["threads"]:
            raw = bytes.fromhex(thread["thread_hex"])
            fields = {name: word(raw, offset) for name, offset in THREAD_FIELDS.items()}
            item = {"thread": thread["thread"],
                    "fields": {key: hex(value) for key, value in fields.items()},
                    "mach_run_state": mach_run_state(fields["scheduler_state_flags"]),
                    "wait_event64": hex(fields["wait_event_low"] |
                                        fields["wait_event_high"] << 32),
                    "owning_task_matches": fields["owning_task"] == int(task["task"], 16),
                    "saved_user_registers": thread.get("user_regs")}
            result["threads"].append(item)
        decoded.append(result)
    return decoded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    data = args.kernel.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_KERNEL:
        parser.error("Kernel does not match the original 1A543a system kernel")
    segments, _ = parse_macho(data)
    evidence = {}
    for label, (start, end, mode) in RANGES.items():
        segment = next(s for s in segments
                       if s["vmaddr"] <= start and end <= s["vmaddr"] + s["filesize"])
        offset = segment["fileoff"] + start - segment["vmaddr"]
        decoder = Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN |
                     (CS_MODE_THUMB if mode == "Thumb" else CS_MODE_ARM))
        evidence[label] = [{"address": hex(i.address), "mnemonic": i.mnemonic,
                            "operands": i.op_str}
                           for i in decoder.disasm(data[offset:offset + end - start], start)]
    report = {
        "kernel": str(args.kernel), "kernel_sha256": digest,
        "scope": "Static original-binary layout proof and optional saved-dump decoding",
        "proc_offsets": {"task": "0x138"},
        "task_offsets": {"first_thread": "0x28", "thread_count": "0x30",
                         "bsd_proc": "0x178"},
        "thread_offsets": {key: hex(value) for key, value in THREAD_FIELDS.items()},
        "arm_user_frame": {**{f"r{i}": hex(i * 4) for i in range(13)},
                           "sp": "0x34", "lr": "0x38", "pc": "0x3c", "cpsr": "0x40"},
        "arm_kernel_context": {**{f"r{i}": hex(0x10 + (i - 4) * 4) for i in range(4, 13)},
                                "sp": "0x34", "lr": "0x38",
                                "default_pointer": "kernel_stack_base + 0x3fb0"},
        "scheduler_flags_to_mach_run_state": {"0x10": 5, "0x4": 1, "0x8": 4,
                                               "0x2": 2, "0x1": 3},
        "instructions": evidence,
        "literal_values": {"machine_stack_top_delta_at_c0061298": "0x3fb0"},
        "limits": ["Saved user PC reflects the latest saved trap state, not current execution.",
                   "Runnable state does not establish CPU progress or prove a busy loop.",
                   "A zero kernel-stack/context pointer is normal for a thread using a continuation.",
                   "No firmware instructions or guest state are modified."],
    }
    if args.snapshot:
        report["snapshot"] = str(args.snapshot)
        report["decoded_tasks"] = decode_snapshot(args.snapshot)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Recorded original process/task/thread offsets in {args.report}")


if __name__ == "__main__":
    main()
