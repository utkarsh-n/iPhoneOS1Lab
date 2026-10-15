#!/usr/bin/env python3
"""Capture bounded 1A543a runtime snapshots through a local QEMU GDB stub.

Each sample opens a fresh connection, interrupts once, reads only allowlisted
MMIO and validated kernel-RAM objects, restores PhyMemMode=0, and detaches.
Saved user registers are trap frames, not current user execution. This tool
does not write guest memory/registers, acknowledge IRQs, or establish UI boot.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import time

from debug_gdb import Remote
from inspect_thread_layout import THREAD_FIELDS, mach_run_state, word
from prepare_kernel_boot import EXPECTED_KERNEL, parse_macho


ROOT = Path(__file__).resolve().parents[1]
KERNEL_DEFAULT = ROOT / "firmware/1A543a/kernelcache.s5l8900xrb.macho"
KERNEL_RAM_LOW, KERNEL_RAM_END = 0xc0000000, 0xc8000000
ALLPROC_ADDRESS, NPROCS_ADDRESS = 0xc01e042c, 0xc01c44a0
PROC_SIZE, PROC_NEXT, PROC_PID, PROC_NAME, PROC_TASK = 0x13c, 0, 0x24, 0xeb, 0x138
TASK_SIZE, TASK_HEAD, TASK_COUNT, TASK_BSD_PROC = 0x17c, 0x28, 0x30, 0x178
THREAD_SIZE, USER_FRAME_SIZE = 0x300, 0x44
MAX_PROCESSES, MAX_THREADS_PER_TASK, MAX_TOTAL_THREADS = 128, 64, 256
MAX_READ_BYTES, SAMPLE_SECONDS = 512 * 1024, 30

TIMER_BASE = 0x3e200000
TIMER_REGISTERS = {
    "config": 0xa0, "state": 0xa4, "reload": 0xa8,
    "count_buffer2": 0xac, "prescaler": 0xb0, "remaining": 0xb4,
}
UART_BASES = [0x3cc00000 + i * 0x4000 for i in range(5)]
# UERSTAT+14 clears errors, URXH+24 consumes bytes. UMSTAT+1c and the
# write-only transmit register+20 are also excluded. Reads are sparse.
UART_REGISTERS = {
    "ULCON": 0, "UCON": 4, "UFCON": 8, "UMCON": 0xc,
    "UTRSTAT": 0x10, "UFSTAT": 0x18, "UBRDIV": 0x28,
    "UFRACVAL": 0x2c, "STORED_30": 0x30,
    "STORED_34": 0x34, "STORED_38": 0x38,
}
SYSIC_BASE = 0x39a00000
SYSIC_ARRAYS = {"polarity": 0x80, "status": 0xa0,
                "enable": 0xc0, "type": 0xe0}
VIC_BASES = [0x38e00000, 0x38e01000]
# Current pl192_read's write-only SOFTINTCLEAR+1c falls through into ACK.
# Neither +1c nor VECTADDR+f00 may be read by this tool.
VIC_REGISTERS = {
    "IRQSTATUS": 0, "FIQSTATUS": 4, "RAWINTR": 8,
    "INTSELECT": 0xc, "INTENABLE": 0x10, "INTENCLEAR_READ_ZERO": 0x14,
    "SOFTINT": 0x18, "PROTECTION": 0x20,
    "SWPRIORITYMASK": 0x24, "PRIORITYDAISY": 0x28,
}
CLCD_BASE = 0x38900000
CLCD_REGISTERS = {
    "CONTROL_04": 4, "WINDOW_ENABLE_08": 8, "IRQ_ENABLE_14": 0x14,
    "IRQ_PENDING_18": 0x18, "REG_24": 0x24,
    **{f"WINDOW_REGISTER_{offset:02X}": offset
       for offset in range(0x58, 0xb4 + 4, 4)},
}
PHYSICAL_WORD_ALLOWLIST = {
    TIMER_BASE + 0x80, TIMER_BASE + 0x84,
    *[TIMER_BASE + offset for offset in TIMER_REGISTERS.values()],
    *[base + offset for base in UART_BASES for offset in UART_REGISTERS.values()],
    *[SYSIC_BASE + offset + group * 4
      for offset in SYSIC_ARRAYS.values() for group in range(7)],
    *[base + offset for base in VIC_BASES for offset in VIC_REGISTERS.values()],
    *[CLCD_BASE + offset for offset in CLCD_REGISTERS.values()],
}
SENTINELS = {
    "proc_pid": (0xc00f9e0c, 8),
    "proc_name": (0xc00f9e5c, 12),
    "thread_task_owner": (0xc002b770, 8),
    "timer_timebase_helper": (0xc0060650, 28),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def kernel_pointer(address, length, label):
    if address & 3 or not KERNEL_RAM_LOW <= address < KERNEL_RAM_END or \
            length <= 0 or address + length > KERNEL_RAM_END:
        raise ValueError(f"{label}: invalid canonical kernel RAM range "
                         f"{address:#x}+{length:#x}")


class Reader:
    """Enforce per-sample time/byte budgets and separate physical/virtual reads."""
    def __init__(self, remote, timeout):
        self.remote, self.timeout = remote, timeout
        self.deadline = time.monotonic() + SAMPLE_SECONDS
        self.bytes_read = 0
        self.mode = None

    def budget(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Per-sample 30-second inspection budget reached")
        self.remote.socket.settimeout(min(self.timeout, remaining))

    def command(self, command):
        self.budget()
        return self.remote.command(command)

    def set_mode(self, physical):
        result = self.command(f"Qqemu.PhyMemMode:{int(physical)}")
        if result != "OK":
            raise RuntimeError("Physical-memory mode change rejected: " + result)
        self.mode = bool(physical)

    def memory(self, address, length):
        if not 0 < length <= 1024 or self.bytes_read + length > MAX_READ_BYTES:
            raise ValueError("Per-read or per-sample memory byte limit exceeded")
        self.budget()
        data = self.remote.memory(address, length)
        if len(data) != length:
            raise RuntimeError(f"Short GDB memory read at {address:#x}: "
                               f"{len(data)} of {length}")
        self.bytes_read += length
        return data

    def virtual(self, address, length, label):
        if self.mode is not False:
            raise RuntimeError("Virtual read attempted outside PhyMemMode=0")
        kernel_pointer(address, length, label)
        return self.memory(address, length)

    def physical_word(self, address):
        if self.mode is not True or address not in PHYSICAL_WORD_ALLOWLIST:
            raise ValueError(f"Physical read not allowlisted: {address:#x}")
        return word(self.memory(address, 4), 0)


def register_packet(reader):
    packet = reader.command("g")
    if not packet or packet.startswith("E"):
        raise RuntimeError("Register packet unavailable: " + packet)
    raw = bytes.fromhex(packet)
    if len(raw) not in (68, 168):
        raise RuntimeError(f"Expected 68-byte core or 168-byte legacy ARM "
                           f"register packet; received {len(raw)}")
    registers = struct.unpack_from("<16I", raw)
    # This QEMU's legacy packet includes FPA registers between r15 and CPSR.
    # CPSR is the last word, not necessarily the word directly after r15.
    cpsr = struct.unpack_from("<I", raw, len(raw) - 4)[0]
    mode = {0x10: "user", 0x11: "FIQ", 0x12: "IRQ", 0x13: "SVC",
            0x17: "abort", 0x1b: "undefined", 0x1f: "system"}.get(cpsr & 31)
    return {"registers": {f"r{i}": f"0x{v:08x}" for i, v in enumerate(registers)},
            "cpsr": f"0x{cpsr:08x}", "mode": mode,
            "thumb": bool(cpsr & 0x20), "irq_masked": bool(cpsr & 0x80),
            "fiq_masked": bool(cpsr & 0x40), "packet_bytes": len(raw),
            "source": "Current CPU at this debugger interruption"}


def registers_at(reader, base, offsets):
    return {name: {"offset": hex(offset),
                   "value": f"0x{reader.physical_word(base + offset):08x}"}
            for name, offset in offsets.items()}


def devices(reader):
    reader.set_mode(True)
    high1 = reader.physical_word(TIMER_BASE + 0x80)
    low = reader.physical_word(TIMER_BASE + 0x84)
    high2 = reader.physical_word(TIMER_BASE + 0x80)
    timer = {"base": hex(TIMER_BASE), "high_before": hex(high1),
             "low": hex(low), "high_after": hex(high2),
             "coherent_high_words": high1 == high2,
             "ticks64": hex((high1 << 32) | low) if high1 == high2 else None,
             "registers": registers_at(reader, TIMER_BASE, TIMER_REGISTERS)}
    uart = [{"channel": i, "base": hex(base),
             "registers": registers_at(reader, base, UART_REGISTERS)}
            for i, base in enumerate(UART_BASES)]
    sysic = {"base": hex(SYSIC_BASE), "arrays": {
        name: [f"0x{reader.physical_word(SYSIC_BASE + offset + g * 4):08x}"
               for g in range(7)] for name, offset in SYSIC_ARRAYS.items()}}
    vic = [{"index": i, "base": hex(base),
            "registers": registers_at(reader, base, VIC_REGISTERS)}
           for i, base in enumerate(VIC_BASES)]
    clcd = {"base": hex(CLCD_BASE),
            "registers": registers_at(reader, CLCD_BASE, CLCD_REGISTERS),
            "boundary": "Readback only; unsupported offsets may return zero. "
                        "No framebuffer pixels or renderer state are read."}
    reader.set_mode(False)
    return {"timer": timer, "uart": uart, "sysic": sysic, "vic": vic, "clcd": clcd}


def original_sentinels(kernel):
    segments, _ = parse_macho(kernel)
    result = {}
    for name, (address, length) in SENTINELS.items():
        segment = next(s for s in segments
                       if s["vmaddr"] <= address and
                       address + length <= s["vmaddr"] + s["filesize"])
        offset = segment["fileoff"] + address - segment["vmaddr"]
        result[name] = kernel[offset:offset + length]
    return result


def validate_guest_kernel(reader, expected):
    results = []
    for name, (address, length) in SENTINELS.items():
        try:
            observed = reader.virtual(address, length, name)
            results.append({"name": name, "address": hex(address),
                            "expected": expected[name].hex(),
                            "observed": observed.hex(),
                            "matches": observed == expected[name]})
        except RuntimeError as error:
            results.append({"name": name, "address": hex(address),
                            "matches": False, "error": str(error)})
    return {"sentinels": results, "all_match": all(x["matches"] for x in results),
            "boundary": "Four instruction-range matches; not a full live kernel hash"}


def saved_user_frame(reader, pointer):
    raw = reader.virtual(pointer, USER_FRAME_SIZE, "saved ARM user frame")
    values = struct.unpack("<17I", raw)
    return {**{f"r{i}": f"0x{values[i]:08x}" for i in range(13)},
            **{name: f"0x{values[index]:08x}"
               for name, index in [("sp", 13), ("lr", 14), ("pc", 15), ("cpsr", 16)]}}


def capture_threads(reader, task_address, raw, record, thread_budget):
    count = word(raw, TASK_COUNT)
    pointer = word(raw, TASK_HEAD)
    head = task_address + TASK_HEAD
    record.update({"task_hex": raw.hex(), "thread_count": count,
                   "first_thread": hex(pointer), "threads": []})
    limit = min(count, MAX_THREADS_PER_TASK, thread_budget[0])
    seen = set()
    reason = "empty" if not count else None
    for _ in range(limit):
        if not pointer or pointer == head:
            reason = "queue_end"
            break
        if pointer in seen:
            reason = "cycle"
            break
        seen.add(pointer)
        try:
            node = reader.virtual(pointer, THREAD_SIZE, "thread")
        except (ValueError, RuntimeError) as error:
            reason = "invalid_thread"
            record["thread_error"] = str(error)
            break
        fields = {name: word(node, offset) for name, offset in THREAD_FIELDS.items()}
        item = {"thread": hex(pointer), "thread_hex": node.hex(),
                "fields": {name: hex(value) for name, value in fields.items()},
                "task_owner": hex(fields["owning_task"]),
                "owning_task_matches": fields["owning_task"] == task_address,
                "mach_run_state": mach_run_state(fields["scheduler_state_flags"]),
                "wait_event64": hex(fields["wait_event_low"] |
                                    fields["wait_event_high"] << 32),
                "saved_user_frame_pointer": hex(fields["arm_user_frame_pointer"]),
                "user_frame_boundary": "Most recently saved trap frame; not a current user PC"}
        record["threads"].append(item)
        thread_budget[0] -= 1
        if not item["owning_task_matches"]:
            reason = "owner_mismatch"
            break
        frame = fields["arm_user_frame_pointer"]
        if frame:
            try:
                item["user_regs"] = saved_user_frame(reader, frame)
            except (ValueError, RuntimeError) as error:
                item["user_frame_error"] = str(error)
        else:
            item["user_regs"] = None
        pointer = fields["task_queue_next"]
    if reason is None:
        reason = "queue_end" if pointer == head else "declared_count_or_limit_reached"
    record["thread_list_end_reason"] = reason
    record["unvisited_thread_next"] = hex(pointer)


def process_list(reader):
    result = {"processes": [], "tasks": []}
    result["nprocs"] = word(reader.virtual(NPROCS_ADDRESS, 4, "nprocs global"), 0)
    pointer = word(reader.virtual(ALLPROC_ADDRESS, 4, "allproc global"), 0)
    seen, thread_budget = set(), [MAX_TOTAL_THREADS]
    reason = None
    while pointer and len(seen) < MAX_PROCESSES:
        if pointer in seen:
            reason = "cycle"
            break
        seen.add(pointer)
        try:
            raw = reader.virtual(pointer, PROC_SIZE, "proc")
        except (ValueError, RuntimeError) as error:
            result["process_error"] = str(error)
            reason = "invalid_proc"
            break
        pid = word(raw, PROC_PID)
        name = raw[PROC_NAME:PROC_NAME + 17].split(b"\0")[0].decode("ascii", "replace")
        task_address = word(raw, PROC_TASK)
        proc = {"pid": pid, "name": name, "proc": hex(pointer), "task": hex(task_address)}
        result["processes"].append(proc)
        task = dict(proc)
        try:
            task_raw = reader.virtual(task_address, TASK_SIZE, "proc task")
            owner = word(task_raw, TASK_BSD_PROC)
            task.update({"bsd_proc": hex(owner), "bsd_proc_matches": owner == pointer})
            if owner == pointer:
                capture_threads(reader, task_address, task_raw, task, thread_budget)
            else:
                task["thread_list_end_reason"] = "task_bsd_proc_mismatch"
        except (ValueError, RuntimeError) as error:
            task["task_error"] = str(error)
        result["tasks"].append(task)
        pointer = word(raw, PROC_NEXT)
    result.update({"process_list_end_reason": reason or ("null" if not pointer else "limit"),
                   "unvisited_proc_next": hex(pointer),
                   "thread_budget_remaining": thread_budget[0]})
    return result


def cleanup(remote, result):
    """Cleanup has its own short timeouts even if the sample budget expired."""
    if remote is None:
        return
    interruption = None
    try:
        try:
            remote.socket.settimeout(2)
            result["physical_mode_restore"] = remote.command("Qqemu.PhyMemMode:0")
            if result["physical_mode_restore"] != "OK":
                result["physical_mode_restore_error"] = "Restore did not return OK"
        except (Exception, KeyboardInterrupt) as error:
            result["physical_mode_restore_error"] = f"{type(error).__name__}: {error}"
            if isinstance(error, KeyboardInterrupt):
                interruption = error
        try:
            remote.socket.settimeout(2)
            result["detach"] = remote.command("D")
            if result["detach"] != "OK":
                raise RuntimeError("Detach did not return OK: " + result["detach"])
        except (Exception, KeyboardInterrupt) as error:
            result["detach_error"] = f"{type(error).__name__}: {error}"
            if isinstance(error, KeyboardInterrupt):
                interruption = error
            try:
                # 'c' has no immediate reply; do not wait for a future stop packet.
                remote.socket.sendall(b"$c#63")
                result["resume_fallback_sent"] = True
            except (Exception, KeyboardInterrupt) as resume_error:
                result["resume_fallback_error"] = str(resume_error)
                if isinstance(resume_error, KeyboardInterrupt):
                    interruption = resume_error
    finally:
        try:
            remote.socket.close()
            result["socket_closed"] = True
        except Exception as error:
            result["socket_close_error"] = str(error)
    if interruption:
        raise interruption


def capture_sample(args, sample, expected):
    remote, reader = None, None
    begin = time.monotonic()
    sample["started_utc"] = utc_now()
    try:
        remote = Remote(args.port, args.timeout)
        reader = Reader(remote, args.timeout)
        reader.budget()
        sample["interrupt_attempts"] = 1
        sample["stop_reply"] = remote.interrupt()
        if sample["stop_reply"][:1] not in ("T", "S"):
            raise RuntimeError("Unexpected interrupt reply: " + sample["stop_reply"])
        sample["cpu"] = register_packet(reader)
        sample["physical_mode_initial"] = reader.command("qqemu.PhyMemMode")
        reader.set_mode(False)
        sample["devices"] = devices(reader)
        sample["guest_kernel_check"] = validate_guest_kernel(reader, expected)
        if sample["guest_kernel_check"]["all_match"]:
            sample.update(process_list(reader))
        else:
            sample["process_list_skipped"] = "Original instruction sentinels did not all match"
    except Exception as error:
        sample["capture_error"] = f"{type(error).__name__}: {error}"
    finally:
        cleanup(remote, sample)
        sample["finished_utc"] = utc_now()
        sample["elapsed_host_seconds"] = round(time.monotonic() - begin, 6)
        if reader:
            sample["memory_bytes_read"] = reader.bytes_read


def comparison(previous, current):
    result = {"left_sample": previous["index"], "right_sample": current["index"],
              "boundary": "Differences show distinct snapshots, not successful scheduling or UI"}
    a, b = previous.get("cpu", {}), current.get("cpu", {})
    if a and b:
        result["current_cpu_pc_equal"] = a["registers"]["r15"] == b["registers"]["r15"]
        result["current_cpu_registers_equal"] = a == b
    a = previous.get("devices", {}).get("timer", {}).get("ticks64")
    b = current.get("devices", {}).get("timer", {}).get("ticks64")
    if a is not None and b is not None:
        result["timer_tick_delta_mod64"] = hex((int(b, 16) - int(a, 16)) & ((1 << 64) - 1))
    return result


def save_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, default=KERNEL_DEFAULT)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.samples <= 16 or \
            not 0 <= args.interval <= 60 or not 0.5 <= args.timeout <= 10:
        parser.error("Require port1..65535, samples1..16, interval0..60, timeout0.5..10")
    kernel = args.kernel.read_bytes()
    digest = hashlib.sha256(kernel).hexdigest()
    if digest != EXPECTED_KERNEL:
        parser.error("Local kernel must match the verified original 1A543a system kernel")
    expected = original_sentinels(kernel)
    report = {
        "target": "iPhone1,1 iPhone OS 1.0 1A543a", "port": args.port,
        "kernel": str(args.kernel), "local_kernel_sha256": digest,
        "layout_source": "tools/inspect_thread_layout.py and original _proc_pid/_proc_name",
        "limits": {"max_processes": MAX_PROCESSES, "max_threads_per_task": MAX_THREADS_PER_TASK,
                   "max_total_threads": MAX_TOTAL_THREADS, "max_read_bytes": MAX_READ_BYTES,
                   "sample_seconds": SAMPLE_SECONDS, "interval_seconds": args.interval},
        "safety": {"physical_reads": "Only sparse 32-bit allowlisted non-acknowledging registers",
                   "excluded_uart_offsets": ["0x14", "0x1c", "0x20", "0x24"],
                   "excluded_vic_offsets": ["0x1c", "0xf00"],
                   "virtual_reads": "Aligned canonical kernel-RAM objects and four original-code sentinels",
                   "cleanup": "Restore PhyMemMode0, detach/resume, close socket after every sample"},
        "interpretation": [
            "CPU registers are current only at their individual debugger interruption.",
            "User PCs are most recently saved trap frames; they do not identify current user execution.",
            "Runnable flags or equal/different PCs alone do not prove CPU or SpringBoard progress.",
            "Timer deltas measure modeled virtual time, not UI responsiveness or instruction counts.",
            "Guest memory/registers are never written and interrupt/FIFO acknowledgements are excluded.",
            "Failed cleanup is reported; a sent fallback resume packet is not confirmation of resumed execution.",
        ], "samples": [], "comparisons": [], "full_boot_verified": False,
    }
    try:
        for index in range(args.samples):
            if index:
                time.sleep(args.interval)
            sample = {"index": index}
            report["samples"].append(sample)
            capture_sample(args, sample, expected)
            if index:
                report["comparisons"].append(comparison(report["samples"][index - 1], sample))
            save_report(args.report, report)
            cpu = sample.get("cpu", {}).get("registers", {}).get("r15", "unavailable")
            print(f"Sample {index}: CPU PC {cpu}; report {args.report}", flush=True)
    except KeyboardInterrupt:
        report["interrupted_by_user"] = True
    finally:
        save_report(args.report, report)
    return 1 if any("capture_error" in s or "detach_error" in s or
                    "physical_mode_restore_error" in s or "socket_close_error" in s
                    for s in report["samples"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
