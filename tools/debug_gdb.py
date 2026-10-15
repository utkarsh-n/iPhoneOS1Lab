#!/usr/bin/env python3
"""Small bounded GDB Remote Serial Protocol client for QEMU diagnostics."""
import argparse
import json
import socket
import struct
from pathlib import Path


class Remote:
    def __init__(self, port=12345, timeout=10):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout)
        self.socket.settimeout(timeout)

    def command(self, value):
        body = value.encode("ascii")
        self.socket.sendall(b"$" + body + b"#" + f"{sum(body) & 255:02x}".encode())
        response = self.read_packet()
        # QEMU can send an unsolicited stop notification when reconnecting.
        # Consume it before the response to an inspection/configuration packet.
        while response[:1] in ("T", "S") and value not in ("c", "s", "?"):
            response = self.read_packet()
        return response

    def interrupt(self):
        self.socket.sendall(b"\x03")
        return self.read_packet()

    def read_packet(self):
        while True:
            start = self.socket.recv(1)
            if not start:
                raise ConnectionError("GDB connection closed")
            if start != b"$":
                continue
            payload = bytearray()
            while True:
                byte = self.socket.recv(1)
                if byte == b"#":
                    break
                if not byte:
                    raise ConnectionError("GDB response ended")
                payload += byte
            checksum = self.socket.recv(2)
            self.socket.sendall(b"+")
            decoded = bytearray()
            i = 0
            while i < len(payload):
                if payload[i] == 125:
                    i += 1
                    decoded.append(payload[i] ^ 32)
                elif payload[i] == 42:
                    i += 1
                    decoded += bytes([decoded[-1]]) * (payload[i] - 29)
                else:
                    decoded.append(payload[i])
                i += 1
            text = decoded.decode("ascii")
            if text.startswith("O") and text != "OK":
                print(bytes.fromhex(text[1:]).decode("utf8", "replace"), flush=True)
                continue
            return text

    def registers(self):
        packet = self.command("g")
        if not packet or packet.startswith("E"):
            raise RuntimeError("ARM register packet unavailable: " + packet)
        values = struct.unpack("<16I", bytes.fromhex(packet)[:64])
        return {f"r{index}": f"0x{value:08x}" for index, value in enumerate(values)}

    def memory(self, address, length):
        if length > 1024:
            return b"".join(self.memory(address + offset, min(1024, length-offset))
                            for offset in range(0, length, 1024))
        value = self.command(f"m{address:x},{length:x}")
        if value.startswith("E"):
            raise RuntimeError(value)
        return bytes.fromhex(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--command", action="append", default=[])
    parser.add_argument("--registers", action="store_true")
    parser.add_argument("--memory", nargs=2, metavar=("ADDRESS", "LENGTH"))
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    remote = Remote(args.port, args.timeout)
    report = []
    for command in args.command:
        result = {"command": command, "response": remote.command(command)}
        report.append(result)
        print(json.dumps(result), flush=True)
    if args.registers:
        registers = remote.registers()
        report.append({"registers": registers})
        print(json.dumps(registers, indent=2), flush=True)
    if args.memory:
        value = remote.memory(int(args.memory[0], 0), int(args.memory[1], 0))
        print(value.hex(), flush=True)
        report.append({"memory": args.memory, "hex": value.hex()})
    if args.detach:
        print(json.dumps({"detach": remote.command("D")}), flush=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
