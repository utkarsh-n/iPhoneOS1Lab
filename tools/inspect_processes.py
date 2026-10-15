#!/usr/bin/env python3
"""Read the original 1A543a kernel process list through its local GDB stub."""
import argparse
import json
import struct
from pathlib import Path
from debug_gdb import Remote


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    remote = Remote(args.port, 10)
    report = {'target': 'iPhone1,1 1.0 1A543a', 'processes': [],
              'field_evidence': 'Original _proc_pid at c00f9e0c reads +24; '
                                '_proc_name at c00f9e5c reads name at +eb.'}
    try:
        report['stop'] = remote.interrupt()
        report['registers'] = remote.registers()
        report['nprocs'] = struct.unpack('<I', remote.memory(0xc01c44a0, 4))[0]
        pointer = struct.unpack('<I', remote.memory(0xc01e042c, 4))[0]
        visited = set()
        while pointer and pointer not in visited and len(visited) < 128:
            visited.add(pointer)
            node = remote.memory(pointer, 0x110)
            pid = struct.unpack_from('<I', node, 0x24)[0]
            name = node[0xeb:0xeb+17].split(b'\0')[0].decode('ascii', 'replace')
            report['processes'].append({'address': hex(pointer), 'pid': pid, 'name': name})
            pointer = struct.unpack_from('<I', node)[0]
        report['unvisited_next'] = hex(pointer)
    finally:
        report['detach'] = remote.command('D')
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
