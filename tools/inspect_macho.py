#!/usr/bin/env python3
"""Inspect 32-bit ARM Mach-O headers without executing or modifying binaries."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

def inspect(path):
    data = path.read_bytes()
    if len(data) < 28 or data[:4] != b'\xce\xfa\xed\xfe':
        raise ValueError('Expected a thin, little-endian 32-bit Mach-O')
    magic, cpu, subtype, kind, count, command_bytes, flags = struct.unpack_from('<7I', data)
    end = 28 + command_bytes
    if end > len(data) or count > command_bytes//8:
        raise ValueError('Load commands exceed file bounds')
    result = dict(path=str(path.resolve()), size=len(data), sha256=hashlib.sha256(data).hexdigest(),
        cpu_type=cpu, cpu_subtype=subtype, file_type=kind, flags=flags,
        load_command_count=count, segments=[], dependencies=[], entry_pc=None,
        symbols=[])
    offset = 28
    for _ in range(count):
        if offset+8 > end:
            raise ValueError('Truncated load command')
        command, size = struct.unpack_from('<2I', data, offset)
        if size < 8 or offset+size > end:
            raise ValueError('Invalid load command size')
        if command == 1:
            if size < 56:
                raise ValueError('Truncated segment command')
            _, _, name, address, memory_size, file_offset, file_size, maxprot, prot, sections, segflags = struct.unpack_from('<2I16s8I', data, offset)
            if file_offset+file_size > len(data):
                raise ValueError('Segment exceeds file bounds')
            result['segments'].append(dict(name=name.split(b'\0')[0].decode(),
                address=f'0x{address:08x}', memory_size=memory_size, file_offset=file_offset,
                file_size=file_size, protection=prot, section_count=sections))
        elif command in (0xc, 0x80000018, 0x8000001f):
            name_offset = struct.unpack_from('<I', data, offset+8)[0]
            if name_offset >= size:
                raise ValueError('Invalid dylib name offset')
            name = data[offset+name_offset:offset+size].split(b'\0')[0].decode('utf8', 'replace')
            result['dependencies'].append(name)
        elif command in (4,5) and size >= 84:
            flavor, words = struct.unpack_from('<2I',data,offset+8)
            if cpu == 12 and flavor == 1 and words >= 17:
                result['entry_pc'] = f'0x{struct.unpack_from("<I", data, offset+16+15*4)[0]:08x}'
        elif command == 2:
            symoff, nsyms, stroff, strsize = struct.unpack_from('<4I',data,offset+8)
            if symoff+nsyms*12 > len(data) or stroff+strsize > len(data):
                raise ValueError('Symbol table exceeds file bounds')
            result['symbol_count'] = nsyms
            for i in range(nsyms):
                index, typ, section, desc, value = struct.unpack_from('<IBBHI', data, symoff+i*12)
                if index and index < strsize and not typ & 0xe0:
                    start = stroff + index
                    stop = data.find(b'\0', start, stroff + strsize)
                    if stop < 0:
                        raise ValueError('Unterminated symbol name')
                    name=data[start:stop].decode('utf8','replace')
                    result['symbols'].append(dict(name=name,address=f'0x{value:08x}',type=typ))
        offset += size
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binaries',type=Path,nargs='+')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--symbols',action='store_true')
    args=parser.parse_args()
    results=[inspect(p) for p in args.binaries]
    if not args.symbols:
        for result in results:
            result.pop('symbols')
    output=json.dumps(results,indent=2)+'\n'
    if args.output:
        args.output.write_text(output)
    else:
        print(output,end='')

if __name__=='__main__':
    main()
