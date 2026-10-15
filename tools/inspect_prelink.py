#!/usr/bin/env python3
"""Decode the original kernel's IOKit-serialized prelinked extension metadata."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET


def decode(element, objects):
    if 'IDREF' in element.attrib:
        return objects[element.attrib['IDREF']]
    tag = element.tag
    if tag == 'dict':
        children = list(element)
        if len(children) % 2 or any(c.tag != 'key' for c in children[::2]):
            raise ValueError('Malformed serialized dictionary')
        value = {children[i].text: decode(children[i+1], objects)
                 for i in range(0, len(children), 2)}
    elif tag == 'array':
        value = [decode(child, objects) for child in element]
    elif tag in ('string', 'key'):
        value = element.text or ''
    elif tag == 'integer':
        value = int(element.text, 0)
    elif tag == 'data':
        value = {'base64': base64.b64encode(base64.b64decode(element.text or '')).decode()}
    elif tag in ('true', 'false'):
        value = tag == 'true'
    else:
        raise ValueError('Unsupported serialized tag: '+tag)
    if 'ID' in element.attrib:
        objects[element.attrib['ID']] = value
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    data = args.kernel.read_bytes()
    if struct.unpack_from('<II', data) != (0xfeedface, 12):
        raise ValueError('Expected 32-bit little-endian ARM Mach-O')
    offset = 28
    info = None
    segments = []
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, length = struct.unpack_from('<II', data, offset)
        if length < 8 or offset+length > len(data):
            raise ValueError('Invalid load command')
        if command == 1:
            name, address, mem_size, file_offset, file_size, _, _, sections, _ = struct.unpack_from('<16s8I', data, offset+8)
            segments.append((address, file_offset, file_size))
            if name.split(b'\0')[0] == b'__PRELINK':
                for i in range(sections):
                    section = struct.unpack_from('<16s16s9I', data, offset+56+i*68)
                    if section[0].split(b'\0')[0] == b'__info':
                        info = data[section[4]:section[4]+section[3]].split(b'\0')[0]
        offset += length
    if info is None:
        raise ValueError('No prelink metadata section')
    extensions = decode(ET.fromstring(info), {})
    def memory(address, length):
        for va, fo, size in segments:
            if va <= address and address+length <= va+size:
                pos = fo+address-va
                return data[pos:pos+length]
        raise ValueError('Metadata address outside kernel segments')
    selected = []
    for item in extensions:
        record = {'bundle_id': item.get('CFBundleIdentifier'),
                  'executable': item.get('CFBundleExecutable'),
                  'version': item.get('CFBundleVersion')}
        prelink = {key: value for key, value in item.items() if 'Prelink' in key}
        record['prelink'] = prelink
        address = item.get('OSBundlePrelinkKmodInfo')
        packed = item.get('OSBundlePrelink')
        if isinstance(packed, dict) and 'base64' in packed:
            raw = base64.b64decode(packed['base64'], validate=True)
            if len(raw) < 16 or len(raw) % 4:
                raise ValueError('Malformed prelink descriptor')
            words = struct.unpack('>'+str(len(raw)//4)+'I', raw)
            record['prelink_descriptor_words'] = [hex(word) for word in words]
            address = words[0]
        if isinstance(address, int) and address:
            try:
                kmod = memory(address, 0xa8)
                record['loaded_address'] = hex(struct.unpack_from('<I', kmod, 0x94)[0])
                record['loaded_size'] = struct.unpack_from('<I', kmod, 0x98)[0]
                record['kmod_name'] = kmod[12:76].split(b'\0')[0].decode('ascii', 'replace')
                if record['kmod_name'] != record['bundle_id']:
                    raise ValueError('Kmod name does not match bundle identifier')
                record['kmod_info_address'] = hex(address)
                memory(int(record['loaded_address'], 16), record['loaded_size'])
            except ValueError as error:
                record['kmod_error'] = str(error)
        selected.append(record)
    report = {'kernel_sha256': hashlib.sha256(data).hexdigest(),
              'extensions': selected, 'full_metadata': extensions,
              'boundary': 'Static prelinked metadata; loaded state and runtime addresses require guest verification'}
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'extension_count': len(extensions),
                      'report': str(args.report)}, indent=2))


if __name__ == '__main__':
    main()
