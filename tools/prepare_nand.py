#!/usr/bin/env python3
"""Generate M68 NAND page files with C000 metadata and explicit bank geometry."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
UPSTREAM_COMMIT='7bda431b215f8282d8ec7d6326dc40bbc4f63299'

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda:file.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('filesystem',type=Path)
    parser.add_argument('output',type=Path)
    parser.add_argument('--banks',type=int,choices=(4,8),default=4,
        help='M68 has four banks in its original device tree; eight reproduces the older N45 geometry')
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    filesystem=args.filesystem.resolve()
    output=args.output.resolve()
    if output.exists():
        parser.error('Output already exists; choose a new NAND directory')
    if filesystem.stat().st_size % 2048:
        parser.error('HFS partition size must be a multiple of the 2048-byte NAND page')
    with filesystem.open('rb') as image:
        image.seek(1024)
        if image.read(2) not in (b'HX',b'H+'):
            parser.error('Expected a raw HFS+/HFSX partition')
    upstream=ROOT/'vendor/generate-nand'
    commit=subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()
    if commit!=UPSTREAM_COMMIT:
        parser.error('NAND generator must use the pinned original 1G commit')
    original=(upstream/'generate_nand.c').read_text()
    needle='#define FIL_ID 0x43303032'
    if original.count(needle)!=1:
        raise ValueError('Unexpected upstream FIL_ID definition')
    source=original.replace(needle,'#define FIL_ID 0x43303030')
    # Override only active geometry in the temporary source copy. Leave WMR
    # maximum-capacity array sizes unchanged: they form the on-flash structs.
    for definition in ('#define BANKS 8','#define PAGES_PER_SUBLOCK 1024'):
        if source.count(definition)!=1:
            raise ValueError('Unexpected upstream geometry definition: '+definition)
        name=definition.split()[1]
        source=source.replace(definition,'#ifndef '+name+'\n'+definition+'\n#endif')
    # Original malloc leaves unused MBR/GPT bytes indeterminate, including bytes
    # covered by GPT CRCs. Zero output page allocations for repeatable metadata.
    source=source.replace('malloc(BYTES_PER_PAGE)','calloc(BYTES_PER_PAGE, 1)')
    virtual_pages_per_block=128*args.banks
    compiler_geometry=['-DBANKS='+str(args.banks),
                       '-DPAGES_PER_SUBLOCK='+str(virtual_pages_per_block)]
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='m68-nand-',dir=output.parent) as temp:
        temp=Path(temp)
        (temp/'generate_nand.c').write_text(source)
        (temp/'filesystem-readonly.img').symlink_to(filesystem)
        binary=temp/'generate_nand'
        subprocess.run(['clang','-O2',*compiler_geometry,'-I'+str(upstream),str(temp/'generate_nand.c'),
                        '-o',str(binary),'-Wno-format','-Wno-incompatible-pointer-types'],check=True)
        log=subprocess.check_output([str(binary)],cwd=temp,text=True)
        # iBoot159's C000 BBT loader consumes size at 0x34 and bitmap at
        # 0x38; a set bit means the modeled physical block is usable.
        for bank in range(args.banks):
            bbt=temp/f'nand/bank{bank}/524160.page'
            content=bytearray(bbt.read_bytes())
            if content[:13]!=b'DEVICEINFOBBT':
                raise ValueError('Expected BBT special-page signature')
            struct.pack_into('<I',content,0x34,512)
            content[0x38:0x38+512]=b'\xff'*512
            bbt.write_bytes(content)
        page=(temp/'nand/bank0/0.page').read_bytes()
        if len(page)!=2112 or struct.unpack_from('<I',page)[0]!=0x43303030:
            raise ValueError('NAND FIL version verification failed')
        actual_banks={p.name for p in (temp/'nand').iterdir() if p.is_dir()}
        if actual_banks!={f'bank{i}' for i in range(args.banks)}:
            raise ValueError('Generated NAND bank directories disagree with requested geometry')
        # The original FTL reads its context from the final interleaved page
        # of virtual block 201: bank3 for four banks, bank7 for eight banks.
        context_page=temp/f'nand/bank{args.banks-1}/25855.page'
        context=context_page.read_bytes()
        if len(context)!=2112 or context[2048+9]!=0x43 or \
                struct.unpack_from('<II',context,2040)!=(0x46560000,0xb9a9ffff):
            raise ValueError('FTL context location or version verification failed')
        shutil.move(str(temp/'nand'),output)
    report={'target':'iPhone1,1 1.0 1A543a','fil_id':'0x43303030',
        'filesystem':str(filesystem),'filesystem_sha256':digest(filesystem),
        'nand':str(output),'page_bytes':2048,'spare_bytes':64,'banks':args.banks,
        'physical_pages_per_block':128,'virtual_pages_per_block':virtual_pages_per_block,
        'physical_blocks_per_bank':4096,'physical_pages_per_bank':524288,
        'source_commit':commit,'working_source_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'compiler_geometry':compiler_geometry,
        'source_change':'FIL_ID C002 -> C000; explicit active bank geometry; zero page allocations; initialize C000 BBT size/bitmap records',
        'geometry_evidence':'Original device-tree disk reg=0x0f; ADMFMC c0423a54 masks ready banks and c0423ac4 publishes accepted bank count',
        'struct_layout':'Original fixed WMR maximum-capacity arrays retained',
        'evidence':'reports/iboot-wmr-init-debug.json: iBoot159 WMR_Init expects C000',
        'generator_output':log}
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    main()
