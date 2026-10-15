#!/usr/bin/env python3
"""Fetch the exact target IPSW from Apple and verify before accepting it."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def main():
    metadata = json.loads((ROOT/'firmware-source.json').read_text())
    target = ROOT/'firmware'/metadata['filename']
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.stat().st_size != metadata['size'] or digest(target) != metadata['sha256']:
            raise ValueError('Existing IPSW does not match; preserve it and choose another path')
        print(f'Already verified: {target}')
        return
    temporary = target.with_suffix('.ipsw.download')
    try:
        with urllib.request.urlopen(metadata['url'], timeout=30) as response, temporary.open('xb') as output:
            if urllib.parse.urlparse(response.geturl()).hostname != 'secure-appldnld.apple.com':
                raise ValueError('Unexpected download host')
            while block := response.read(1024*1024):
                output.write(block)
        if temporary.stat().st_size != metadata['size'] or digest(temporary) != metadata['sha256']:
            raise ValueError('Downloaded IPSW does not match size and SHA-256')
        temporary.rename(target)
    except Exception:
        # Failed or partial downloads remain available for inspection.
        raise
    print(f'Downloaded and verified: {target}')

if __name__ == '__main__':
    main()
