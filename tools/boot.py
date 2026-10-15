#!/usr/bin/env python3
"""Run genuine firmware on the experimental S5L8900 board and collect evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(os.environ.get('IPHONEOS1_RUNTIME', str(Path.home() / 'iphoneos1-lab-runtime')))

class QMP:
    def __init__(self, path: Path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.stream = self.sock.makefile('rwb')
        self.read()
        self.call('qmp_capabilities')

    def read(self):
        line = self.stream.readline()
        if not line:
            raise EOFError('QEMU closed QMP')
        return json.loads(line)

    def call(self, command, arguments=None):
        msg = {'execute': command}
        if arguments is not None:
            msg['arguments'] = arguments
        self.stream.write(json.dumps(msg).encode() + b'\n')
        self.stream.flush()
        while True:
            result = self.read()
            if 'return' in result or 'error' in result:
                return result

    def close(self):
        self.stream.close()
        self.sock.close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', action='store_true', help='N45 iPod firmware; distinct control experiment')
    parser.add_argument('--stock-rootfs', action='store_true', help='Original unmodified rootfs; separate diagnostic NAND')
    parser.add_argument('--nand', type=Path, help='Select a separate synthetic NAND layout for diagnostics')
    parser.add_argument('--direct-kernel', action='store_true', help='Diagnostic entry into the genuine system kernel, bypassing iBoot')
    parser.add_argument('--gui', action='store_true', help='Open the actual framebuffer in SDL')
    parser.add_argument('--seconds', type=float, default=45, help='Bounded evidence capture; 0 runs until interrupted')
    parser.add_argument('--cpu', help='Default: original ARM1176 for M68, upstream max for N45 control')
    parser.add_argument('--trace', action='store_true', help='Capture translated ARM instructions and guest errors')
    parser.add_argument('--gdb', type=int, help='Expose the local GDB remote stub on this port')
    parser.add_argument('--paused', action='store_true', help='Start paused for debugging')
    clock_mode = parser.add_mutually_exclusive_group()
    clock_mode.add_argument('--icount', type=int, help='Virtual instruction clock shift; M68 default is 2')
    clock_mode.add_argument('--no-icount', action='store_true', help='Experimental wall clock scheduling')
    parser.add_argument('--snapshot-interval', type=float, default=0, help='Periodically capture the genuine framebuffer')
    parser.add_argument('--home-at', type=float, help='Press the emulated Home button at this elapsed second')
    parser.add_argument('--tag', default=None)
    parser.add_argument('--qemu', type=Path, default=Path.home() / 'iphoneos1-qemu-build/qemu-system-arm')
    args = parser.parse_args()
    if args.seconds < 0 or args.snapshot_interval < 0:
        parser.error('Capture duration and snapshot interval must be nonnegative')
    if args.home_at is not None and args.home_at < 0:
        parser.error('Home-key time must be nonnegative')
    if args.cpu is None:
        args.cpu = 'max' if args.reference else 'arm1176'
    if args.icount is None and not args.reference and not args.no_icount:
        args.icount = 2
    if args.direct_kernel and args.reference:
        parser.error('Direct-kernel inputs target 1A543a only')
    firmware = RUNTIME / ('reference-n45' if args.reference else '1A543a')
    iboot = firmware / ('iboot_204_n45ap.bin' if args.reference else 'iboot.bin')
    bootrom = ROOT / 'firmware/bootrom_s5l8900'
    nor = firmware / 'nor.bin'
    nand_name = 'nand' if args.reference else (
        'nand-stock-m68-4bank' if args.stock_rootfs else 'nand-m68-4bank')
    nand = firmware/nand_name
    if args.nand:
        nand = args.nand.resolve()
    for path in [args.qemu, iboot, bootrom, nor, nand]:
        if not path.exists():
            parser.error(f'Required file is missing: {path}')
    tag = args.tag or ('n45-reference' if args.reference else 'm68-1A543a')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', tag):
        parser.error('Tag must contain 1-64 letters, digits, underscores or hyphens')
    report = ROOT / 'reports' / tag
    report.mkdir(parents=True, exist_ok=True)
    # Keep high-volume live output outside the Documents checkout. Publish
    # completed logs after QEMU exits so host filesystem delays do not alter
    # guest driver scheduling during reverse-engineering experiments.
    live = RUNTIME/'evidence'/tag
    live.mkdir(parents=True, exist_ok=True)
    overlay = live/'nand-overlay'
    if overlay.exists():
        parser.error(f'Use a new tag; writable NAND overlay already exists: {overlay}')
    for bank in range(8):
        (overlay/f'bank{bank}').mkdir(parents=True)
    (report/'live-path.txt').write_text(str(live)+'\n')
    # Unix sockets have a small pathname limit; runtime path contains no spaces.
    qmp_path = RUNTIME / f'{tag}.qmp'
    if qmp_path.exists():
        parser.error(f'QMP socket already exists; another run may be active: {qmp_path}')
    nor_run = RUNTIME / f'{tag}-nor.bin'
    shutil.copyfile(nor, nor_run)
    machine = f'iPod-Touch,bootrom={bootrom},iboot={iboot},nand={nand},nand-overlay={overlay}'
    if not args.reference:
        machine += ',iphone-2g=true'
    command = [str(args.qemu), '-M', machine, '-cpu', args.cpu, '-m', '128M',
        '-drive', f'if=pflash,format=raw,file={nor_run}',
        '-serial', f'file:{live / "serial.log"}', '-monitor', 'none',
        '-qmp', f'unix:{qmp_path},server=on,wait=off',
        '-display', 'sdl' if args.gui else 'none']
    for uart in range(1, 5):
        command += ['-serial', f'file:{live / ("serial-uart"+str(uart)+".log")}']
    if args.trace:
        command += ['-d', 'in_asm,guest_errors,unimp', '-D', str(live / 'trace.log')]
    if args.gdb:
        command += ['-gdb', f'tcp:127.0.0.1:{args.gdb}']
    if args.paused:
        command += ['-S']
    if args.icount is not None:
        command += ['-icount', f'shift={args.icount},sleep=off']
    if args.direct_kernel:
        loader_path = firmware/'direct-kernel/loader-argv.json'
        command += json.loads(loader_path.read_text())
    (report / 'command.json').write_text(json.dumps(command, indent=2)+'\n')
    outcome = {'target': 'iPod1,1 3A101a reference' if args.reference else 'iPhone1,1 1.0 1A543a',
        'cpu': args.cpu, 'gui_requested': args.gui, 'full_boot_verified': False,
        'stock_rootfs': args.stock_rootfs, 'nand': str(nand),
        'nand_overlay': str(overlay),
        'boot_entry': 'direct system kernel diagnostic' if args.direct_kernel else 'iBoot',
        'live_evidence': str(live),
        'qemu_sha256': hashlib.sha256(args.qemu.read_bytes()).hexdigest(),
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    qmp = None
    started = time.monotonic()
    captures = []
    with (live / 'host.log').open('wb') as log:
        proc = subprocess.Popen(command, stdout=log, stderr=log)
        outcome['pid'] = proc.pid
        try:
            deadline = time.monotonic()+45
            while not qmp_path.exists():
                if proc.poll() is not None:
                    raise RuntimeError(f'QEMU exited during startup: {proc.returncode}')
                if time.monotonic() > deadline:
                    raise TimeoutError('QMP startup timeout')
                time.sleep(.1)
            qmp = QMP(qmp_path)
            print(f'Running {outcome["target"]}; evidence: {report}', flush=True)
            next_snapshot = args.snapshot_interval if args.snapshot_interval > 0 else None
            home_sent = False
            while proc.poll() is None:
                elapsed = time.monotonic()-started
                if args.home_at is not None and not home_sent and elapsed >= args.home_at:
                    outcome['home_button'] = qmp.call('send-key', {'keys': [{'type': 'qcode', 'data': 'h'}], 'hold-time': 150})
                    home_sent = True
                if next_snapshot is not None and elapsed >= next_snapshot:
                    name = f'screen-{int(elapsed):04d}.ppm'
                    captures.append({'seconds': round(elapsed, 2), 'file': name,
                        'result': qmp.call('screendump', {'filename': str(live/name)})})
                    next_snapshot += args.snapshot_interval
                if args.seconds and elapsed >= args.seconds:
                    break
                time.sleep(.2)
            if proc.poll() is None:
                outcome['status'] = qmp.call('query-status')
                outcome['registers'] = qmp.call('human-monitor-command', {'command-line': 'info registers'})
                outcome['screenshot'] = qmp.call('screendump', {'filename': str(live / 'screen.ppm')})
                qmp.call('quit')
        except KeyboardInterrupt:
            outcome['interrupted'] = True
        except Exception as error:
            outcome['capture_error'] = str(error)
        finally:
            outcome['captures'] = captures
            if qmp:
                qmp.close()
            if proc.poll() is None:
                proc.terminate()
            try:
                outcome['exit_code'] = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                outcome['exit_code'] = proc.wait()
            outcome['elapsed_seconds'] = round(time.monotonic()-started, 2)
            for artifact in live.iterdir():
                if artifact.is_file():
                    shutil.copyfile(artifact, report/artifact.name)
            (report/'outcome.json').write_text(json.dumps(outcome, indent=2)+'\n')
            qmp_path.unlink(missing_ok=True)
    protocol_errors = []
    for name in ('home_button', 'status', 'registers', 'screenshot'):
        response = outcome.get(name, {})
        if 'error' in response:
            protocol_errors.append({'operation': name, 'error': response['error']})
    for capture in captures:
        if 'error' in capture['result']:
            protocol_errors.append({'operation': 'screendump', 'file': capture['file'],
                                    'error': capture['result']['error']})
    outcome['protocol_errors'] = protocol_errors
    outcome['script_exit_code'] = (130 if outcome.get('interrupted') else
        1 if outcome.get('capture_error') or protocol_errors or outcome['exit_code'] != 0 else 0)
    (report/'outcome.json').write_text(json.dumps(outcome, indent=2)+'\n')
    summary = {key: value for key, value in outcome.items() if key != 'registers'}
    summary['registers_path'] = str(report/'outcome.json')
    print(json.dumps(summary, indent=2))
    return outcome['script_exit_code']

if __name__ == '__main__':
    raise SystemExit(main())
