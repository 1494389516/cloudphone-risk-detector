#!/usr/bin/env python3
"""Build an isolated revision with Xcode and measure the final linked post-hook.

Link-map symbol lengths are authoritative linker output, not next-symbol guesses.
This validates stock Release only; does not claim post-armor/CPSV or device timing.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
SYMBOL = '_cprisk_vm_oph_post_handler_i'


def text_bytes(image, address, length):
    data = image.read_bytes()
    magic, cpu, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', data)
    assert magic == 0xfeedfacf and cpu == 0x100000c, 'Expected thin arm64 Mach-O'
    pos = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, pos)
        assert size >= 8 and pos + size <= len(data)
        if cmd == 0x19:
            segname, vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<16sQQQQ', data, pos + 8)
            if segname.rstrip(b'\0') == b'__TEXT' and vmaddr <= address and address + length <= vmaddr + filesize:
                offset = fileoff + address - vmaddr
                assert offset + length <= len(data)
                return offset, data[offset:offset + length]
        pos += size
    raise RuntimeError('Function range does not fit file-backed __TEXT')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--ref', required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    p.add_argument('--repeats', type=int, default=3)
    a = p.parse_args()
    if a.repeats < 3: p.error('At least three clean builds required')
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    work = out / 'worktree'
    if work.exists(): raise RuntimeError('Use a fresh output directory')
    report = {'revision': subprocess.check_output(['git', 'rev-parse', a.ref], cwd=ROOT).decode().strip(),
              'xcode': subprocess.check_output(['xcodebuild', '-version']).decode(),
              'compiler': subprocess.check_output(['xcrun', 'clang', '--version']).decode(),
              'sdk': subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-version']).decode().strip(),
              'scope': 'stock Xcode iPhoneOS Release, no post-armor/self-expect injection or device execution',
              'rows': [], 'status': 'IN_PROGRESS'}
    subprocess.run(['git', 'worktree', 'add', '--detach', str(work), a.ref], cwd=ROOT, check=True)
    try:
        for repeat in range(a.repeats):
            derived = out / f'DerivedData-{repeat}'
            cmd = ['xcodebuild', '-project', str(work / 'RiskDetectorApp/RiskDetectorApp.xcodeproj'),
                   '-scheme', 'RiskDetectorApp', '-configuration', 'Release', '-sdk', 'iphoneos',
                   '-destination', 'generic/platform=iOS', '-derivedDataPath', str(derived),
                   'ARCHS=arm64', 'CODE_SIGNING_ALLOWED=NO', 'LD_GENERATE_MAP_FILE=YES', 'build']
            with (out / f'build-{repeat}.log').open('wb') as log:
                subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
            matches = []
            for map_path in derived.rglob('*LinkMap*'):
                if not map_path.is_file(): continue
                map_text = map_path.read_text(errors='replace')
                live = map_text.split('# Dead Stripped Symbols:')[0]
                found = re.findall(r'^\s*(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+\[\s*\d+\]\s+' + re.escape(SYMBOL) + r'\s*$', live, re.M)
                if not found: continue
                image_path = re.search(r'^# Path: (.+)$', map_text, re.M)
                assert image_path and len(found) == 1, 'Ambiguous linker map'
                image = pathlib.Path(image_path[1])
                addr, length = map(lambda s: int(s, 16), found[0])
                assert length > 0 and addr % 4 == 0 and length % 4 == 0
                offset, code = text_bytes(image, addr, length)
                index = len(matches)
                shutil.copyfile(map_path, out / f'linkmap-{repeat}-{index}.txt')
                dis = subprocess.check_output(['xcrun', 'llvm-objdump', '-d', str(image)]).decode()
                (out / f'disassembly-{repeat}-{index}.txt').write_text(dis)
                refs = [line.strip() for line in dis.splitlines() if re.search(r'\b(?:bl|b)\s+0x0*' + f'{addr:x}' + r'\b', line)]
                assert refs, 'No direct call/tail-branch to independent post-handler in final image'
                matches.append({'image': str(image.relative_to(derived)), 'address': hex(addr),
                                'length': length, 'file_offset': offset,
                                'code_sha256': hashlib.sha256(code).hexdigest(),
                                'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                                'references': refs})
            assert matches, 'Post-handler absent/dead-stripped: cannot accept final linked evidence'
            report['rows'].append({'repeat': repeat, 'command': cmd, 'images': matches})
            (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            shutil.rmtree(derived)
        signatures = [{(m['image'], m['address'], m['length']) for m in row['images']} for row in report['rows']]
        assert all(s == signatures[0] for s in signatures), 'Address/length differs between clean builds'
        report['status'] = 'APPLE_STOCK_RELEASE_POST_HANDLER_PASS'
    except Exception as e:
        report['status'] = 'FAILED_OR_BLOCKED'
        report['error'] = str(e)
        raise
    finally:
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        # Keep failed build output for diagnosis; remove only the owned clean worktree.
        subprocess.run(['git', 'worktree', 'remove', str(work)], cwd=ROOT, check=True)
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
