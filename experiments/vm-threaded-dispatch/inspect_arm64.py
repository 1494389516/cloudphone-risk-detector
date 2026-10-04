#!/usr/bin/env python3
"""Check per-handler musttail IR and independent ARM64 machine-code regions.

Object evidence only. Never calls this final linked/CPSV/device acceptance.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
from generate import generate, NAMES

p = argparse.ArgumentParser()
p.add_argument('--cc', default='clang')
p.add_argument('--objdump', default='llvm-objdump')
p.add_argument('--apple', action='store_true')
p.add_argument('--integrated', action='store_true')
p.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args()
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
here = pathlib.Path(__file__).resolve().parent; root = here.parents[1]
core = root / 'RiskDetectorApp/Sources/CRiskCore'
source = (core / 'cprisk_vm_interpreter.c').read_text()
(out / 'threaded.inc').write_text(generate(source))
(out / 'candidate.c').write_text(('#define CPRISK_VM_THREADED_DISPATCH 1\n' + source if a.integrated else source + '\n#include "threaded.inc"\n')
    + 'void cprisk_thread_test_entry(cprisk_vm_interp_frame_t *fr) {\n'
    'if(fr->path_lane==0) cprisk_thread_run_a_i(fr); else cprisk_thread_run_b_i(fr);\n}\n')
flags = ['-I', str(core)]
if a.apple:
    sdk = subprocess.check_output(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
    flags += ['--target=arm64-apple-ios14.0', '-isysroot', sdk]
else:
    flags += ['--target=aarch64-none-elf', '-ffreestanding',
              '-I', str(here.parent / 'vm-post-handler-2a/freestanding'),
              '-include', str(here.parent / 'vm-post-handler-2a/host_shim.h')]
rows = []
for opt in ['O0', 'O2', 'Os']:
    ir = out / (opt + '.ll')
    subprocess.run([a.cc, *flags, '-' + opt, '-S', '-emit-llvm', str(out / 'candidate.c'), '-o', str(ir)], check=True)
    text = ir.read_text()
    blocks = dict(re.findall(r'^define[^\n]*@([a-zA-Z0-9_]+)\([^\n]*\)[^\n]*\{\n(.*?)^}', text, re.M | re.S))
    expected = [f'cprisk_thread_{lane}_{name}_i' for lane in ['a', 'b'] for name in NAMES]
    for name in expected:
        assert name in blocks, name
        assert len(re.findall(r'\bmusttail call void\b', blocks[name])) == 1, name
        assert not re.search(r'\bcall[^\n]*@cprisk_thread_(prepare|select|run)_', blocks[name]), name
    # Prefix/selector code must be duplicated into handlers, not outlined into a shared body.
    assert not any(re.match(r'cprisk_thread_(prepare|select)_', n) for n in blocks)
    for repeat in range(3):
        obj = out / f'{opt}-{repeat}.o'
        cmd = [a.cc, *flags, '-' + opt, '-c', str(out / 'candidate.c'), '-o', str(obj)]
        subprocess.run(cmd, check=True)
        dis = subprocess.check_output([a.objdump, '-dr', str(obj)]).decode()
        (out / f'{opt}-{repeat}.asm').write_text(dis)
        # All 52 symbols must survive as distinct regions with an indirect branch.
        functions = dict(re.findall(r'^[0-9a-f]+ <_?(\w+)>:\n(.*?)(?=^[0-9a-f]+ <|\Z)', dis, re.M | re.S))
        handlers = {}
        for name in expected:
            body = functions[name]
            assert re.search(r'\bbr\s+x\d+\b', body), name
            handlers[name] = {'instruction_lines': len(re.findall(r'^\s*[0-9a-f]+:', body, re.M)),
                              'disassembly_sha256': hashlib.sha256(body.encode()).hexdigest()}
        rows.append({'opt': opt, 'repeat': repeat, 'command': cmd,
                     'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest(), 'handlers': handlers})
    group = rows[-3:]
    assert len({r['object_sha256'] for r in group}) == 1, opt + ' repeat mismatch'
report = {'status': 'THREADED_ARM64_OBJECT_PASS', 'apple_sdk': a.apple,
          'final_linked_image': False, 'cpsv_validated': False, 'integrated': a.integrated,
          'compiler': subprocess.check_output([a.cc, '--version']).decode(),
          'handler_count': 52, 'rows': rows}
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k:v for k,v in report.items() if k != 'rows'},indent=2))
