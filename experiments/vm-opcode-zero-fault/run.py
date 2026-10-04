#!/usr/bin/env python3
"""Compare the real interpreter against the pre-fix stage 2A commit."""
import argparse
import hashlib
import json
import pathlib
import platform
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--cc', '--clang', dest='cc', default='cc')
parser.add_argument('--output', required=True)
parser.add_argument('--expect-bug', action='store_true')
args = parser.parse_args()
here = pathlib.Path(__file__).resolve().parent
root = here.parents[1]
core = root / 'RiskDetectorApp/Sources/CRiskCore'
out = pathlib.Path(args.output).resolve()
out.mkdir(parents=True, exist_ok=True)
relative_source = 'RiskDetectorApp/Sources/CRiskCore/cprisk_vm_interpreter.c'
base = 'd07b76404e19cd3dffd790fae55158c329d164c0'
modules = sorted(core.glob('cprisk_vm_oph_*.c')) + [
    core / 'cprisk_vm_hardening.c', core / 'vm_cff_fusion.c',
    core / 'cprisk_vm_sync_barrier.c',
]
report = {
    'base': base,
    'compiler': subprocess.check_output([args.cc, '--version']).decode(),
    'scope': ('Host non-Apple code path forced, deterministic platform substitutes from 2A; actual '
              'interpreter helpers and A/B loops; not Apple device validation'),
}
platform_flags = (['-isysroot', subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()]
                  if platform.system() == 'Darwin' else [])
for phase in ['before', 'after']:
    build = out / phase
    build.mkdir(exist_ok=True)
    source = (subprocess.check_output(['git', 'show', base + ':' + relative_source], cwd=root)
              if phase == 'before' else (root / relative_source).read_bytes())
    (build / 'interpreter-under-test.c').write_bytes(source)
    binary = build / 'regression'
    subprocess.run([
        args.cc, *platform_flags, '-U__APPLE__', '-O2', '-ffunction-sections', '-fdata-sections',
        '-I', str(core), '-I', str(build), '-include',
        str(here.parent / 'vm-post-handler-2a/host_shim.h'),
        str(here / 'regression.c'), *map(str, modules),
        ('-Wl,-dead_strip' if platform.system() == 'Darwin' else '-Wl,--gc-sections'), '-o', str(binary),
    ], check=True)
    result = json.loads(subprocess.check_output([str(binary)], cwd=build))
    result['source_sha256'] = hashlib.sha256(source).hexdigest()
    report[phase] = result

assert report['before']['zero_errors'] > 0 and report['before']['loop_errors'] > 0
before_bytes = (out / 'before/nonzero.bin').read_bytes()
after_bytes = (out / 'after/nonzero.bin').read_bytes()
assert len(before_bytes) == len(after_bytes) == 25600
assert before_bytes == after_bytes, 'Nonzero fault behavior changed'
report['nonzero_byte_comparison'] = '25600/25600 identical'
if args.expect_bug:
    assert report['after']['zero_errors'] > 0 and report['after']['loop_errors'] > 0
    report['status'] = 'BUG_REPRODUCED'
else:
    assert report['after']['zero_errors'] == 0 and report['after']['loop_errors'] == 0
    report['status'] = 'PASS'
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
