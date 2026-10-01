#!/usr/bin/env python3
"""Execute the cumulative GEP patch in a real host VM, with independent offsets."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run import (check_provenance, check_versions, function_body, inspect_ir,
                 inspect_pass_reports, sha256)

# Explicit LLVM input preserves the precise GEP forms under examination. The C
# harness separately checks the ABI layout and computes addresses in real arrays.
SPECS = (
    ('pad0', '', '%Pad, ptr %p, i64 0, i32 0'),
    ('pad1', '', '%Pad, ptr %p, i64 0, i32 1'),
    ('pad2', '', '%Pad, ptr %p, i64 0, i32 2'),
    ('packed1', '', '%Packed, ptr %p, i64 0, i32 1'),
    ('packed2', '', '%Packed, ptr %p, i64 0, i32 2'),
    ('nested', '', '%Nested, ptr %p, i64 0, i32 1, i64 2, i32 1'),
    ('pad_i32', ', i32 %i', '%Pad, ptr %p, i32 %i'),
    ('pad_i64', ', i64 %i', '%Pad, ptr %p, i64 %i'),
    ('packed_i32', ', i32 %i', '%Packed, ptr %p, i32 %i'),
    ('packed_i64', ', i64 %i', '%Packed, ptr %p, i64 %i'),
    ('array_i32', ', i32 %i', '[17 x i64], ptr %p, i64 0, i32 %i'),
    ('array_i64', ', i64 %i', '[17 x i64], ptr %p, i64 0, i64 %i'),
)
REJECT_SPEC = (('large_stride', ', i64 %i', '[65536 x i8], ptr %p, i64 %i'),)
TYPES = '%Pad = type { i8, i64, i16 }\n%Packed = type <{ i8, i64, i16 }>\n%Nested = type { i16, [3 x %Pad], i8 }\n'
HARNESS = r'''#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
struct Pad { uint8_t a; uint64_t b; uint16_t c; };
struct __attribute__((packed)) Packed { uint8_t a; uint64_t b; uint16_t c; };
struct Nested { uint16_t head; struct Pad items[3]; uint8_t tail; };
_Static_assert(sizeof(struct Pad)==24 && offsetof(struct Pad,b)==8 && offsetof(struct Pad,c)==16,"padded ABI");
_Static_assert(sizeof(struct Packed)==11 && offsetof(struct Packed,b)==1 && offsetof(struct Packed,c)==9,"packed ABI");
_Static_assert(sizeof(struct Nested)==88 && offsetof(struct Nested,items)==8,"nested ABI");
#define DECL(n) void *plain_##n(void*); void *protected_##n(void*);
DECL(pad0) DECL(pad1) DECL(pad2) DECL(packed1) DECL(packed2) DECL(nested)
#define DECLIDX(n,t) void *plain_##n(void*,t); void *protected_##n(void*,t);
DECLIDX(pad_i32,int32_t) DECLIDX(pad_i64,int64_t)
DECLIDX(packed_i32,int32_t) DECLIDX(packed_i64,int64_t)
DECLIDX(array_i32,int32_t) DECLIDX(array_i64,int64_t)
#define CHECK(n,expected,...) do { void *a=plain_##n(__VA_ARGS__); void *b=protected_##n(__VA_ARGS__); void *e=(void*)(expected); if(a!=b || b!=e){fprintf(stderr,"FAIL %s case=%u native=%p vm=%p expected=%p\n",#n,cases,a,b,e);return 1;}++cases;}while(0)
int main(void) {
 struct Pad pads[17]; struct Packed packed[17]; struct Nested nested[17]; uint64_t words[17];
 unsigned cases=0;
 for(unsigned j=0;j<17;++j) {
  CHECK(pad0,(unsigned char*)&pads[j]+0,&pads[j]);
  CHECK(pad1,(unsigned char*)&pads[j]+8,&pads[j]);
  CHECK(pad2,(unsigned char*)&pads[j]+16,&pads[j]);
  CHECK(packed1,(unsigned char*)&packed[j]+1,&packed[j]);
  CHECK(packed2,(unsigned char*)&packed[j]+9,&packed[j]);
  CHECK(nested,(unsigned char*)&nested[j]+64,&nested[j]);
 }
 /* Every negative index stays within the owning 17-element allocation. The
    array [0,index] IR deliberately has no inbounds promise on its source type. */
 for(int i=-8;i<=8;++i) {
  CHECK(pad_i32,&pads[8+i],&pads[8],(int32_t)i);
  CHECK(pad_i64,&pads[8+i],&pads[8],(int64_t)i);
  CHECK(packed_i32,&packed[8+i],&packed[8],(int32_t)i);
  CHECK(packed_i64,&packed[8+i],&packed[8],(int64_t)i);
  CHECK(array_i32,&words[8+i],&words[8],(int32_t)i);
  CHECK(array_i64,&words[8+i],&words[8],(int64_t)i);
 }
 printf("PASS cases=%u gep_constant_dynamic_known_offsets\n",cases);return 0;
}
'''


def module_ir(header, prefix, rand, specs=SPECS, annotate=True):
    text = header + '\n' + TYPES
    if annotate:
        annotation = f'obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0,randISA={rand})'
        text += f'@.ann = private constant [{len(annotation)+1} x i8] c"{annotation}\\00"\n'
        text += '@.file = private constant [6 x i8] c"probe\\00"\n'
        records = [f'{{ ptr, ptr, ptr, i32, ptr }} {{ ptr @{prefix}{name}, ptr @.ann, ptr @.file, i32 1, ptr null }}'
                   for name, _, _ in specs]
        text += f'@llvm.global.annotations = appending global [{len(records)} x {{ ptr, ptr, ptr, i32, ptr }}] [' + ', '.join(records) + '], section "llvm.metadata"\n'
    for name, args, gep in specs:
        text += f'define ptr @{prefix}{name}(ptr %p{args}) noinline {{\nentry:\n  %q = getelementptr {gep}\n  ret ptr %q\n}}\n'
    return text


def inspect_rejection(before, after, directory):
    name = 'protected_large_stride'
    if function_body(before, name) != function_body(after, name):
        raise RuntimeError('Oversized dynamic stride was rewritten rather than rejected')
    if '@' + name + '.vm.bytecode' in after or '@__vm_engine' in after:
        raise RuntimeError('Oversized dynamic stride produced VM execution artifacts')
    records = []
    for path in directory.rglob('*.json'):
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            records.extend(r for r in data.get('functions', []) if r.get('name') == name)
    if len(records) != 1:
        raise RuntimeError('Missing or duplicate oversized-stride report')
    passes = [p for p in records[0].get('passes', []) if p.get('id') == 'vm']
    if (len(passes) != 1 or passes[0].get('status') != 'skipped'
            or passes[0].get('delta_insts') != 0):
        raise RuntimeError('Oversized-stride report did not confirm unchanged target')
    detail = json.dumps(passes[0])
    if 'getelementptr' not in detail or 'unsupported' not in detail.lower():
        raise RuntimeError('Oversized-stride report lacks explicit unsupported GEP reason')
    return {'target': name, 'stride': 65536, 'unchanged': True,
            'vm_artifacts_absent': True, 'pass_report': records[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm-root', type=Path, required=True)
    parser.add_argument('--plugin', type=Path, required=True)
    parser.add_argument('--plugin-provenance', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {'schema_version': 1, 'status': 'RUNNING', 'vmp_verified': False,
              'scope': 'macOS arm64 host GEP only; no device, hardening, memory-load or stack correctness conclusion',
              'probe_sha256': sha256(__file__), 'harness': HARNESS,
              'gep_specs': SPECS, 'known_offsets': {'pad': [0, 8, 16], 'packed': [0, 1, 9],
              'nested': 64}, 'dynamic_strides': {'pad': 24, 'packed': 11, 'array': 8},
              'commands': [], 'configurations': []}

    def run(argv):
        argv = [str(a) for a in argv]
        p = subprocess.run(argv, text=True, capture_output=True, timeout=120)
        report['commands'].append({'argv': argv, 'returncode': p.returncode,
                                   'stdout': p.stdout, 'stderr': p.stderr})
        if p.returncode:
            raise RuntimeError('Command failed: ' + ' '.join(argv))
        return p.stdout

    try:
        clang, opt = args.llvm_root/'bin/clang', args.llvm_root/'bin/opt'
        version = check_versions(run([clang, '--version']), run([opt, '--version']))
        provenance = check_provenance(args.plugin_provenance, args.plugin, version)
        if provenance.get('local_patch_set', {}).get('id') != 'pointer-gep-v2':
            raise RuntimeError('Cumulative pointer-gep-v2 provenance required')
        report['plugin_provenance'] = provenance
        layout_dir = Path(tempfile.mkdtemp(prefix='layout-', dir=output))
        (layout_dir/'layout.c').write_text('int layout_anchor;\n')
        run([clang, '-S', '-emit-llvm', layout_dir/'layout.c', '-o', layout_dir/'layout.ll'])
        header = '\n'.join(line for line in (layout_dir/'layout.ll').read_text().splitlines()
                           if line.startswith(('target datalayout', 'target triple')))
        if 'arm64-apple-' not in header and 'aarch64-apple-' not in header:
            raise RuntimeError('Probe result is scoped to macOS arm64')
        report['target_header'] = header
        targets = tuple('protected_'+s[0] for s in SPECS)
        for rand in (0, 1):
            build = Path(tempfile.mkdtemp(prefix=f'randisa-{rand}-', dir=output))
            before, after, optimized = (build/n for n in ('before.ll', 'after.ll', 'optimized.ll'))
            plain, harness = build/'plain.ll', build/'differential.c'
            plain.write_text(module_ir(header, 'plain_', rand, annotate=False))
            before.write_text(module_ir(header, 'protected_', rand))
            harness.write_text(HARNESS)
            reports = build/'pass-reports'
            reports.mkdir()
            run([opt, '-passes=verify', '-disable-output', before])
            run([clang, '-O2', '-c', plain, '-o', build/'plain.o'])
            def transform(source, dest, report_dir):
                run([opt, '-load-pass-plugin='+str(args.plugin), '-passes=obfuscation',
                     '-obf-seed=1', '-obf-deterministic', '-obf-verify', '-obf-verbose',
                     '-obf-report-dir='+str(report_dir), '-S', source, '-o', dest])
                run([opt, '-passes=verify', '-disable-output', dest])
            transform(before, after, reports)
            entry = {'randISA': rand, 'build_directory': str(build),
                     'pass_evidence': inspect_pass_reports(reports, targets),
                     'ir_evidence': inspect_ir(before.read_text(), after.read_text(), targets)}
            run([opt, '-passes=default<O2>', '-S', after, '-o', optimized])
            run([opt, '-passes=verify', '-disable-output', optimized])
            entry['optimized_ir_evidence'] = inspect_ir(before.read_text(), optimized.read_text(), targets, require_entry=False)
            run([clang, '-O0', '-c', optimized, '-o', build/'protected.o'])
            run([clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', harness,
                 build/'plain.o', build/'protected.o', '-o', build/'differential'])
            entry['output'] = run([build/'differential'])
            if entry['output'].strip() != 'PASS cases=204 gep_constant_dynamic_known_offsets':
                raise RuntimeError('Missing expected GEP case count')
            reject_before, reject_after = build/'reject-before.ll', build/'reject-after.ll'
            reject_before.write_text(module_ir(header, 'protected_', rand, REJECT_SPEC))
            reject_reports = build/'reject-reports'
            reject_reports.mkdir()
            transform(reject_before, reject_after, reject_reports)
            entry['oversized_dynamic_stride'] = inspect_rejection(reject_before.read_text(), reject_after.read_text(), reject_reports)
            entry['hashes'] = {str(p): sha256(p) for p in (plain, harness, before, after,
                               optimized, reject_before, reject_after, build/'differential')}
            report['configurations'].append(entry)
        report.update(status='HOST_GEP_VMP_PASS', vmp_verified=True)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report.update(status='BLOCKED_OR_FAILED', error=str(exc))
    (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status': report['status'], 'report': str(output/'report.json')}))
    return 0 if report['vmp_verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
