#!/usr/bin/env python3
"""Differential + bounded-stack validation for the candidate threaded engine."""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import resource
import subprocess
from generate import generate, NAMES

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
CORE = ROOT / 'RiskDetectorApp/Sources/CRiskCore'
BASE = '8e8d40350271f531e5881c445b383d44757131d9'
REL = 'RiskDetectorApp/Sources/CRiskCore/cprisk_vm_interpreter.c'


def run(cc, output, opt='-O2'):
    output.mkdir(parents=True, exist_ok=True)
    source = (ROOT / REL).read_text()
    baseline = subprocess.check_output(['git', 'show', f'{BASE}:{REL}'], cwd=ROOT).decode()
    if source != baseline:
        raise RuntimeError('Interpreter drift: review/rebase generator and frozen comparison before running')
    refs = sorted(set(re.findall(r'\(const void \*\)&(\w+)', source)))
    addresses = {n: 0x100000 + i * 0x100 for i, n in enumerate(refs)}
    source = re.sub(r'\(const void \*\)&(\w+)', lambda m: f'(const void *)(uintptr_t)0x{addresses[m[1]]:x}u', source)
    harness = (HERE.parent / 'vm-post-handler-2a/harness.c').read_text()
    # A standalone stress mode uses the same real BRANCH_REL semantics as the corpus.
    harness = harness.replace('int main(void){', 'int corpus_main(void){')
    harness = harness.replace('f.step_limit_cap=260;', 'f.step_limit_cap=stress_steps;')
    harness = harness.replace('static int wb_fail;', 'static unsigned stress_steps = 260;\nstatic int wb_fail;')
    harness += '''
int main(int argc, char **argv) {
    atomic_store(&s_vm_session_mix_i,0x13579BDF);
    int rc = 0;
    if (argc > 1) {
        stress_steps = 200000;
        for (unsigned lane = 0; lane < 3; lane++) run_case(0, 2, lane, 0, 0);
    } else rc = corpus_main();
#ifdef THREAD_PROBE
    fprintf(stderr,"{\\"stack_span\\":%llu,\\"hits\\":[",(unsigned long long)(probe_high-probe_low));
    for (unsigned l=0;l<2;l++) for(unsigned n=0;n<26;n++)
        fprintf(stderr,"%s%llu",l||n?",":"",(unsigned long long)probe_hits[l][n]);
    fprintf(stderr,"]}\\n");
#endif
    return rc;
}
'''
    report = {'base': BASE, 'compiler': subprocess.check_output([cc, '--version']).decode(),
              'opt': opt, 'platform': platform.platform(), 'address_map': addresses,
              'scope': 'host semantic comparison; platform substitutes; no SDK production routing or CPSV change',
              'release_eligible': False}
    # On Darwin intentionally use the same non-Apple shim, not an Apple runtime claim.
    flags = [opt, '-U__APPLE__', '-ffunction-sections', '-fdata-sections', '-I', str(CORE),
             '-include', str(HERE.parent / 'vm-post-handler-2a/host_shim.h')]
    if platform.system() == 'Darwin':
        flags += ['-isysroot', subprocess.check_output(['xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()]
    link = ['-Wl,-dead_strip'] if platform.system() == 'Darwin' else ['-Wl,--gc-sections']
    modules = sorted(CORE.glob('cprisk_vm_oph_*.c')) + [CORE / 'cprisk_vm_hardening.c', CORE / 'vm_cff_fusion.c', CORE / 'cprisk_vm_sync_barrier.c']
    for phase in ['legacy', 'threaded']:
        build = output / phase
        build.mkdir(exist_ok=True)
        (build / 'interpreter-under-test.c').write_text(source)
        body = harness
        if phase == 'threaded':
            (build / 'threaded.inc').write_text(generate(source))
            probe = ['#define THREAD_PROBE 1', 'static unsigned long long probe_hits[2][26];',
                     'static uintptr_t probe_low = UINTPTR_MAX, probe_high;',
                     '#define LANE_a 0', '#define LANE_b 1']
            probe += [f'#define OP_{n} {i}' for i, n in enumerate(NAMES)]
            probe += ['''#define CPRISK_THREAD_OBSERVE(lane, name) do { \\
    volatile char mark; uintptr_t p = (uintptr_t)&mark; \\
    if(p<probe_low) probe_low=p; if(p>probe_high) probe_high=p; \\
    probe_hits[LANE_##lane][OP_##name]++; \\
} while (0)''', '#include "threaded.inc"']
            body = body.replace('#include "interpreter-under-test.c"', '#include "interpreter-under-test.c"\n' + '\n'.join(probe))
            body = body.replace('if(lane==0)cprisk_vm_interp_loop_a(&f);else cprisk_vm_interp_loop_b(&f);',
                                'if(lane==0)cprisk_thread_run_a_i(&f);else cprisk_thread_run_b_i(&f);')
        (build / 'harness.c').write_text(body)
        binary = build / 'regression'
        cmd = [cc, *flags, '-I', str(build), str(build / 'harness.c'), *map(str, modules), *link, '-o', str(binary)]
        subprocess.run(cmd, check=True)
        row = {'command': cmd, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
        for mode in ['corpus', 'stress']:
            def limit_stack():
                soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
                resource.setrlimit(resource.RLIMIT_STACK, (min(1024*1024, hard) if hard >= 0 else 1024*1024, hard))
            result = subprocess.run([str(binary), *(['stress'] if mode == 'stress' else [])],
                                    capture_output=True, check=True, timeout=180,
                                    preexec_fn=limit_stack if mode == 'stress' else None)
            (build / f'{mode}.txt').write_bytes(result.stdout)
            rows = result.stdout.splitlines()
            assert len(rows) == (6528 if mode == 'corpus' else 3)
            row[mode] = {'cases': len(rows), 'sha256': hashlib.sha256(result.stdout).hexdigest()}
            if mode == 'stress':
                for line in rows:
                    data = bytes.fromhex(line.split()[1].decode())
                    assert int.from_bytes(data[:4], 'little') == 4
                    assert int.from_bytes(data[48:56], 'little') == 200000
            if phase == 'threaded':
                metrics = json.loads(result.stderr)
                row[mode]['probe'] = metrics
                if mode == 'corpus': assert len(metrics['hits']) == 52 and min(metrics['hits']) > 0
                else: assert metrics['stack_span'] < 65536
        # Reuse independently encoded NOP/HALT wire tests through this engine too.
        zero = (HERE.parent / 'vm-opcode-zero-fault/regression.c').read_text()
        zero = zero.replace('"../vm-post-handler-2a/harness.c"',
                            '"' + str(HERE.parent / 'vm-post-handler-2a/harness.c') + '"')
        if phase == 'threaded':
            zero = zero.replace('#undef main', '#undef main\n#include "threaded.inc"')
            zero = zero.replace('if(lane==0)cprisk_vm_interp_loop_a(&f);else cprisk_vm_interp_loop_b(&f);',
                                'if(lane==0)cprisk_thread_run_a_i(&f);else cprisk_thread_run_b_i(&f);')
        zero_source = build / 'zero.c'; zero_source.write_text(zero)
        zero_cmd = cmd[:]
        zero_cmd[zero_cmd.index(str(build / 'harness.c'))] = str(zero_source)
        zero_cmd[-1] = str(build / 'zero-regression')
        subprocess.run(zero_cmd, check=True)
        zero_result = json.loads(subprocess.check_output([str(build / 'zero-regression')], cwd=build))
        assert zero_result['zero_errors'] == zero_result['loop_errors'] == 0
        row['encrypted_wire'] = zero_result
        report[phase] = row
    for mode in ['corpus', 'stress']:
        assert (output / f'legacy/{mode}.txt').read_bytes() == (output / f'threaded/{mode}.txt').read_bytes(), mode + ' mismatch'
    assert (output / 'legacy/nonzero.bin').read_bytes() == (output / 'threaded/nonzero.bin').read_bytes()
    report['status'] = 'HOST_THREADED_DIFFERENTIAL_PASS'
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k in ['status', 'opt', 'release_eligible']}, indent=2))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--cc', default='clang')
    p.add_argument('--output', type=pathlib.Path, required=True)
    p.add_argument('--opt', choices=['O0', 'O2', 'Os'], default='O2')
    a = p.parse_args()
    run(a.cc, a.output.resolve(), '-' + a.opt)
