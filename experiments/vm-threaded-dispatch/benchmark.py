#!/usr/bin/env python3
"""VM-only host microbenchmark. Explicitly NOT SDK evaluate() performance."""
import argparse
import hashlib
import json
import math
import pathlib
import re
import subprocess

p = argparse.ArgumentParser()
p.add_argument('--validation-output', type=pathlib.Path, required=True)
p.add_argument('--samples', type=int, default=1000)
p.add_argument('--rounds', type=int, default=3)
a = p.parse_args()
if a.samples < 1000 or a.rounds < 3: p.error('Require >=1000 samples, >=3 rounds')
root = a.validation_output.resolve()
validation = json.loads((root / 'report.json').read_text())
assert validation['status'] == 'HOST_THREADED_DIFFERENTIAL_PASS'
assert validation['opt'] == '-O2', 'Only optimized benchmark supported'
commands = {}
for phase in ['legacy', 'threaded']:
    build = root / phase
    body = (build / 'harness.c').read_text()
    body = body.replace('int main(int argc, char **argv)', 'int validation_main(int argc, char **argv)')
    body = body.replace('static int wb_fail;', 'static int wb_fail;\nstatic int bench_quiet;\nstatic volatile uint64_t bench_sink;')
    body = body.replace('    printf("%u/%u/%u/%u/%u/%d ",', '''    if (bench_quiet) {
        const uint8_t *bytes = (const uint8_t *)&out;
        uint64_t h = 14695981039346656037ULL;
        for (size_t i=0;i<sizeof(out);i++) h=(h^bytes[i])*1099511628211ULL;
        bench_sink ^= h; return;
    }
    printf("%u/%u/%u/%u/%u/%d ",''')
    # Remove handler-entry observation from timing builds, keep actual engine unchanged.
    body = re.sub(r'#define CPRISK_THREAD_OBSERVE\(lane, name\) do \{.*?\} while \(0\)',
                  '#define CPRISK_THREAD_OBSERVE(lane, name) ((void)0)', body, flags=re.S)
    body = body.replace('#define THREAD_PROBE 1', '#undef THREAD_PROBE')
    body += '''
static uint64_t now_ns(void) {
    struct timespec ts; if(clock_gettime(CLOCK_MONOTONIC,&ts)) abort();
    return (uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec;
}
int main(int argc, char **argv) {
    unsigned count=(unsigned)strtoul(argv[1],NULL,10);
    bench_quiet=1; stress_steps=260;
    atomic_store(&s_vm_session_mix_i,0x13579BDF);
    for(unsigned i=0;i<32;i++) run_case(0,2,i%3,0,0);
    bench_sink=0;
    for(unsigned i=0;i<count;i++) {
        uint64_t start=now_ns(); run_case(0,2,i%3,0,0);
        uint64_t elapsed=now_ns()-start;
        printf("%llu\\n",(unsigned long long)elapsed);
    }
    fprintf(stderr,"%016llx\\n",(unsigned long long)bench_sink);
    return 0;
}
'''
    source = build / 'benchmark.c'; source.write_text(body)
    cmd = validation[phase]['command'][:]
    cmd[cmd.index(str(build / 'harness.c'))] = str(source)
    cmd[-1] = str(build / 'benchmark')
    subprocess.run(cmd, check=True)
    commands[phase] = cmd
rows = []
for repeat in range(a.rounds):
    phases = ['legacy', 'threaded'] if repeat % 2 == 0 else ['threaded', 'legacy']
    sinks = []
    for phase in phases:
        result = subprocess.run([str(root / phase / 'benchmark'), str(a.samples)], check=True, capture_output=True)
        raw = root / f'bench-{repeat}-{phase}.txt'; raw.write_bytes(result.stdout)
        timings = sorted(map(int, result.stdout.splitlines()))
        assert len(timings) == a.samples
        sinks.append(result.stderr.strip().decode())
        rows.append({'repeat': repeat, 'phase': phase, 'samples': len(timings),
                     'p50_ns': timings[math.ceil(len(timings)*.50)-1],
                     'p95_ns': timings[math.ceil(len(timings)*.95)-1],
                     'p99_ns': timings[math.ceil(len(timings)*.99)-1],
                     'result_digest': sinks[-1], 'raw_sha256': hashlib.sha256(result.stdout).hexdigest()})
    assert len(set(sinks)) == 1, 'Observed execution output changed'
report = {'scope': 'HOST_VM_ONLY_260_STEPS; setup+VM+result digest; NOT evaluate() or device P95',
          'platform': validation['platform'], 'compiler': validation['compiler'],
          'samples_per_round': a.samples, 'warmup': 32, 'rounds': a.rounds,
          'commands': commands, 'rows': rows, 'release_eligible': False}
(root / 'benchmark.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(rows,indent=2))
