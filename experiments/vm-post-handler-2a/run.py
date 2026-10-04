#!/usr/bin/env python3
"""Host differential test; never claims Apple SDK/device validation."""
import argparse, hashlib, json, os, pathlib, platform, re, subprocess
p=argparse.ArgumentParser();p.add_argument('--clang',default='clang');p.add_argument('--output',required=True);p.add_argument('--coverage',action='store_true');p.add_argument('--candidate-ref',help='Validate a historical candidate instead of the working tree');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[2]; here=pathlib.Path(__file__).resolve().parent
out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
core=root/'RiskDetectorApp/Sources/CRiskCore';rel='RiskDetectorApp/Sources/CRiskCore/cprisk_vm_interpreter.c'
base='5d8febd30b317082200dd399ff5d0ac64f37df1a'
before=subprocess.check_output(['git','show',f'{base}:{rel}'],cwd=root).decode();after=(subprocess.check_output(['git','show',f'{a.candidate_ref}:{rel}'],cwd=root).decode() if a.candidate_ref else (root/rel).read_text())
# Production edit must be exactly the explicit boundary and its explanatory comment.
marker='/* Shared post-handler boundary.'
start=after.index(marker);end=after.index('cprisk_vm_flow_t cprisk_vm_oph_post_handler_i(',start)
assert after[:start]+after[end:]==before,'unexpected production change outside the noinline annotation'
# Address values feed opaque/session state. Normalize DATA references only;
# retain actual call targets, opcode implementations, loops and post-hook body.
refs=sorted(set(re.findall(r'\(const void \*\)&(\w+)',before)))
address_map={name:0x100000+i*0x100 for i,name in enumerate(refs)}
flags=['-U__APPLE__','-O2','-ffunction-sections','-fdata-sections','-I',str(core),'-include',str(here/'host_shim.h')]
if a.coverage: flags += ['-fprofile-instr-generate', '-fcoverage-mapping']
modules=sorted(core.glob('cprisk_vm_oph_*.c'))+[core/'cprisk_vm_hardening.c',core/'vm_cff_fusion.c',core/'cprisk_vm_sync_barrier.c']
report={'candidate_ref':a.candidate_ref or 'WORKTREE','host_platform':platform.platform(),'base':base,'compiler':subprocess.check_output([a.clang,'--version']).decode(),'flags':flags,'address_map':address_map,'limitations':['Host non-Apple code path forced; Mach-O discovery stubbed','whitebox/session/runtime/emulator/crypto tracing dependencies deterministic substitutes','data-only interpreter code-address references normalized; real Apple self-check not executed','not evaluate() performance or physical ARM64 execution']}
for name,source in [('before',before),('after',after)]:
    build=out/name;build.mkdir(exist_ok=True)
    source=re.sub(r'\(const void \*\)&(\w+)',lambda m:f'(const void *)(uintptr_t)0x{address_map[m[1]]:x}u',source)
    (build/'interpreter-under-test.c').write_text(source)
    binary=build/'test'
    cmd=[a.clang,*flags,'-I',str(build),str(here/'harness.c'),*map(str,modules),('-Wl,-dead_strip' if platform.system()=='Darwin' else '-Wl,--gc-sections'),'-o',str(binary)]
    subprocess.run(cmd,check=True)
    with (build/'results.txt').open('wb') as f:subprocess.run([str(binary)],stdout=f,check=True,timeout=120,env={**os.environ,'LLVM_PROFILE_FILE':str(build/'coverage.profraw')})
    data=(build/'results.txt').read_bytes();report[name]={'cases':len(data.splitlines()),'sha256':hashlib.sha256(data).hexdigest()}
    assert len(data.splitlines())==6528
    limit_cases=[]
    for line in data.decode().splitlines():
        key,encoded=line.split(); parts=list(map(int,key.split('/'))); result=bytes.fromhex(encoded)
        if parts[1]==2:
            assert int.from_bytes(result[:4],'little')==4
            assert int.from_bytes(result[48:56],'little')==260
            limit_cases.append(key)
    assert len(limit_cases)==192
    report[name]['step_limit_reached']=len(limit_cases)
    if a.coverage:
        llvm=pathlib.Path(a.clang).parent
        subprocess.run([str(llvm/'llvm-profdata'),'merge','-sparse',str(build/'coverage.profraw'),'-o',str(build/'coverage.profdata')],check=True)
        cov=json.loads(subprocess.check_output([str(llvm/'llvm-cov'),'export',str(binary),'-instr-profile='+str(build/'coverage.profdata')]))
        names=['nop','ret','raw_region','halt','add','branch_rel','branch_cond','call','mov_wide','adr_add','cond_select','load_store','xor_mix','or_lane','and_lane','rol_acc','vm_call_func','vreg_mov','vreg_alu','vreg_mem','sub_lane','mul_lane','add_rol_acc','branch_ind','poison','unknown']
        hits={f['name']:f['count'] for d in cov['data'] for f in d['functions'] if f['name'] in ['cprisk_vm_oph_'+n for n in names]}
        assert len(hits)==26 and all(hits.values()),hits
        report[name]['canonical_handler_hits']=hits
        (build/'coverage.json').write_text(json.dumps(cov))
report['equal']=(out/'before/results.txt').read_bytes()==(out/'after/results.txt').read_bytes()
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
assert report['equal'],'bitwise differential mismatch'
