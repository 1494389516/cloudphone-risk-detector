#!/usr/bin/env python3
"""Real Swift injector + real C v2 observer on a signed native Mach-O fixture.

The 58 roster functions here are inert fixtures, NOT the production VM. Separate
integrated interpreter/ARM64 gates cover that engine. No device performance claim.
"""
import argparse, hashlib, json, pathlib, re, shutil, struct, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[2]; CORE=ROOT/'RiskDetectorApp/Sources/CRiskCore'
sys.path.insert(0,str(ROOT/'experiments/vm-threaded-dispatch'))
from apple_release import text_bytes
from layout import build_layout

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    o=a.output.resolve();o.mkdir(parents=True,exist_ok=True)
    names=re.findall(r'CPRISK_CPSV2_IDENTITY\((\w+)\)',(CORE/'cprisk_vm_cpsv2_roster.inc').read_text());assert len(names)==58
    source=(CORE/'cprisk_vm_interpreter.c').read_text()
    start=source.index('static void cprisk_vm_selfchk_hmac_key_i(');end=source.index('\nstatic uint64_t cprisk_vm_selfchk_fault_mask_i(',start)
    body='''#include "include/cprisk_vm_cpsv2_hash.h"
#include "include/cprisk_macho.h"
#include <stdio.h>
_Static_assert(S_THREAD_LOCAL_ZEROFILL == 0x12, "Match Apple's loader contract");
/* Regression: real SDK images contain file-less TLS zero-fill sections. */
static _Thread_local volatile uint64_t tls_zero;
__attribute__((used,section("__DATA,__swift5_mdvsi")))
static const uint8_t manifest[CPRISK_CPSV2_BYTES]={0x43,0x50,0x53,0x56,2,0,0,0,58};
__attribute__((used,section("__DATA,__swift5_mdvsk"))) static const uint8_t expectation[8]={0};
void cprisk_crypto_trace_primitive_enter_i(void) {}
uint64_t cprisk_crypto_trace_now_i(void) {return 0;}
void cprisk_crypto_trace_record_span_ticks_i(uint64_t n) {(void)n;}
int cprisk_get_runtime_material(uint8_t *p) {memset(p,0x52,32);return 0;}
'''
    for i,n in enumerate(names):
        body+=f'__attribute__((noinline,used)) void {n}(void) {{ __asm__ volatile("mov x9, #{i+1}" ::: "x9"); }}\n'
    body+=source[start:end]+'\n#include "cprisk_vm_cpsv2_runtime.inc"\n'
    body+='''extern const struct mach_header_64 _mh_execute_header;
int main(void) {
    tls_zero++;
    uint32_t tag=0; unsigned long n=0;
    const uint8_t *e=cprisk_find_section(&_mh_execute_header,"__DATA","__swift5_mdvsk",&n);
    int ok=cprisk_vm_cpsv2_observe_i(&_mh_execute_header,&tag);
    return !(ok && n==8 && cprisk_cpsv2_u32(e)==0x48535043 && tag && tag==cprisk_cpsv2_u32(e+4));
}
'''
    c=o/'fixture.c';c.write_text(body);exe=o/'fixture';linkmap=o/'linkmap.txt'
    sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip()
    subprocess.run(['xcrun','clang','-isysroot',sdk,'-arch','arm64','-O2','-I',str(CORE),str(c),'-Wl,-map,'+str(linkmap),'-o',str(exe)],check=True)
    subprocess.run(['codesign','--force','--sign','-',str(exe)],check=True,capture_output=True)
    # Reserved/uninjected image must reject.
    assert subprocess.run([str(exe)]).returncode==1
    pristine=exe.read_bytes()
    layout_data=build_layout(exe,linkmap)
    ranges=layout_data['ranges']
    offsets=[text_bytes(exe,r['address'],r['length'])[0] for r in ranges]
    layout=o/'layout.json';layout.write_text(json.dumps(layout_data))
    subprocess.run(['swift','build','--package-path',str(ROOT/'cprisk-armor'),'--product','cprisk-vm-self-expect'],check=True)
    tool=ROOT/'cprisk-armor/.build/debug/cprisk-vm-self-expect'
    inject=[str(tool),'--in',str(exe),'--material-hex','52'*32,'--cpsv2-layout',str(layout)]
    subprocess.run(inject,check=True)
    injected=exe.read_bytes()
    assert subprocess.run(inject,capture_output=True).returncode!=0,'stale image layout accepted'
    assert exe.read_bytes()==injected,'failed injection modified file'
    subprocess.run(['codesign','--force','--sign','-',str(exe)],check=True,capture_output=True)
    subprocess.run([str(exe)],check=True)
    signed=exe.read_bytes();tamper=o/'tamper'
    for i,offset in enumerate(offsets):
        changed=bytearray(signed);changed[offset]^=1;tamper.write_bytes(changed);tamper.chmod(0o755)
        subprocess.run(['codesign','--force','--sign','-',str(tamper)],check=True,capture_output=True)
        rc=subprocess.run([str(tamper)]).returncode
        assert rc==1,(names[i],rc)
    # Locate pointer-free manifest; mutate descriptor/version without updating expectation.
    manifest_offset=signed.index(b'CPSV\x02\0\0\0\x3a\0\0\0')
    for delta in [4,8,12,16,32,40,44]:
        changed=bytearray(signed);changed[manifest_offset+delta]^=1;tamper.write_bytes(changed)
        subprocess.run(['codesign','--force','--sign','-',str(tamper)],check=True,capture_output=True)
        assert subprocess.run([str(tamper)]).returncode==1
    report=dict(status='APPLE_SWIFT_C_V2_FIXTURE_PASS',native_arm64=True,signed_host_fixture=True,
                ranges=ranges,code_tamper_rejections=58,manifest_tamper_rejections=7,
                uninjected_rejected=True,stale_sidecar_rejected=True,production_vm_execution=False)
    (o/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='ranges'},indent=2))
if __name__=='__main__':main()
