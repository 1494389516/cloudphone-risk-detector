#!/usr/bin/env python3
"""Reproduce the local pointer patch's real host differential (not unit tests)."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run import check_provenance, check_versions, inspect_ir, inspect_pass_reports, sha256

SOURCE = r'''#include <stdint.h>
#ifndef PREFIX
#error PREFIX required
#endif
#define JOIN2(a,b) a##b
#define JOIN(a,b) JOIN2(a,b)
#ifdef PROTECTED
#define TARGET __attribute__((noinline, annotate(ANNOTATION)))
#else
#define TARGET __attribute__((noinline))
#endif
TARGET uint32_t JOIN(PREFIX, pointer_eq)(const void *a, const void *b) { return a == b; }
TARGET uint32_t JOIN(PREFIX, pointer_ne)(const void *a, const void *b) { return a != b; }
TARGET uint32_t JOIN(PREFIX, pointer_eqnull)(const void *a, const void *b) { (void)b; return a == 0; }
TARGET uint32_t JOIN(PREFIX, pointer_nenull)(const void *a, const void *b) { (void)b; return a != 0; }
'''
HARNESS = r'''#include <stdint.h>
#include <stdio.h>
#define DECL(n) uint32_t plain_##n(const void*,const void*); uint32_t protected_##n(const void*,const void*);
DECL(pointer_eq) DECL(pointer_ne) DECL(pointer_eqnull) DECL(pointer_nenull)
static unsigned char global_a[8], global_b[8];
#define CHECK(n, expected) do { uint32_t a=plain_##n(p[i],p[j]), b=protected_##n(p[i],p[j]); if(a!=b || b!=(uint32_t)(expected)){ fprintf(stderr,"FAIL %s i=%u j=%u native=%u vm=%u\n",#n,i,j,a,b);return 1;}++cases;}while(0)
int main(void) {
 unsigned char a[8],b[8]; unsigned cases=0;
 const void *p[]={0,a,a,a+1,a+8,b,b+1,global_a,global_a+1,global_b};
 for(unsigned i=0;i<10;++i)for(unsigned j=0;j<10;++j) {
 CHECK(pointer_eq,p[i]==p[j]);CHECK(pointer_ne,p[i]!=p[j]);
 CHECK(pointer_eqnull,p[i]==0);CHECK(pointer_nenull,p[i]!=0);
 }
 printf("PASS cases=%u pointer_eq_ne_null\n",cases);return 0;
}
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm-root',type=Path,required=True)
    parser.add_argument('--plugin',type=Path,required=True)
    parser.add_argument('--plugin-provenance',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(); output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    report={'schema_version':1,'status':'RUNNING','vmp_verified':False,'scope':'macOS host pointer equality only; no device or stack correctness conclusion','source':SOURCE,'harness':HARNESS,'probe_sha256':sha256(__file__),'commands':[],'configurations':[]}
    def run(argv):
        argv=[str(a) for a in argv]; p=subprocess.run(argv,text=True,capture_output=True,timeout=120)
        report['commands'].append({'argv':argv,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        if p.returncode: raise RuntimeError('Command failed: '+' '.join(argv))
        return p.stdout
    try:
        clang=args.llvm_root/'bin/clang';opt=args.llvm_root/'bin/opt'
        version=check_versions(run([clang,'--version']),run([opt,'--version']))
        provenance=check_provenance(args.plugin_provenance,args.plugin,version)
        if provenance.get('local_patch_set',{}).get('id') not in ('pointer-eq-ne-v1', 'pointer-gep-v2'):raise RuntimeError('Pointer patch provenance required')
        report['plugin_provenance']=provenance
        targets=tuple('protected_pointer_'+s for s in ('eq','ne','eqnull','nenull'))
        for rand in (0,1):
            build=Path(tempfile.mkdtemp(prefix='randisa-'+str(rand)+'-',dir=output))
            source=build/'probe.c';harness=build/'differential.c';source.write_text(SOURCE);harness.write_text(HARNESS)
            before=build/'before.ll';after=build/'after.ll';optimized=build/'optimized.ll';reports=build/'pass-reports';reports.mkdir()
            common=[clang,'-std=c11','-Wall','-Wextra','-Werror']
            run(common+['-O2','-DPREFIX=plain_','-c',source,'-o',build/'plain.o'])
            annotation=f'obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0,randISA={rand})'
            run(common+['-O0','-Xclang','-disable-O0-optnone','-DPREFIX=protected_','-DPROTECTED=1','-DANNOTATION="'+annotation+'"','-S','-emit-llvm',source,'-o',before])
            run([opt,'-load-pass-plugin='+str(args.plugin),'-passes=obfuscation','-obf-seed=1','-obf-deterministic','-obf-verify','-obf-verbose','-obf-report-dir='+str(reports),'-S',before,'-o',after])
            run([opt,'-passes=verify','-disable-output',after])
            entry={'randISA':rand,'build_directory':str(build),'pass_evidence':inspect_pass_reports(reports,targets),'ir_evidence':inspect_ir(before.read_text(),after.read_text(),targets)}
            run([opt,'-passes=default<O2>','-S',after,'-o',optimized]);run([opt,'-passes=verify','-disable-output',optimized])
            entry['optimized_ir_evidence']=inspect_ir(before.read_text(),optimized.read_text(),targets,require_entry=False)
            run([clang,'-O0','-c',optimized,'-o',build/'protected.o'])
            run(common+['-O2',harness,build/'plain.o',build/'protected.o','-o',build/'differential'])
            entry['output']=run([build/'differential'])
            if entry['output'].strip()!='PASS cases=400 pointer_eq_ne_null':raise RuntimeError('Missing pointer case count')
            entry['hashes']={str(p):sha256(p) for p in (source,harness,before,after,optimized,build/'differential')}
            report['configurations'].append(entry)
        report.update(status='HOST_POINTER_VMP_PASS',vmp_verified=True)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        report.update(status='BLOCKED_OR_FAILED',error=str(exc))
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'report':str(output/'report.json')}))
    return 0 if report['vmp_verified'] else 1
if __name__=='__main__':raise SystemExit(main())
