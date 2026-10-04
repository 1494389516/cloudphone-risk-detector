#!/usr/bin/env python3
"""Inspect non-Apple AArch64 ELF objects, NOT an iPhone Release image."""
import argparse,hashlib,json,pathlib,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--llvm-bin',required=True);p.add_argument('--output',required=True);a=p.parse_args()
here=pathlib.Path(__file__).resolve().parent;root=here.parents[1];out=pathlib.Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
core=root/'RiskDetectorApp/Sources/CRiskCore';llvm=pathlib.Path(a.llvm_bin)
rel='RiskDetectorApp/Sources/CRiskCore/cprisk_vm_interpreter.c';symbol='cprisk_vm_oph_post_handler_i'
base=subprocess.check_output(['git','show','5d8febd:'+rel],cwd=root)
(out/'baseline.c').write_bytes(base)
rows=[]
for opt in ['-O0','-O2','-Oz']:
 for phase,source in [('before',out/'baseline.c'),('after',root/rel)]:
  for repeat in range(3):
   obj=out/f'{phase}{opt}-{repeat}.o'
   cmd=[str(llvm/'clang'),'--target=aarch64-none-elf','-ffreestanding',opt,'-I',str(here/'freestanding'),'-I',str(core),'-include',str(here/'host_shim.h'),'-c',str(source),'-o',str(obj)]
   subprocess.run(cmd,check=True)
   nm=subprocess.check_output([str(llvm/'llvm-nm'),'-S',str(obj)]).decode()
   found=re.search(r'^([0-9a-f]+) ([0-9a-f]+) T '+symbol+r'$',nm,re.M);assert found
   dis=subprocess.check_output([str(llvm/'llvm-objdump'),'-dr',str(obj)]).decode()
   (obj.with_suffix('.disasm.txt')).write_text(dis)
   # A relocation names the external out-of-line destination; disassembly
   # around it distinguishes call/tail branch from mere address-taking.
   calls=[line.strip() for line in dis.splitlines() if re.search(r'R_AARCH64_(CALL26|JUMP26).*'+symbol,line)]
   assert calls, 'post-handler has no direct out-of-line references'
   textfile=obj.with_suffix('.text.bin')
   subprocess.run([str(llvm/'llvm-objcopy'),'--dump-section',f'.text={textfile}',str(obj)],check=True)
   rows.append(dict(text_sha256=hashlib.sha256(textfile.read_bytes()).hexdigest(),phase=phase,opt=opt,repeat=repeat,section_offset='0x'+found[1],length=int(found[2],16),references=calls,object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest()))
report={'target':'aarch64-none-elf','apple_release':False,'linked_address':False,'flags':'-ffreestanding; non-Apple path; declaration-only libc headers and Mach-O lookup shim','rows':rows}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
for r in rows:print(r['phase'],r['opt'],r['repeat'],r['section_offset'],r['length'],len(r['references']))
