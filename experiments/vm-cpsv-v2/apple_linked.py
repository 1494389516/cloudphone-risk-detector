#!/usr/bin/env python3
"""Stock iPhoneOS Release with actual threaded runtime and v2 injection.

Verifies the linked artifact, not execution on a device or post-armor transforms.
"""
import argparse, hashlib, json, pathlib, re, struct, subprocess
from layout import ROOT, build_layout, text_bytes

def section(data, segment, name):
    n=struct.unpack_from('<I',data,16)[0];pos=32
    for _ in range(n):
        cmd,size=struct.unpack_from('<II',data,pos)
        if cmd==0x19:
            count=struct.unpack_from('<I',data,pos+64)[0]
            for i in range(count):
                at=pos+72+i*80
                sect,seg,addr,length,offset=struct.unpack_from('<16s16sQQI',data,at)
                if sect.rstrip(b'\0').decode()==name and seg.rstrip(b'\0').decode()==segment:
                    assert offset+length<=len(data)
                    return data[offset:offset+length]
        pos+=size
    raise ValueError('Missing section '+name)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);derived=out/'DerivedData'
    cmd=['xcodebuild','-project',str(ROOT/'RiskDetectorApp/RiskDetectorApp.xcodeproj'),
         '-scheme','RiskDetectorApp','-configuration','Release','-sdk','iphoneos',
         '-destination','generic/platform=iOS','-derivedDataPath',str(derived),
         'ARCHS=arm64','CODE_SIGNING_ALLOWED=NO','LD_GENERATE_MAP_FILE=YES',
         'OTHER_CFLAGS=$(inherited) -DCPRISK_VM_THREADED_DISPATCH=1','build']
    with (out/'build.log').open('wb') as log:subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,check=True)
    matches=[]
    for mp in derived.rglob('*LinkMap*'):
        if not mp.is_file():continue
        text=mp.read_text(errors='replace');owner=re.search(r'^# Path: (.+)$',text,re.M)
        if not owner or '_cprisk_thread_run_a_i' not in text.split('# Dead Stripped Symbols:')[0]:continue
        image=pathlib.Path(owner[1]).resolve();layout=build_layout(image,mp);matches.append((image,layout,mp))
    assert len(matches)==1,'Actual linked threaded VM absent/ambiguous; do not accept a legacy build'
    image,layout,mp=matches[0];before=image.read_bytes()
    payload=section(before,'__DATA','__swift5_mdvsi');assert len(payload)==960 and payload[:16]==struct.pack('<4I',0x56535043,2,58,0)
    (out/'linkmap.txt').write_text(mp.read_text());lp=out/'layout.json';lp.write_text(json.dumps(layout,indent=2))
    subprocess.run(['swift','build','--package-path',str(ROOT/'cprisk-armor'),'--product','cprisk-vm-self-expect'],check=True)
    subprocess.run([str(ROOT/'cprisk-armor/.build/debug/cprisk-vm-self-expect'),'--in',str(image),'--hmac','--material-hex','52'*32,'--cpsv2-layout',str(lp)],check=True)
    after=image.read_bytes();payload=section(after,'__DATA','__swift5_mdvsi')
    assert payload[:16]==struct.pack('<4I',0x56535043,2,58,0) and any(payload[16:32])
    assert section(after,'__DATA','__swift5_mdvsk')[:4]==b'CPSH'
    dis=subprocess.check_output(['xcrun','llvm-objdump','-d',str(image)]).decode();(out/'disassembly.txt').write_text(dis)
    funcs=dict(re.findall(r'^[0-9a-f]+ <_?(\w+)>:\n(.*?)(?=^[0-9a-f]+ <|\Z)',dis,re.M|re.S))
    rows=[]
    for i,r in enumerate(layout['ranges']):
        offset,code=text_bytes(image,r['address'],r['length'])
        assert before[offset:offset+r['length']]==code,'Injector changed protected code'
        if i>=6:assert re.search(r'\bbr\s+x\d+\b',funcs[r['name']]),'Linked handler lost tail transfer: '+r['name']
        rows.append(dict(**r,file_offset=offset,sha256=hashlib.sha256(code).hexdigest()))
    report=dict(status='APPLE_LINKED_THREADED_V2_PASS',revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT).decode().strip(),
                sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-version']).decode().strip(),
                command=cmd,ranges=rows,indirect_tail_handlers=52,total_span_bytes=sum(r['length'] for r in rows),
                injected_image_sha256=hashlib.sha256(after).hexdigest(),post_armor=False,device_execution=False,performance_accepted=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ['ranges','command']},indent=2))
if __name__=='__main__':main()
