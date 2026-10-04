#!/usr/bin/env python3
"""Actual C parser/MAC vs Python oracle, plus optional Swift parser parity."""
import argparse, base64, ctypes as C, hashlib, json, pathlib, random, struct, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[2]; HERE=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--cc',default='clang');p.add_argument('--swiftc');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
o=a.output.resolve();o.mkdir(parents=True,exist_ok=True)
lib=o/('contract.dylib' if sys.platform=='darwin' else 'contract.so')
sdk = subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip() if sys.platform=='darwin' else None
subprocess.run([a.cc,*(['-isysroot',sdk] if sdk else []),'-O2','-shared','-fPIC','-I',str(ROOT/'RiskDetectorApp/Sources/CRiskCore/include'),str(HERE/'contract.c'),'-o',str(lib)],check=True)
x=C.CDLL(str(lib)); x.parse.argtypes=[C.c_char_p,C.c_size_t,C.c_char_p,C.POINTER(C.c_uint64),C.c_uint64,C.c_uint64]
x.tag.argtypes=[C.c_char_p,C.c_size_t,C.c_char_p,C.POINTER(C.c_uint64),C.c_char_p,C.c_size_t,C.c_char_p,C.POINTER(C.c_uint32)]
kind=lambda i: i+1 if i<6 else (1+(i-6)//26)*256+((i-6)%26 if (i-6)%26<24 else (255 if (i-6)%26==24 else 254))
uuid=bytes(range(1,17));rvas=[1024+i*32 for i in range(58)];image=bytes((i*7+11)&255 for i in range(4096));key=bytes(range(32))
valid=struct.pack('<4I',0x56535043,2,58,0)+uuid+b''.join(struct.pack('<QII',v,16,kind(i)) for i,v in enumerate(rvas))
def oracle(p,u,rv,start,size):
    if len(p)!=960 or size>(1<<64)-1-start: return False
    if struct.unpack_from('<4I',p)!=(0x56535043,2,58,0) or p[16:32]!=u or not any(u):return False
    total=0;prior=[]
    for i in range(58):
        v,n,k=struct.unpack_from('<QII',p,32+i*16)
        if k!=kind(i) or v!=rv[i] or v%4 or n%4 or not 0<n<=65536 or not start<=v<=start+size or n>start+size-v or total+n>1048576:return False
        if any(v<b and lo<v+n for lo,b in prior):return False
        prior.append((v,v+n));total+=n
    return True
rows=[]
def check(name,p,u=uuid,rv=rvas,start=0,size=len(image)):
    expected=oracle(p,u,rv,start,size);arr=(C.c_uint64*58)(*rv)
    actual=bool(x.parse(p,len(p),u,arr,start,size));assert actual==expected,(name,actual,expected)
    rows.append(dict(name=name,payload=base64.b64encode(p).decode(),uuid=base64.b64encode(u).decode(),rvas=list(map(str,rv)),textRVA=str(start),textSize=str(size),accepted=expected))
    return expected
assert check('valid',valid)
for n in range(960): assert not check('truncated-'+str(n),valid[:n])
assert not check('trailing',valid+b'\0')
def patch(offset,fmt,value):
    b=bytearray(valid);struct.pack_into(fmt,b,offset,value);return bytes(b)
for off,fmt,val in [(0,'I',0),(4,'I',1),(4,'I',3),(8,'I',57),(8,'I',59),(12,'I',1),(32,'Q',2**64-4),(32,'Q',1025),(40,'I',0),(40,'I',15),(40,'I',65540),(40,'I',48),(44,'I',2),(48+12,'I',1)]:
    assert not check(f'bad-{off}-{val}',patch(off,'<'+fmt,val))
assert not check('stale-uuid',valid,bytes(range(16)))
assert not check('zero-uuid',valid[:16]+bytes(16)+valid[32:],bytes(16))
assert not check('text-overflow',valid,start=2**64-4,size=8)
assert not check('out-of-text',valid,start=1030)
rv=[4096+i*65536 for i in range(58)]
large=valid[:32]+b''.join(struct.pack('<QII',v,65536,kind(i)) for i,v in enumerate(rv))
assert not check('total-limit',large,rv=rv,size=4*1024*1024)
# Boundary-valid largest single span with independent nonoverlapping identities.
rv=[4096+i*65536 for i in range(58)]
boundary=valid[:32]+b''.join(struct.pack('<QII',v,65536 if i==0 else 4,kind(i)) for i,v in enumerate(rv))
assert check('max-single-range',boundary,rv=rv,size=4*1024*1024)
rng=random.Random(813)
for i in range(2000):
    b=bytearray(valid)
    for _ in range(rng.randrange(1,5)):
        j=rng.randrange(len(b));b[j]^=rng.randrange(1,256)
    check('mutation-'+str(i),bytes(b))
def mac(p,img):
    msg=p+b''.join(img[v:v+struct.unpack_from('<I',p,40+i*16)[0]] for i,v in enumerate(rvas))
    k=key+bytes(32)
    return hashlib.sha256(bytes(v^0xa3 for v in k)+hashlib.sha256(bytes(v^0x6d for v in k)+msg).digest()).digest()[:4]
def ctag(p,img):
    tag=C.c_uint32();assert x.tag(p,len(p),uuid,(C.c_uint64*58)(*rvas),img,len(img),key,C.byref(tag));return struct.pack('<I',tag.value)
expected=mac(valid,image);assert ctag(valid,image)==expected
for i,v in enumerate(rvas):
    img=bytearray(image);img[v]^=1
    assert ctag(valid,bytes(img))==mac(valid,img)!=expected
# Valid descriptor length change must be part of authenticated message too.
changed=patch(40,'<I',12);assert check('valid-length-change',changed)
assert ctag(changed,image)==mac(changed,image)!=expected
(o/'vectors.json').write_text(json.dumps(rows))
swift=False
if a.swiftc:
    exe=o/'swift-contract'
    subprocess.run([a.swiftc,*(['-sdk',sdk] if sdk else []),str(ROOT/'cprisk-armor/Sources/MachOKit/CPSV2Manifest.swift'),str(HERE/'contract.swift'),'-o',str(exe)],check=True)
    subprocess.run([str(exe),str(o/'vectors.json')],check=True);swift=True
report=dict(status='CPSV2_CONTRACT_PASS',cases=len(rows),negative=sum(not r['accepted'] for r in rows),tampered_ranges=58,tag_le=expected.hex(),swift_parity=swift,production_acceptance=False)
(o/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
