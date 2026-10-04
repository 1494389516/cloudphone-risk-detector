#!/usr/bin/env python3
"""Bind authoritative linker-map extents to an exact final, unstripped Mach-O.

Run after all size-preserving code transforms. A size-changing transform must
supply its own final extent map; this tool cannot infer new function lengths.
The map is trusted build input, not an authenticated runtime artifact.
"""
import argparse, hashlib, json, pathlib, re, sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
from macho_ranges import text_bytes

def build_layout(image, linkmap):
    image=image.resolve();text=linkmap.read_text();live=text.split('# Dead Stripped Symbols:')[0]
    owner=re.search(r'^# Path: (.+)$',text,re.M)
    if not owner or pathlib.Path(owner[1]).resolve()!=image:
        raise ValueError('Linker map belongs to a different image path')
    roster=ROOT/'RiskDetectorApp/Sources/CRiskCore/cprisk_vm_cpsv2_roster.inc'
    names=re.findall(r'CPRISK_CPSV2_IDENTITY\((\w+)\)',roster.read_text());assert len(names)==58
    ranges=[]
    for name in names:
        matches=re.findall(r'^\s*(0x[\da-fA-F]+)\s+(0x[\da-fA-F]+)\s+\[\s*\d+\]\s+_'+name+r'\s*$',live,re.M)
        if len(matches)!=1: raise ValueError('Missing/ambiguous final function: '+name)
        address,length=map(lambda x:int(x,16),matches[0])
        if address%4 or length%4 or not 0<length<=65536:raise ValueError('Invalid function extent: '+name)
        text_bytes(image,address,length)
        if any(address<r['address']+r['length'] and r['address']<address+length for r in ranges):raise ValueError('Overlapping/folded function: '+name)
        ranges.append(dict(name=name,address=address,length=length))
    if sum(r['length'] for r in ranges)>1048576:raise ValueError('Total coverage exceeds 1 MiB')
    return dict(imageSHA256=hashlib.sha256(image.read_bytes()).hexdigest(),ranges=ranges)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',type=pathlib.Path,required=True);p.add_argument('--linkmap',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    a.output.write_text(json.dumps(build_layout(a.image,a.linkmap),indent=2)+'\n')
