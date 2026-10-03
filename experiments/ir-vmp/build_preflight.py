#!/usr/bin/env python3
"""Build the restricted LLVM API checker with the exact vNext toolchain."""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
from vnext import atomic_json, sha256, load, HERE


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--llvm-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--system-library",action="append",default=[],metavar="NAME=PATH",
                   help="explicit recorded replacement for a missing llvm-config system library")
    args=p.parse_args()
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    config=args.llvm_root.resolve()/"bin/llvm-config"
    version=subprocess.check_output([str(config),"--version"],text=True,timeout=30).strip()
    if version!=load(HERE/"toolchain.lock.json")["llvm_version"]:
        raise ValueError("preflight requires exact locked LLVM version")
    flags=shlex.split(subprocess.check_output([str(config),"--cxxflags","--ldflags","--system-libs","--libs","core","irreader","support","analysis"],text=True,timeout=30))
    replacements={}
    for spec in args.system_library:
        name,path=spec.split("=",1)
        if name in replacements:raise ValueError("duplicate library override")
        replacement=Path(path).resolve(strict=True)
        matches=[flag for flag in flags if flag=="-l"+name or Path(flag).name=="lib"+name+".a"]
        if len(matches)!=1:raise ValueError("expected exactly one system library flag to replace: "+name)
        flags=[str(replacement) if flag==matches[0] else flag for flag in flags]
        replacements[name]={"path":str(replacement),"sha256":sha256(replacement)}
    cc=args.llvm_root.resolve()/"bin/clang++"
    exe=output/"preflight"
    command=[str(cc),str(HERE/"preflight.cpp"),"-o",str(exe)]+flags
    result=subprocess.run(command,capture_output=True,text=True,timeout=180)
    report={"schema_version":1,"llvm_version":version,"source_sha256":sha256(HERE/"preflight.cpp"),
            "command":command,"returncode":result.returncode,"stdout":result.stdout,"stderr":result.stderr,
            "status":"built" if result.returncode==0 else "failed","compiler_sha256":sha256(cc)}
    if result.returncode==0:report["executable_sha256"]=sha256(exe)
    report["system_library_overrides"]=replacements
    atomic_json(output/"preflight-provenance.json",report)
    print(result.stderr)
    return result.returncode


if __name__=="__main__":raise SystemExit(main())
