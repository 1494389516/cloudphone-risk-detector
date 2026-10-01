#!/usr/bin/env python3
"""Build the pinned upstream plugin from an existing checkout; never downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

XOLLVM_COMMIT = "81808e195c9a40a01c36b1016ed7e6fbd96a4a3e"


def capture(args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT,
                                   timeout=60, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--llvm-root", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    source, llvm, build = (p.resolve() for p in
                           (args.source, args.llvm_root, args.build_dir))
    if args.jobs < 1:
        raise ValueError("--jobs must be positive")
    if build == source or source in build.parents:
        raise ValueError("use a separate build directory outside the source checkout")
    if build.exists() and any(build.iterdir()):
        raise ValueError("build directory must be empty; stale CMake/plugin artifacts are rejected")
    head = capture(["git", "-C", str(source), "rev-parse", "HEAD"])
    if head != XOLLVM_COMMIT:
        raise ValueError(f"expected xollvm {XOLLVM_COMMIT}, got {head}")
    if capture(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("xollvm checkout must be clean, including untracked files")
    versions = {}
    for name in ("clang", "clang++", "opt", "llvm-config"):
        exe = llvm / "bin" / name
        versions[name] = capture([str(exe), "--version"])
    ver = versions["llvm-config"]
    if not re.fullmatch(r"(?:22|23)\.\d+\.\d+(?:[-+].*)?", ver):
        raise ValueError(f"expected LLVM 22 or 23, got {ver}")
    for name in ("clang", "clang++", "opt"):
        match = re.search(r"version\s+(\d+\.\d+\.\d+)", versions[name])
        if not match or match.group(1) != ver.split("-")[0].split("+")[0]:
            raise ValueError(f"{name} does not match llvm-config {ver}")
    cmake_dir = capture([str(llvm / "bin/llvm-config"), "--cmakedir"])
    env = dict(os.environ)
    env["PATH"] = str(llvm / "bin") + os.pathsep + env.get("PATH", "")
    build.mkdir(parents=True, exist_ok=True)
    commands = [
        ["cmake", "-S", str(source), "-B", str(build),
         f"-DLLVM_DIR={cmake_dir}", "-DCMAKE_BUILD_TYPE=Release",
         f"-DCMAKE_C_COMPILER={llvm / 'bin/clang'}",
         f"-DCMAKE_CXX_COMPILER={llvm / 'bin/clang++'}"],
        ["cmake", "--build", str(build), "--target", "Obfuscator",
         "--parallel", str(args.jobs)],
    ]
    for command in commands:
        subprocess.run(command, env=env, check=True)
    plugins = [p for p in build.rglob("*") if p.is_file()
               and p.name in ("Obfuscator.so", "Obfuscator.dylib", "libObfuscator.so", "libObfuscator.dylib")]
    if len(plugins) != 1:
        raise ValueError(f"expected one built plugin, found {len(plugins)}")
    plugin = plugins[0].resolve()
    # Recheck source state after build; provenance is a local record, not an attestation.
    if capture(["git", "-C", str(source), "rev-parse", "HEAD"]) != head or capture(
        ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=all"]
    ):
        raise ValueError("source checkout changed during build")
    report = {"schema_version": 1, "status": "built", "xollvm_commit": head,
              "plugin_path": str(plugin),
              "plugin_sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(),
              "llvm_version": ver, "tool_versions": versions, "commands": commands,
              "license": "Apache-2.0 WITH LLVM-exception",
              "limitations": ["Local provenance only; not a signed attestation",
                              "Build success does not validate virtualization or iOS compatibility"]}
    path = build / "plugin-provenance.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"plugin build blocked: {error}", file=sys.stderr)
        sys.exit(1)
