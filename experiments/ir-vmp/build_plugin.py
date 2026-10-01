#!/usr/bin/env python3
"""Build the pinned upstream plugin from an existing checkout; never downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

XOLLVM_COMMIT = "81808e195c9a40a01c36b1016ed7e6fbd96a4a3e"
PATCH_DIR = Path(__file__).resolve().parent / "patches"
PATCH_SETS = ("pointer-eq-ne-v1", "pointer-gep-v2")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_tree_hash(source):
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("staged source contains a symlink")
        if path.is_file():
            digest.update(path.relative_to(source).as_posix().encode() + b"\0")
            digest.update(bytes.fromhex(sha256(path)))
    return digest.hexdigest()


def patch_manifest(name):
    if name not in PATCH_SETS:
        raise ValueError("unknown local patch set: " + str(name))
    path = PATCH_DIR / (name + ".json")
    data = json.loads(path.read_text())
    if (data.get("schema_version") != 1 or data.get("id") != name
            or data.get("xollvm_commit") != XOLLVM_COMMIT
            or data.get("patch_file") != name + ".patch"
            or data.get("patch_sha256") != sha256(PATCH_DIR / data["patch_file"])):
        raise ValueError("local patch manifest/hash mismatch")
    return data


def check_patch_files(source, manifest, key):
    for relative, hashes in manifest["files"].items():
        path = source / relative
        if (path.is_symlink() or not path.is_file() or source not in path.resolve().parents
                or sha256(path) != hashes[key]):
            raise ValueError("patch source hash mismatch: " + relative)


def stage_patched_source(source, build, manifest):
    # Copy only tracked regular files from the clean pinned checkout. The caller's
    # checkout is never patched. Exact before/after hashes reject fuzzy application.
    staged = build / "patched-source"
    staged.mkdir()
    tracked = [name for name in capture(["git", "-C", str(source), "ls-files", "-z"]).split("\0") if name]
    for relative in tracked:
        original = source / relative
        if (original.is_symlink() or not original.is_file()
                or source not in original.resolve().parents):
            raise ValueError("unsupported tracked source file: " + relative)
        destination = staged / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, destination)
    check_patch_files(staged, manifest, "before_sha256")
    patch = str(PATCH_DIR / manifest["patch_file"])
    subprocess.run(["git", "apply", "--check", patch], cwd=staged, check=True)
    subprocess.run(["git", "apply", patch], cwd=staged, check=True)
    check_patch_files(staged, manifest, "after_sha256")
    return staged


def capture(args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT,
                                   timeout=60, **kwargs).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--llvm-root", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--patch-set", choices=PATCH_SETS,
                        help="apply a reviewed local patch in an isolated source copy")
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
    manifest = patch_manifest(args.patch_set) if args.patch_set else None
    compile_source = stage_patched_source(source, build, manifest) if manifest else source
    staged_hash = source_tree_hash(compile_source) if manifest else None
    cmake_build = build / "cmake" if manifest else build
    commands = [
        ["cmake", "-S", str(compile_source), "-B", str(cmake_build),
         f"-DLLVM_DIR={cmake_dir}", "-DCMAKE_BUILD_TYPE=Release",
         f"-DCMAKE_C_COMPILER={llvm / 'bin/clang'}",
         f"-DCMAKE_CXX_COMPILER={llvm / 'bin/clang++'}"],
        ["cmake", "--build", str(cmake_build), "--target", "Obfuscator",
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
    if manifest:
        check_patch_files(compile_source, manifest, "after_sha256")
        if source_tree_hash(compile_source) != staged_hash:
            raise ValueError("staged source tree changed during build")
        if patch_manifest(args.patch_set) != manifest:
            raise ValueError("patch manifest changed during build")
    report = {"schema_version": 1, "status": "built", "xollvm_commit": head,
              "plugin_path": str(plugin),
              "plugin_sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(),
              "llvm_version": ver, "tool_versions": versions, "commands": commands,
              "license": "Apache-2.0 WITH LLVM-exception",
              "limitations": ["Local provenance only; not a signed attestation",
                              "Build success does not validate virtualization or iOS compatibility"]}
    if manifest:
        report.update(schema_version=2, local_patch_set=manifest,
                      patched_source=str(compile_source), patched_source_tree_sha256=staged_hash)
    path = build / "plugin-provenance.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(path)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"plugin build blocked: {error}", file=sys.stderr)
        sys.exit(1)
