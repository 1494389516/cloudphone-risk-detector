#!/usr/bin/env python3
"""Fail-closed, host-only differential experiment; never enables production VMP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
STACK_TARGETS = tuple("protected_" + s for s in (
    "vm_stack_crypto_init", "vm_stack_encrypt_push", "vm_stack_push_encrypted"))

PINNED_COMMIT = "81808e195c9a40a01c36b1016ed7e6fbd96a4a3e"
GF2_TARGETS = ("protected_cprisk_gf2_xorshift64", "protected_cprisk_gf2_fnv1a")


class GateError(RuntimeError):
    pass


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def llvm_version(version):
    if "Apple clang" in version:
        raise GateError("Apple clang is not the pinned upstream LLVM toolchain")
    match = re.search(r"(?:clang|LLVM) version\s+(\d+\.\d+\.\d+[^\s]*)", version, re.I)
    if not match:
        raise GateError("Cannot establish full LLVM tool version")
    return match.group(1)


def check_versions(clang_version, opt_version):
    version = llvm_version(clang_version)
    if int(version.split(".")[0]) not in (22, 23) or llvm_version(opt_version) != version:
        raise GateError("xollvm experiment requires matching full LLVM 22 or 23 clang/opt versions")
    return version


def function_body(ir, name):
    match = re.search(r"^define\b[^\n]*@" + re.escape(name) + r"\([^\n]*\)[^\n]*\{\n(.*?)^\}",
                      ir, re.M | re.S)
    if not match:
        raise GateError("Missing defined target function: " + name)
    return match.group(1)


def inspect_ir(before, after, targets=GF2_TARGETS, require_entry=True):
    """Require exact per-target raw xollvm IR evidence before optimization."""
    engine = function_body(after, "__vm_engine")
    if "indirectbr" not in engine:
        raise GateError("VM engine has no indirect dispatch")
    evidence = {}
    for name in targets:
        old, new = function_body(before, name), function_body(after, name)
        if old == new:
            raise GateError("Target silently unchanged: " + name)
        bytecode = re.search(r"^@" + re.escape(name) + r"\.vm\.bytecode\s*=.*?private (?:unnamed_addr )?constant \[([1-9][0-9]*) x i8\]", after, re.M)
        handlers = re.search(r"^@" + re.escape(name) + r"\.vm\.ophandlers\s*=", after, re.M)
        if not bytecode or not handlers or (require_entry and "vm.entry" not in new) or "@" + name + ".vm.bytecode" not in new or "@" + name + ".vm.ophandlers" not in new:
            raise GateError("Incomplete VM execution evidence in target: " + name)
        evidence[name] = {"bytecode_bytes": int(bytecode.group(1)),
                          "before_sha256": hashlib.sha256(old.encode()).hexdigest(),
                          "after_sha256": hashlib.sha256(new.encode()).hexdigest()}
    return evidence


def inspect_pass_reports(directory, targets):
    records = []
    for path in Path(directory).rglob("*.json"):
        data = json.loads(path.read_text())
        if isinstance(data, dict) and isinstance(data.get("functions"), list):
            if any(not isinstance(item, dict) for item in data["functions"]):
                raise GateError("Malformed function report: " + str(path))
            records.extend(data["functions"])
    for name in targets:
        found = [r for r in records if r.get("name") == name]
        if len(found) != 1 or found[0].get("skipped") is not False:
            raise GateError("Missing, duplicate, or skipped function report: " + name)
        raw_passes = found[0].get("passes", [])
        if not isinstance(raw_passes, list) or any(not isinstance(p, dict) for p in raw_passes):
            raise GateError("Malformed pass report: " + name)
        passes = [p for p in raw_passes if p.get("id") == "vm"]
        if len(passes) != 1 or passes[0].get("status") != "ran" or passes[0].get("changed") is not True:
            raise GateError("VM pass did not run and change target: " + name)
    return {"targets": list(targets), "all_vm_passes_ran_and_changed": True}


def check_provenance(path, plugin, version):
    if not path or not Path(path).is_file():
        raise GateError("--plugin-provenance is required")
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise GateError("Invalid plugin provenance format")
    if (data.get("xollvm_commit") != PINNED_COMMIT or data.get("plugin_sha256") != sha256(plugin)
            or data.get("llvm_version") != version or data.get("status") != "built"):
        raise GateError("Plugin provenance commit/hash mismatch")
    return data


def execute(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "mode": args.mode, "suite": args.suite, "status": "RUNNING",
              "vmp_verified": False, "scope": "host experiment only; no iOS/device validation",
              "commands": [], "tools": {}, "hashes": {}}
    started = time.monotonic()

    def run(command):
        entry = {"argv": [str(x) for x in command]}
        report["commands"].append(entry)
        try:
            result = subprocess.run(entry["argv"], text=True, capture_output=True,
                                    timeout=args.timeout, cwd=HERE)
        except (OSError, subprocess.TimeoutExpired) as exc:
            entry["error"] = str(exc)
            raise GateError(str(exc)) from exc
        entry.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode:
            raise GateError("Command failed: " + " ".join(entry["argv"]))
        return result.stdout

    def tool(label, requested):
        resolved = shutil.which(requested)
        if not resolved:
            raise GateError("Required tool unavailable: " + requested)
        resolved = str(Path(resolved).resolve())
        version = run([resolved, "--version"])
        report["tools"][label] = {"path": resolved, "version": version,
                                  "sha256": sha256(resolved)}
        return resolved, version

    try:
        stem = "gf2_" if args.suite == "gf2" else ""
        candidate = stem + "candidates.c"
        harness = stem + "differential.c"
        targets = GF2_TARGETS if args.suite == "gf2" else STACK_TARGETS
        sources = [HERE / candidate, HERE / harness]
        if args.suite == "gf2":
            sources += [HERE / "gf2_candidates.inc", HERE / "sources.json", HERE / "verify_sources.py"]
            run([sys.executable, HERE / "verify_sources.py"])
        else:
            sources += [HERE / "candidates.h"]
            sources += [HERE.parents[1] / "RiskDetectorApp/Sources/CRiskCore" / name
                        for name in ("vm_stack_crypto.c", "vm_stack_crypto.h")]
        for source in sources:
            if not source.is_file():
                raise GateError("Missing source: " + str(source))
            report["hashes"][str(source)] = sha256(source)
        if args.mode == "baseline-only":
            cc, _ = tool("cc", args.cc)
        else:
            cc, cc_version = tool("clang", args.clang)
            opt, opt_version = tool("opt", args.opt)
            version = check_versions(cc_version, opt_version)
            if not args.plugin or not Path(args.plugin).is_file():
                raise GateError("An existing xollvm plugin must be supplied with --plugin")
            plugin = str(Path(args.plugin).resolve())
            report["tools"]["plugin"] = {"path": plugin, "sha256": sha256(plugin)}
            report["plugin_provenance"] = check_provenance(args.plugin_provenance, plugin, version)
        # Every invocation gets a fresh build directory: stale objects cannot pass gates.
        build = Path(tempfile.mkdtemp(prefix="build-", dir=output))
        report["build_directory"] = str(build)
        common = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        plain = build / "plain.o"
        protected = build / "protected.o"
        run(common + ["-DCPRISK_VMP_PREFIX=plain_", "-c", candidate, "-o", plain])
        if args.mode == "baseline-only":
            run(common + ["-DCPRISK_VMP_PREFIX=protected_", "-c", candidate, "-o", protected])
        else:
            before, after = build / "before.ll", build / "after.ll"
            run([cc, "-std=c11", "-O0", "-Xclang", "-disable-O0-optnone", "-Wall", "-Wextra", "-Werror",
                          "-DCPRISK_VMP_PREFIX=protected_", "-DCPRISK_VMP_PROTECTED=1",
                          "-S", "-emit-llvm", candidate, "-o", before])
            pass_reports = build / "pass-reports"
            pass_reports.mkdir()
            run([opt, "-load-pass-plugin=" + plugin, "-passes=obfuscation",
                 "-obf-seed=1", "-obf-deterministic", "-obf-verify", "-obf-verbose",
                 "-obf-report-dir=" + str(pass_reports), "-S", before, "-o", after])
            run([opt, "-passes=verify", "-disable-output", after])
            report["pass_evidence"] = inspect_pass_reports(pass_reports, targets)
            report["ir_evidence"] = inspect_ir(before.read_text(), after.read_text(), targets)
            report["hashes"][str(before)] = sha256(before)
            report["hashes"][str(after)] = sha256(after)
            optimized = build / "optimized.ll"
            run([opt, "-passes=default<O2>", "-S", after, "-o", optimized])
            run([opt, "-passes=verify", "-disable-output", optimized])
            report["optimized_ir_evidence"] = inspect_ir(
                before.read_text(), optimized.read_text(), targets, require_entry=False)
            report["hashes"][str(optimized)] = sha256(optimized)
            # Do not run another optimizer after examining the final IR.
            run([cc, "-O0", "-c", optimized, "-o", protected])
        executable = build / "differential"
        run(common + [harness, plain, protected, "-o", executable])
        report["hashes"][str(executable)] = sha256(executable)
        result = run([executable])
        if not re.search(r"\bPASS cases=[1-9][0-9]*\b", result):
            raise GateError("Differential harness did not report a nonzero passing case count")
        report["differential_output"] = result
        report["status"] = "BASELINE_ONLY_PASS" if args.mode == "baseline-only" else "HOST_VMP_PASS"
        report["vmp_verified"] = args.mode == "xollvm"
        return_code = 0
    except (GateError, OSError, ValueError) as exc:
        report["status"] = "BLOCKED_OR_FAILED"
        report["error"] = str(exc)
        return_code = 1
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report_path = output / "report.json"
    # Replace the previous report atomically even on failure.
    temporary = output / (".report-" + str(os.getpid()) + ".json")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(report_path)
    print(json.dumps({"status": report["status"], "vmp_verified": report["vmp_verified"],
                      "report": str(report_path)}))
    return return_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline-only", "xollvm"), required=True)
    parser.add_argument("--output", default=str(HERE / "out"))
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--opt", default="opt")
    parser.add_argument("--plugin")
    parser.add_argument("--plugin-provenance")
    parser.add_argument("--suite", choices=("gf2", "stack"), default="gf2")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return execute(args)


if __name__ == "__main__":
    sys.exit(main())
