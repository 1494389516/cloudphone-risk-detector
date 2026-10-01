#!/usr/bin/env python3
"""Build a separate iPhoneOS Release App; only device-returned evidence can pass."""
import argparse
import datetime
import fnmatch
import importlib.util
import json
import math
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
sys.path.insert(0, str(EXPERIMENT))
spec = importlib.util.spec_from_file_location("ir_vmp_host", EXPERIMENT / "run.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


def check_device_result(data, run_id):
    def integer(value, expected):
        return type(value) is int and value == expected

    if not isinstance(data, dict) or not isinstance(data.get("concurrent"), list):
        raise host.GateError("Device result must contain an object and a concurrent array")
    seeds = [0x783cb86db73074ac] + [0x783cb86db73074ac ^ ((i + 1) << 32) for i in range(4)]
    rows = [data.get("serial")] + data["concurrent"]
    elapsed = data.get("elapsed_seconds")
    if (not integer(data.get("schema_version"), 1) or data.get("run_id") != run_id
            or data.get("status") != "PASS" or data.get("configuration") != "Release"
            or data.get("physical_device") is not True or data.get("model") != "iPhone"
            or not integer(data.get("thread_error"), 0) or not integer(data.get("workers_ready"), 4)
            or data.get("start_gate_used") is not True
            or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed <= 0
            or len(rows) != 5 or any(not isinstance(row, dict)
                or not integer(row.get("returncode"), 0) or not integer(row.get("cases"), 4096)
                or not integer(row.get("known_answer_checks"), 8) or not integer(row.get("failure_line"), 0)
                or row.get("seed") != f"{seed:016x}" for row, seed in zip(rows, seeds))):
        raise host.GateError("Device result failed run identity, physical-device, differential or concurrency gates")


def check_devicectl_result(path, require_clean_exit=False):
    data = json.loads(path.read_text())
    if (not isinstance(data, dict) or not isinstance(data.get("info"), dict)
            or data["info"].get("outcome") != "success" or not isinstance(data.get("result"), dict)):
        raise host.GateError("devicectl JSON does not prove command success: " + str(path))
    if require_clean_exit:
        termination = data["result"].get("terminationResult")
        if (not isinstance(termination, dict) or type(termination.get("exitCode")) is not int
                or termination["exitCode"] != 0 or termination.get("terminatingSignal") is not None
                or termination.get("wasCoreDumpCreated") is not False):
            raise host.GateError("devicectl launch JSON does not prove clean App exit: " + str(path))
    return data


def execute(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "mode": args.mode, "status": "RUNNING",
              "iphone_release_verified": False, "device_executed": False,
              "configuration": "Release", "target": "arm64-apple-ios15.0",
              "run_id": str(uuid.uuid4()), "commands": [], "hashes": {},
              "scope": "isolated GF2 app only; no production SDK integration or Pass 13 changes"}
    started = time.monotonic()

    def write_report():
        report_path = output / "report.json"
        temporary = output / (".report-" + report["run_id"] + ".json")
        temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        temporary.replace(report_path)
        return report_path

    # Invalidate a prior success before invoking tools; even an interrupted run
    # must not leave an older device pass looking like the current result.
    write_report()

    def run(command):
        entry = {"argv": [str(arg) for arg in command]}
        report["commands"].append(entry)
        try:
            result = subprocess.run(entry["argv"], text=True, capture_output=True,
                                    cwd=HERE, timeout=args.timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            entry["error"] = str(exc)
            raise host.GateError(str(exc)) from exc
        entry.update(returncode=result.returncode, stderr=result.stderr)
        if len(result.stdout) > 20000:
            log = output / ("command-" + report["run_id"] + "-" + str(len(report["commands"])) + ".stdout")
            log.write_text(result.stdout)
            entry["stdout_path"] = str(log)
        else:
            entry["stdout"] = result.stdout
        if result.returncode:
            raise host.GateError("Command failed: " + " ".join(entry["argv"]))
        return result.stdout

    try:
        build = Path(tempfile.mkdtemp(prefix="build-", dir=output))
        report["build_directory"] = str(build)
        root = Path(args.llvm_root).resolve()
        clang, opt, objdump = (root / "bin" / tool for tool in ("clang", "opt", "llvm-objdump"))
        version = host.check_versions(run([clang, "--version"]), run([opt, "--version"]))
        plugin = Path(args.plugin).resolve()
        report["plugin_provenance"] = host.check_provenance(args.plugin_provenance, plugin, version)
        report["xcode_version"] = run(["xcodebuild", "-version"])
        sdk = run(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]).strip()
        apple_clang = run(["xcrun", "--sdk", "iphoneos", "--find", "clang"]).strip()
        report["apple_clang_version"] = run([apple_clang, "--version"])
        report["sdk"] = sdk
        run([sys.executable, EXPERIMENT / "verify_sources.py"])
        for source in (HERE / "run.py", HERE / "main.m", HERE / "differential.c", HERE / "differential.h",
                       EXPERIMENT / "run.py", EXPERIMENT / "gf2_candidates.c", EXPERIMENT / "gf2_candidates.inc",
                       EXPERIMENT / "sources.json", EXPERIMENT / "verify_sources.py"):
            report["hashes"][str(source)] = host.sha256(source)
        target = ["-target", report["target"], "-isysroot", sdk]
        candidate = EXPERIMENT / "gf2_candidates.c"
        before, after, optimized = (build / name for name in ("before.ll", "after.ll", "optimized.ll"))
        run([clang, *target, "-std=c11", "-O0", "-Xclang", "-disable-O0-optnone",
             "-Wall", "-Wextra", "-Werror", "-DCPRISK_VMP_PREFIX=protected_", "-DCPRISK_VMP_PROTECTED=1",
             "-S", "-emit-llvm", candidate, "-o", before])
        passes = build / "pass-reports"
        passes.mkdir()
        run([opt, "-load-pass-plugin=" + str(plugin), "-passes=obfuscation", "-obf-seed=1",
             "-obf-deterministic", "-obf-verify", "-obf-report-dir=" + str(passes), "-S", before, "-o", after])
        run([opt, "-passes=verify", "-disable-output", after])
        report["pass_evidence"] = host.inspect_pass_reports(passes, host.GF2_TARGETS)
        report["ir_evidence"] = host.inspect_ir(before.read_text(), after.read_text())
        run([opt, "-passes=default<O2>", "-S", after, "-o", optimized])
        run([opt, "-passes=verify", "-disable-output", optimized])
        report["optimized_ir_evidence"] = host.inspect_ir(before.read_text(), optimized.read_text(), require_entry=False)
        protected, plain = build / "protected.o", build / "plain.o"
        run([clang, *target, "-O0", "-c", optimized, "-o", protected])
        release = [apple_clang, *target, "-O2", "-DNDEBUG", "-Wall", "-Wextra", "-Werror"]
        run([*release, "-DCPRISK_VMP_PREFIX=plain_", "-c", candidate, "-o", plain])
        app = build / "IRVMPRelease.app"
        app.mkdir()
        binary = app / "IRVMPRelease"
        run([*release, "-fobjc-arc", HERE / "main.m", HERE / "differential.c", plain, protected,
             "-framework", "UIKit", "-framework", "Foundation", "-Wl,-no_adhoc_codesign", "-o", binary])
        plist = {"CFBundleIdentifier": args.bundle_id, "CFBundleExecutable": binary.name,
                 "CFBundleName": "IR-VMP Release", "CFBundlePackageType": "APPL",
                 "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
                 "MinimumOSVersion": "15.0", "CFBundleSupportedPlatforms": ["iPhoneOS"],
                 "UIDeviceFamily": [1], "UIRequiredDeviceCapabilities": ["arm64"],
                 "LSRequiresIPhoneOS": True, "UILaunchScreen": {}, "CPRiskRunID": report["run_id"]}
        (app / "Info.plist").write_bytes(plistlib.dumps(plist))
        # Check the linked executable, not just the intermediate object or IR.
        asm = run([objdump, "--disassemble", "--no-show-raw-insn", binary])
        (build / "final.asm").write_text(asm)
        machine = {}
        for name in host.GF2_TARGETS:
            match = re.search(r"^[0-9a-f]+ <_" + re.escape(name) + r">:\n(.*?)(?=\n[0-9a-f]+ <|\Z)", asm, re.M | re.S)
            if not match or not re.search(r"\bbl\s+[^\n]*<___vm_engine>", match.group(1)):
                raise host.GateError("Final linked wrapper does not call VM engine: " + name)
            machine[name] = {"direct_vm_engine_call": True}
        report["machine_code_evidence"] = machine
        load_commands = run(["xcrun", "otool", "-l", binary])
        (build / "load-commands.txt").write_text(load_commands)
        if not re.search(r"cmd LC_BUILD_VERSION\s+cmdsize \d+\s+platform (?:2|IOS)\s+minos 15\.0\b", load_commands):
            raise host.GateError("Final binary is not the expected iOS 15 arm64 build")
        report.update(app_path=str(app), unsigned_binary_bytes=binary.stat().st_size,
                      build_verified=True, status="IOS_RELEASE_APP_BUILD_PASS")
        for artifact in (before, after, optimized, protected, plain, binary, app / "Info.plist"):
            report["hashes"][str(artifact)] = host.sha256(artifact)
        if args.mode == "device":
            if not args.device or not args.identity or not args.profile:
                raise host.GateError("Device execution requires --device, --identity and --profile; unsigned build is not a device pass")
            profile_path = Path(args.profile).resolve()
            profile = plistlib.loads(run(["security", "cms", "-D", "-i", profile_path]).encode())
            entitlement = profile["Entitlements"]
            prefix = profile["ApplicationIdentifierPrefix"][0]
            identifier = prefix + "." + args.bundle_id
            if not fnmatch.fnmatchcase(identifier, entitlement["application-identifier"]):
                raise host.GateError("Provisioning profile does not match bundle identifier")
            if profile["ExpirationDate"] < datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
                raise host.GateError("Provisioning profile has expired")
            signing_entitlements = dict(entitlement)
            signing_entitlements["application-identifier"] = identifier
            if "keychain-access-groups" in signing_entitlements:
                signing_entitlements["keychain-access-groups"] = [group.replace("*", args.bundle_id)
                                                               for group in signing_entitlements["keychain-access-groups"]]
            entitlements_path = build / "entitlements.plist"
            entitlements_path.write_bytes(plistlib.dumps(signing_entitlements))
            shutil.copy2(profile_path, app / "embedded.mobileprovision")
            run(["codesign", "--force", "--sign", args.identity, "--entitlements", entitlements_path, app])
            run(["codesign", "--verify", "--strict", "--verbose=2", app])
            report["signed_binary_sha256"] = host.sha256(binary)
            report["profile_sha256"] = host.sha256(profile_path)
            report["device"] = args.device
            run(["xcrun", "devicectl", "device", "install", "app", "--device", args.device,
                 "--json-output", build / "install.json", app])
            report["device_commands"] = {"install": check_devicectl_result(build / "install.json")}
            run(["xcrun", "devicectl", "device", "process", "launch", "--device", args.device,
                 "--terminate-existing", "--console", "--json-output", build / "launch.json", args.bundle_id])
            report["device_commands"]["launch"] = check_devicectl_result(build / "launch.json", require_clean_exit=True)
            device_report = build / "device-result.json"
            run(["xcrun", "devicectl", "device", "copy", "from", "--device", args.device,
                 "--domain-type", "appDataContainer", "--domain-identifier", args.bundle_id,
                 "--source", "Documents/report-" + report["run_id"] + ".json",
                 "--destination", device_report, "--json-output", build / "copy.json"])
            report["device_commands"]["copy"] = check_devicectl_result(build / "copy.json")
            data = json.loads(device_report.read_text())
            report["device_result"] = data
            report["device_executed"] = True
            check_device_result(data, report["run_id"])
            report.update(status="IPHONE_RELEASE_VMP_PASS", iphone_release_verified=True)
        return_code = 0
    except Exception as exc:
        report.update(status="BLOCKED_OR_FAILED", error=str(exc), error_type=type(exc).__name__,
                      iphone_release_verified=False)
        return_code = 1
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report_path = write_report()
    print(json.dumps({key: report[key] for key in ("status", "iphone_release_verified", "device_executed")} | {"report": str(report_path)}))
    return return_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("build-only", "device"), default="build-only")
    parser.add_argument("--llvm-root", default="/opt/homebrew/opt/llvm@22")
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--plugin-provenance", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bundle-id", default="com.cprisk.irvmp.release")
    parser.add_argument("--device")
    parser.add_argument("--identity", help="Existing codesigning identity; never creates or downloads one")
    parser.add_argument("--profile", help="Matching existing iPhone provisioning profile")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return execute(args)


if __name__ == "__main__":
    sys.exit(main())
