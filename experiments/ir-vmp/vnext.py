#!/usr/bin/env python3
"""Strict vNext policy, source identity and release-evidence gates.

Evidence is a local, hash-linked execution record, not an attestation. Unbuilt
SDK integration is deliberately ineligible even if an input claims all pass.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import uuid

from verify_sources import verify_suite

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DIMENSIONS = ("conversion", "host_semantics", "production_callpath",
              "device_semantics", "performance", "resilience")


class ValidationError(ValueError):
    pass


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValidationError("duplicate_key: " + key)
            result[key] = value
        return result
    def constant(value):
        raise ValidationError("nonfinite_number: " + value)
    data = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    def finite(value):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValidationError("nonfinite_number")
        if isinstance(value, dict):
            for item in value.values():
                finite(item)
        elif isinstance(value, list):
            for item in value:
                finite(item)
    finite(data)
    return data


def load(path):
    return strict_json(Path(path).read_text())


def schema_validate(data, filename):
    try:
        from jsonschema import Draft202012Validator, FormatChecker, validators
    except ImportError as exc:
        raise ValidationError("missing_dependency: install requirements.txt") from exc
    # JSON Schema allows 1.0 as an integer; this build contract requires JSON integer tokens.
    checker = Draft202012Validator.TYPE_CHECKER.redefine("integer", lambda c, v: type(v) is int)
    validator = validators.extend(Draft202012Validator, type_checker=checker)
    schema = load(HERE / filename)
    validator.check_schema(schema)
    errors = sorted(validator(schema, format_checker=FormatChecker()).iter_errors(data), key=str)
    if errors:
        error = errors[0]
        raise ValidationError("schema: " + "/".join(map(str, error.path)) + ": " + error.message)


def safe_file(base, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or str(path) != relative:
        raise ValidationError("illegal_path: " + relative)
    result = base / path
    if not result.is_file() or not result.resolve().is_relative_to(base.resolve()):
        raise ValidationError("missing_or_escaping_file: " + relative)
    return result


def validate_policy(path):
    policy = load(path)
    schema_validate(policy, "policy.schema.json")
    lock = load(HERE / "toolchain.lock.json")
    for name in ("backend_id", "upstream_commit", "patch_set"):
        if policy[name] != lock[name]:
            raise ValidationError("toolchain_identity: " + name)
    for filename, key in (("pointer-gep-v2.json", "patch_manifest_sha256"),
                          ("pointer-gep-v2.patch", "patch_sha256")):
        if sha256(HERE / "patches" / filename) != lock[key]:
            raise ValidationError("patch_hash: " + filename)
    if policy["profile"] == "off" and policy["required"]:
        raise ValidationError("required_off_conflict")
    if policy["profile"] in ("ir-vmp-canary", "ir-vmp-release") and policy["target_triple"] != "arm64-apple-ios14.0":
        raise ValidationError("production_requires_ios_target")
    if policy["profile"] == "ir-vmp-release" and not policy["required"]:
        raise ValidationError("release_must_be_required")
    registry = load(HERE / "candidate_registry.json")
    entries = {r["candidate_id"]: r for r in registry["candidates"]}
    if len(entries) != len(registry["candidates"]):
        raise ValidationError("duplicate_registry_candidate")
    seen = set()
    for target in policy["candidates"]:
        cid = target["candidate_id"]
        if cid in seen:
            raise ValidationError("duplicate_target: " + cid)
        seen.add(cid)
        entry = entries[cid]
        manifest = verify_suite(entry["suite"])
        for key in ("source_sha256", "body_sha256"):
            if target[key] != entry[key] or entry[key] != manifest[key]:
                raise ValidationError("source_identity: " + cid + ": " + key)
        directory = HERE / "suites" / entry["suite"]
        deps = {p.name: sha256(p) for p in sorted(directory.iterdir()) if p.is_file()}
        if target["dependencies_sha256"] != canonical_hash(deps):
            raise ValidationError("dependency_identity: " + cid)
        safe_file(ROOT, entry["source"])
    return policy


def new_evidence(policy, config_hash):
    return {
        "report_kind": "cprisk.ir-vmp.release-evidence", "schema_version": 1,
        "run_id": str(uuid.uuid4()),
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "profile": policy["profile"], "config_sha256": config_hash, "artifact_id": None,
        "artifact_manifest": None,
        "targets": [{"candidate_id": t["candidate_id"], "requested": True,
                     **{d: {"status": "not_run", "reason": "not_executed", "evidence": []}
                        for d in DIMENSIONS}, "release_eligible": False}
                    for t in policy["candidates"]],
    }


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "-" + str(uuid.uuid4()))
    temporary.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def verify_release_evidence(path, policy_path):
    policy = validate_policy(policy_path)
    report = load(path)
    schema_validate(report, "release_evidence.schema.json")
    if report["config_sha256"] != sha256(policy_path) or report["profile"] != policy["profile"]:
        raise ValidationError("evidence_config_identity")
    requested = [t["candidate_id"] for t in policy["candidates"]]
    observed = [t["candidate_id"] for t in report["targets"]]
    if len(set(observed)) != len(observed) or set(observed) != set(requested):
        raise ValidationError("missing_duplicate_or_unrequested_target")
    eligible = True
    registry = {t["candidate_id"]: t for t in load(HERE / "candidate_registry.json")["candidates"]}
    bundle = None
    base = Path(path).resolve().parent
    if report["artifact_id"] is not None:
        if report["artifact_manifest"] is None:
            raise ValidationError("missing_artifact_manifest")
        manifest_file = safe_file(base, report["artifact_manifest"])
        if sha256(manifest_file) != report["artifact_id"]:
            raise ValidationError("artifact_manifest_hash")
        bundle = load(manifest_file)
        if bundle.get("run_id") != report["run_id"] or bundle.get("config_sha256") != report["config_sha256"]:
            raise ValidationError("artifact_manifest_identity")
        expected = {(t["candidate_id"], seed) for t in policy["candidates"] for seed in policy["seeds"]}
        actual = [(r["candidate_id"], r["seed"]) for r in bundle["runs"]]
        if len(set(actual)) != len(actual) or set(actual) != expected:
            raise ValidationError("artifact_seed_or_target_coverage")
    for target in report["targets"]:
        for dimension in DIMENSIONS:
            check = target[dimension]
            if check["status"] == "pass" and (not check["evidence"] or report["artifact_id"] is None):
                raise ValidationError("pass_without_artifact_evidence: " + dimension)
            for ref in check["evidence"]:
                file = safe_file(Path(path).resolve().parent, ref["path"])
                if sha256(file) != ref["sha256"]:
                    raise ValidationError("evidence_hash_mismatch")
                record = load(file)
                # These fields prevent successful results being rebound to another
                # candidate, configuration, artifact or invocation merely by editing a summary.
                for key, value in (("candidate_id", target["candidate_id"]),
                                   ("dimension", dimension), ("run_id", report["run_id"]),
                                   ("config_sha256", report["config_sha256"]),
                                   ("artifact_id", report["artifact_id"])):
                    if not isinstance(record, dict) or record.get(key) != value:
                        raise ValidationError("evidence_identity: " + key)
                if check["status"] == "pass":
                    if dimension not in ("conversion", "host_semantics"):
                        raise ValidationError("evidence_adapter_not_implemented: " + dimension)
                    wanted = [r for r in bundle["runs"] if r["candidate_id"] == target["candidate_id"]]
                    if record.get("runs") != wanted:
                        raise ValidationError("evidence_run_coverage")
                    for run in wanted:
                        child_path = safe_file(base, run["report"])
                        if sha256(child_path) != run["sha256"]:
                            raise ValidationError("child_report_hash")
                        child = load(child_path)
                        expected_symbol = "protected_" + registry[target["candidate_id"]]["symbol"]
                        if (child.get("status") != "HOST_VMP_PASS" or child.get("vmp_verified") is not True
                                or child.get("mode") != "xollvm" or child.get("seed") != run["seed"]
                                or child.get("suite") != registry[target["candidate_id"]]["suite"]
                                or child.get("completed_cases", 0) < 10000
                                or child.get("pass_evidence", {}).get("targets") != [expected_symbol]
                                or set(child.get("ir_evidence", {})) != {expected_symbol}
                                or set(child.get("optimized_ir_evidence", {})) != {expected_symbol}
                                or child.get("preflight", {}).get("status") != "pass"):
                            raise ValidationError("child_is_not_complete_business_VM_execution")
        computed = (policy["profile"] == "ir-vmp-release" and policy["required"]
                    and report["artifact_id"] is not None
                    and registry[target["candidate_id"]]["production_enabled"] is True
                    and all(target[d]["status"] == "pass" for d in DIMENSIONS))
        if target["release_eligible"] != computed:
            raise ValidationError("forged_release_eligible")
        eligible = eligible and computed
    return eligible


def run_lab(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Invalidate any earlier status even if policy parsing fails.
    atomic_json(output / "status.json", {"status": "RUNNING", "release_eligible": False})
    atomic_json(output / "release-evidence.json", {"status": "INVALIDATED", "release_eligible": False})
    policy = validate_policy(args.policy)
    report = new_evidence(policy, sha256(args.policy))
    atomic_json(output / "release-evidence.json", report)
    if policy["profile"] == "off":
        atomic_json(output / "status.json", {"status": "UNPROTECTED", "release_eligible": False})
        return 0
    if policy["profile"] != "semantic-lab" or policy["target_triple"] != "host":
        for target in report["targets"]:
            target["production_callpath"].update(status="blocked", reason="sdk_object_integration_not_implemented")
        atomic_json(output / "release-evidence.json", report)
        raise ValidationError("production_integration_blocked: no SDK protected build is implemented")
    registry = {t["candidate_id"]: t for t in load(HERE / "candidate_registry.json")["candidates"]}
    runs = []
    for target in report["targets"]:
        cid = target["candidate_id"]
        for seed in policy["seeds"]:
            destination = output / report["run_id"] / cid / str(seed)
            command = [sys.executable, str(HERE / "run.py"), "--mode", args.mode,
                       "--suite", registry[cid]["suite"], "--seed", str(seed),
                       "--random-cases", "10000", "--cc", args.cc, "--output", str(destination)]
            if args.mode == "xollvm":
                command += ["--clang", args.clang, "--opt", args.opt]
                for flag in ("plugin", "plugin_provenance", "preflight"):
                    if getattr(args, flag): command += ["--" + flag.replace("_", "-"), str(getattr(args, flag))]
            if args.sanitize:
                command += ["--sanitize"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            child = load(destination / "report.json")
            runs.append({"candidate_id": cid, "seed": seed, "report": str((destination / "report.json").relative_to(output)),
                         "sha256": sha256(destination / "report.json"), "completed_cases": child.get("completed_cases", 0),
                         "command": command, "returncode": result.returncode})
            atomic_json(output / "baseline-runs.json", {"run_id": report["run_id"], "runs": runs})
            expected_status = "BASELINE_ONLY_PASS" if args.mode == "baseline-only" else "HOST_VMP_PASS"
            if result.returncode or child["status"] != expected_status or child["vmp_verified"] is not (args.mode == "xollvm"):
                dimension = "conversion" if "pass_evidence" not in child else "host_semantics"
                target[dimension].update(status="blocked" if "unavailable" in child.get("error", "") else "fail",
                                         reason=child.get("error", "child_failed"))
                atomic_json(output / "release-evidence.json", report)
                raise ValidationError("experiment_failed: " + cid + ": " + child.get("error", result.stderr))
        target["host_semantics"]["reason"] = "native_baseline_only; VM semantics not executed" if args.mode == "baseline-only" else "host_VM_diff_completed"
        target["device_semantics"].update(status="blocked", reason="physical_sdk_execution_not_available")
    if args.mode == "xollvm":
        lock = load(HERE / "toolchain.lock.json")
        for item in runs:
            child = load(output / item["report"])
            if (child["plugin_provenance"]["llvm_version"] != lock["llvm_version"] or
                    child["plugin_provenance"].get("local_patch_set", {}).get("id") != lock["patch_set"]):
                raise ValidationError("vnext_requires_exact_locked_toolchain_and_patch")
        manifest = {"run_id": report["run_id"], "config_sha256": report["config_sha256"],
                    "artifact_kind": "host_experiment_bundle_not_sdk", "runs": runs}
        atomic_json(output / "artifact-manifest.json", manifest)
        report["artifact_manifest"] = "artifact-manifest.json"
        report["artifact_id"] = sha256(output / "artifact-manifest.json")
        for target in report["targets"]:
            for dimension in ("conversion", "host_semantics"):
                record = {"candidate_id": target["candidate_id"], "dimension": dimension,
                          "run_id": report["run_id"], "config_sha256": report["config_sha256"],
                          "artifact_id": report["artifact_id"],
                          "runs": [r for r in runs if r["candidate_id"] == target["candidate_id"]]}
                filename = target["candidate_id"] + "-" + dimension + ".json"
                atomic_json(output / filename, record)
                target[dimension].update(status="pass", reason="all_requested_host_seeds_passed",
                                         evidence=[{"path": filename, "sha256": sha256(output / filename)}])
    atomic_json(output / "release-evidence.json", report)
    atomic_json(output / "status.json", {"status": "BASELINE_ONLY_PASS" if args.mode == "baseline-only" else "HOST_VMP_PASS", "release_eligible": False,
                                        "run_id": report["run_id"], "completed_cases": sum(r["completed_cases"] for r in runs)})
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "run", "verify-release"))
    parser.add_argument("--policy", type=Path, default=HERE / "policy.semantic-lab.json")
    parser.add_argument("--output", type=Path, default=HERE / "out-vnext")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--mode", choices=("baseline-only", "xollvm"), default="baseline-only")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--opt", default="opt")
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--plugin-provenance", type=Path)
    parser.add_argument("--preflight", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            validate_policy(args.policy)
            print("POLICY_VALID (not a protection or release result)")
            return 0
        if args.command == "verify-release":
            if args.evidence is None:
                raise ValidationError("--evidence is required")
            if not verify_release_evidence(args.evidence, args.policy):
                raise ValidationError("release_ineligible: required SDK/device/performance/resilience evidence unavailable")
            return 0
        return run_lab(args)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        if args.command == "run":
            atomic_json(args.output / "status.json", {"status": "BLOCKED_OR_FAILED", "reason": str(exc), "release_eligible": False})
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
