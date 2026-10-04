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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "verify-release"))
    parser.add_argument("--policy", type=Path, default=HERE / "policy.semantic-lab.json")
    parser.add_argument("--evidence", type=Path)
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
    except (OSError, ValueError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
