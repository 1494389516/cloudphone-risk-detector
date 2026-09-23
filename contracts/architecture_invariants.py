#!/usr/bin/env python3
"""Small, non-optional architecture gates kept even when broad test suites move."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def require(path, *needles):
    text = (ROOT / path).read_text(encoding="utf-8")
    missing = [item for item in needles if item not in text]
    if missing:
        raise SystemExit(f"{path}: missing architecture invariant(s): {missing}")

require(
    "RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/CollectorClient.swift",
    'path: "/attestation/challenge"',
    'path: "/attestation/enroll"',
    'path: "/reports"',
    "AppAttestSigner.submitCollectorReport",
    'scheme?.lowercased() == "https"',
)
require(
    "RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/AppAttestSigner.swift",
    "private static let uploadGate = TransactionGate()",
    "private static let initializationGate = TransactionGate()",
    "case keychainFailure(OSStatus)",
)
require(
    "RiskDetectorApp/Sources/CloudPhoneRiskAppCore/RiskDetectionService.swift",
    "submitToCollector(",
    "report.sceneTag",
)
require(
    "contracts/README.md",
    "retry the identical serialized upload",
    "Keychain reads/writes fail closed",
)
print("SDK architecture invariants: PASS")
