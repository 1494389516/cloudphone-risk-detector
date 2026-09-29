#!/usr/bin/env python3
"""Small, non-optional architecture gates kept even when broad test suites move."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def check_signal_vocabulary():
    """Check declaration ownership and actual Xcode source-phase membership."""
    sources = ROOT / "RiskDetectorApp/Sources/CloudPhoneRiskKit"
    vocabulary = sources / "Risk/RiskSignalVocabulary.swift"
    for kind, name in (("enum", "SignalID"), ("enum", "SignalCategory"),
                       ("enum", "RiskSignalState"), ("struct", "RiskSignal")):
        declaration = re.compile(rf"^public {kind} {name}\b", re.MULTILINE)
        owners = [path for path in sources.rglob("*.swift")
                  if declaration.search(path.read_text(encoding="utf-8"))]
        if owners != [vocabulary]:
            raise SystemExit(f"{name}: expected one definition in {vocabulary}, got {owners}")

    project = (ROOT / "RiskDetectorApp/RiskDetectorApp.xcodeproj/project.pbxproj").read_text()
    # Remove comments so a filename mentioned in a comment cannot satisfy the gate.
    project = re.sub(r"/\*.*?\*/", "", project, flags=re.DOTALL)
    objects = dict(re.findall(r"([A-F0-9]{24})\s*=\s*\{([^{}]*)\};", project))

    def field(body, name):
        match = re.search(rf"\b{name}\s*=\s*([^;]+);", body)
        return match.group(1).strip().strip('"') if match else None

    def references(body, name):
        match = re.search(rf"\b{name}\s*=\s*\((.*?)\);", body, re.DOTALL)
        return re.findall(r"[A-F0-9]{24}", match.group(1)) if match else []

    def one(items, label):
        if len(items) != 1:
            raise SystemExit(f"signal vocabulary: expected one {label}, got {items}")
        return items[0]

    file_id = one([key for key, body in objects.items()
                   if field(body, "isa") == "PBXFileReference"
                   and field(body, "path") == "RiskSignalVocabulary.swift"], "file reference")
    one([key for key, body in objects.items()
         if field(body, "isa") == "PBXGroup" and field(body, "path") == "Risk"
         and file_id in references(body, "children")], "Risk group membership")
    target = one([body for body in objects.values()
                  if field(body, "isa") == "PBXNativeTarget"
                  and field(body, "name") == "CloudPhoneRiskKit"], "SDK target")
    compiled = []
    for phase_id in references(target, "buildPhases"):
        phase = objects.get(phase_id, "")
        if field(phase, "isa") == "PBXSourcesBuildPhase":
            for build_id in references(phase, "files"):
                build = objects.get(build_id, "")
                if field(build, "isa") == "PBXBuildFile" and field(build, "fileRef") == file_id:
                    compiled.append(build_id)
    one(compiled, "SDK compile-source entry")


check_signal_vocabulary()

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
