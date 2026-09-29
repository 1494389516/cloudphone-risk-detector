#!/usr/bin/env python3
"""Build an external SwiftPM consumer and run frozen wire compatibility checks."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory(prefix="local-assessment-contract-") as directory:
    package = Path(directory)
    sdk_path = json.dumps(str(ROOT / "RiskDetectorApp"))
    (package / "Package.swift").write_text(f'''// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "LocalAssessmentContract",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: {sdk_path})],
    targets: [.executableTarget(
        name: "CompatibilityCheck",
        dependencies: [.product(name: "CloudPhoneRiskKit", package: "RiskDetectorApp")]
    )]
)
''')
    source = package / "Sources/CompatibilityCheck"
    source.mkdir(parents=True)
    (source / "CompatibilityCheck.swift").write_text(
        (ROOT / "contracts/local_assessment_compatibility.swift").read_text()
    )
    subprocess.run(["swift", "run", "--package-path", str(package), "CompatibilityCheck"], check=True)
