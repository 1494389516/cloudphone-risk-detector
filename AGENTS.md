# AGENTS.md

## Cursor Cloud specific instructions

### Project Overview

CloudPhoneRiskKit is a **pure iOS/macOS Swift SDK** for mobile device environment risk detection (jailbreak, cloud phone, hook injection, debugging/tampering). It includes:

- `CloudPhoneRiskKit` — Core SDK library (Swift Package)
- `CloudPhoneRiskAppCore` — App-layer wrapper
- `RiskDetectorApp` — SwiftUI demo application

The Swift Package is at `RiskDetectorApp/Package.swift`. There are **no external dependencies**. Test target `CloudPhoneRiskKitTests` is defined and covers core scoring/decision logic.

### Platform Limitations (Linux Cloud VM)

This project **requires macOS + Xcode 15+** for full build and testing. It relies heavily on Apple-only frameworks (UIKit, Security, CryptoKit, Metal, CoreMotion, Darwin/Mach kernel APIs). On the Linux Cloud VM:

- **`swift build` will fail** — CryptoKit and other Apple-only frameworks are unavailable on Linux.
- **`swift package resolve`** and **`swift package dump-package`** work for validating the package structure.
- **`swiftlint lint`** works for code quality checks (run from `RiskDetectorApp/` directory).
- **`swift test` will fail on Linux** — tests depend on CloudPhoneRiskKit which requires Apple frameworks. Tests run in CI on macOS via GitHub Actions.
- The demo app requires an iOS Simulator or physical device to run.

### Available Commands on Linux

| Command | Working Directory | Purpose |
|---------|-------------------|---------|
| `swift package resolve` | `RiskDetectorApp/` | Validate package dependencies resolve |
| `swift package dump-package` | `RiskDetectorApp/` | Validate Package.swift structure |
| `swiftlint lint` | `RiskDetectorApp/` | Run SwiftLint (0 serious violations expected with `.swiftlint.yml`) |

### SwiftLint

A `.swiftlint.yml` is configured in `RiskDetectorApp/`. Current state: **0 serious violations, ~89 warnings**. Rules are tuned for a security SDK (short identifiers allowed, relaxed complexity limits for detection logic).

### CI/CD

GitHub Actions workflow at `.github/workflows/ci.yml`:
- **build-and-test**: macOS 14 + Xcode 15.4 — `swift build` + `swift test`
- **swiftlint**: Ubuntu — lint with `--strict` mode

### For Full Development

Full build, run, and testing requires:
- macOS 14.0+ with Xcode 15.0+
- iOS 14.0+ deployment target
- Swift 5.9+
- See `README.md` for integration and usage instructions
