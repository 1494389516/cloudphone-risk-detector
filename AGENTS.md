# AGENTS.md

## Cursor Cloud specific instructions

### Project Overview

CloudPhoneRiskKit is a **pure iOS/macOS Swift SDK** for mobile device environment risk detection (jailbreak, cloud phone, hook injection, debugging/tampering). It includes:

- `CloudPhoneRiskKit` — Core SDK library (Swift Package)
- `CloudPhoneRiskAppCore` — App-layer wrapper
- `RiskDetectorApp` — SwiftUI demo application

The Swift Package is located at `RiskDetectorApp/Package.swift`. There are **no external dependencies** and **no test targets** defined.

### Platform Limitations (Linux Cloud VM)

This project **requires macOS + Xcode 15+** for full build and testing. It relies heavily on Apple-only frameworks (UIKit, Security, CryptoKit, Metal, CoreMotion, Darwin/Mach kernel APIs). On the Linux Cloud VM:

- **`swift build` will fail** — The code imports `Darwin` and Apple-only frameworks with no Linux fallbacks.
- **`swift package resolve`** and **`swift package dump-package`** work fine for validating the package structure.
- **`swiftlint lint`** works for code quality checks (run from `RiskDetectorApp/` directory).
- There are no automated tests (`XCTest` targets) defined in `Package.swift`.
- The demo app (`RiskDetectorApp`) requires an iOS Simulator or physical device to run.

### Available Commands on Linux

| Command | Working Directory | Purpose |
|---------|-------------------|---------|
| `swift package resolve` | `RiskDetectorApp/` | Validate package dependencies resolve |
| `swift package dump-package` | `RiskDetectorApp/` | Validate Package.swift structure |
| `swiftlint lint` | `RiskDetectorApp/` | Run SwiftLint code quality checks (expect pre-existing warnings/errors) |

### Pre-existing Lint Issues

The codebase has ~1226 SwiftLint violations (157 errors, 1069 warnings) using default rules. These are pre-existing and not caused by any agent changes. No `.swiftlint.yml` configuration file exists in the repo.

### For Full Development

Full build, run, and testing requires:
- macOS 14.0+ with Xcode 15.0+
- iOS 14.0+ deployment target
- Swift 5.9+
- See `README.md` for integration and usage instructions
