import Foundation
import MachOKit
import StringEncryptor
import MetadataScrubber
import DataSegmentEncryptor
import IntegrityAnchor
import StructureObfuscator
import AntiDebugInjector
import InstructionSubstitution
import ControlFlowOrchestrator
import SymbolStripper
import ImportEncryptor
import HeaderEncryptor
import TextSegmentEncryptor
import VMProtector
import Security

// MARK: - CLI Options

struct CLIOptions {
    var inputPath: String?
    var outputPath: String?
    var passes: Set<Int> = []
    var allPasses: Bool = false
    var verbose: Bool = false
    var keyHex: String?
    var keyFile: String?
    var cffPolicyPath: String?
    var vmpPolicyPath: String?
    var buildSeedRaw: String?
    /// Pass 2: `conservative` (default) or `aggressive` Swift metadata scrub.
    var metadataScrubLevelRaw: String?
    /// Pass 2: report `__TEXT.__cstring` matches for curated Swift semantic tokens (stderr + PassResult details).
    var swiftSemanticReport: Bool = false
    /// Pass 2: scrub matching `__cstring` literals (opt-in; can break string comparisons at runtime).
    var swiftSemanticScrubCString: Bool = false
    /// Pass 2: append unreferenced decoy section with fake Swift-mangled noise (best-effort).
    var swiftSemanticDecoys: Bool = false
    /// `standard` (default) or `appstore-safe` — selects default CFF/VMP YAML when paths not overridden.
    var safetyProfileRaw: String?
}

func parseArguments() -> CLIOptions {
    var options = CLIOptions()
    let args = CommandLine.arguments
    var i = 1
    while i < args.count {
        switch args[i] {
        case "--input":
            i += 1
            if i < args.count { options.inputPath = args[i] }
        case "--output":
            i += 1
            if i < args.count { options.outputPath = args[i] }
        case "--key":
            i += 1
            if i < args.count { options.keyHex = args[i] }
        case "--key-file":
            i += 1
            if i < args.count { options.keyFile = args[i] }
        case "--cff-policy":
            i += 1
            if i < args.count { options.cffPolicyPath = args[i] }
        case "--vmp-policy":
            i += 1
            if i < args.count { options.vmpPolicyPath = args[i] }
        case "--build-seed":
            i += 1
            if i < args.count { options.buildSeedRaw = args[i] }
        case "--pass1": options.passes.insert(1)
        case "--pass2": options.passes.insert(2)
        case "--pass3": options.passes.insert(3)
        case "--pass4": options.passes.insert(4)
        case "--pass5": options.passes.insert(5)
        case "--pass6": options.passes.insert(6)
        case "--pass7": options.passes.insert(7)
        case "--pass8": options.passes.insert(8)
        case "--pass9": options.passes.insert(9)
        case "--pass10": options.passes.insert(10)
        case "--pass11": options.passes.insert(11)
        case "--pass12": options.passes.insert(12)
        case "--pass13": options.passes.insert(13)
        case "--all":   options.allPasses = true
        case "--verbose": options.verbose = true
        case "--metadata-scrub-level":
            i += 1
            if i < args.count { options.metadataScrubLevelRaw = args[i] }
        case "--swift-semantic-report":
            options.swiftSemanticReport = true
        case "--swift-semantic-scrub-cstring":
            options.swiftSemanticScrubCString = true
        case "--swift-semantic-decoys":
            options.swiftSemanticDecoys = true
        case "--safety-profile":
            i += 1
            if i < args.count { options.safetyProfileRaw = args[i] }
        case "--help":
            printUsage()
            exit(0)
        default:
            fputs("Unknown option: \(args[i])\n", stderr)
        }
        i += 1
    }
    return options
}

func printUsage() {
    print("""
    Usage: cprisk-armor --input <path> --output <path> [options]

    Options:
      --input <path>    Input Mach-O binary path
      --output <path>   Output path for armored binary
      --key <hex>       32-byte encryption key as hex string (64 hex chars)
      --key-file <path> Path to file containing the raw 32-byte key
      --pass1           Pass 1: String Encryption
      --pass2           Pass 2: Metadata Scrubbing
      --pass3           Pass 3: Data Segment Encryption
      --pass4           Pass 4: Integrity Anchor
      --pass5           Pass 5: Structure Obfuscation
      --pass6           Pass 6: Symbol Stripping + export trie scrub (MH_EXECUTE)
      --pass7           Pass 7: Anti-Debug Metadata Injection
      --pass8           Pass 8: Instruction Substitution
      --pass9           Pass 9: Control Flow Orchestrator (policy-guided binary rewrite)
      --pass10          Pass 10: Import Table Encryption
      --pass11          Pass 11: Header Encryption
      --pass12          Pass 12: __TEXT.__text page encryption + metadata
      --pass13          Pass 13: VMProtector (policy-driven bytecode + entry trampoline)
      --all             Enable all passes
      --cff-policy      Override cff_policy.yaml path for Pass 9
      --vmp-policy      Override vmp_policy.yaml path for Pass 13 (default: RiskDetectorApp/vmp_policy.yaml search)
      --safety-profile standard|appstore-safe
                        Build policy profile: appstore-safe defaults to *_appstore_safe.yaml when --cff-policy/--vmp-policy omitted
      --build-seed      Build randomization seed (u64, decimal or 0x-prefixed hex)
      --metadata-scrub-level conservative|aggressive
                        Pass 2 Swift metadata: conservative (default, string payloads only)
                        or aggressive (full section overwrite; higher breakage risk)
      --swift-semantic-report
                        Pass 2: scan __TEXT.__cstring for semantic-leak tokens (details + stderr when --verbose)
      --swift-semantic-scrub-cstring
                        Pass 2: overwrite matching CString bodies in-place (same length; runtime risk)
      --swift-semantic-decoys
                        Pass 2: append `__TEXT,__cp5_swdec` with fake Swift-mangled decoys (best-effort)
      --verbose         Verbose output
      --help            Show this help

    Environment:
      CPRISK_ARMOR_KEY        Hex-encoded key (fallback when --key/--key-file not set)
      CPRISK_ARMOR_BUILD_SEED Decimal or 0x-prefixed seed for deterministic randomization (preferred override)
      CPRISK_BUILD_SEED       Legacy alias for CPRISK_ARMOR_BUILD_SEED (fallback when --build-seed is missing)
      CPRISK_METADATA_SCRUB_LEVEL  Pass 2: conservative (default) or aggressive
                        (aggressive overwrites non-`__swift5_types` ancillary sections in full; may break reflection / some dynamic features)
      CPRISK_SWIFT_SEMANTIC_REPORT=1  Pass 2: same as --swift-semantic-report
      CPRISK_SWIFT_SEMANTIC_SCRUB_CSTRING=1  Pass 2: same as --swift-semantic-scrub-cstring
      CPRISK_SWIFT_SEMANTIC_DECOYS=1  Pass 2: same as --swift-semantic-decoys

    Swift metadata (compile-time, complements Pass 2):
      Xcode project/target: set SWIFT_REFLECTION_METADATA_LEVEL=minimal (default in this repo’s
        project-level Debug/Release — reduces refl/__swift5_*-derived strings vs. full metadata).
      SwiftPM (Release only): CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1 enables -disable-reflection-metadata
        and -disable-reflection-names in Package.swift (stronger than minimal; test before shipping).

    Pass 13 (VMProtector) — choosing --input:
      Pass 13 resolves policy names from vmp_policy.yaml by matching the Mach-O symbol table. If the
      input is stripped (typical for many shipping app executables), Swift/C symbols may be missing
      and targets will not resolve — this is usually not a policy typo, but a stripped symtab.
      Debug Xcode builds often place much Swift code in a separate companion binary (e.g.
      <Product>.debug.dylib under .../Objects-normal/<arch>/Binary/) that still carries symbols.
      For development and policy validation, prefer an unstripped intermediate Mach-O or that
      debug dylib as --input. For fat/universal files, ensure the slice matches the target arch.

    A key is REQUIRED when any encryption pass (1, 3, 4, 12) or --all is enabled.
    """)
}

/// Resolve the encryption key from CLI flags or environment variable.
/// Priority: --key > --key-file > CPRISK_ARMOR_KEY env var.
func resolveEncryptionKey(from options: CLIOptions) -> Data? {
    if let hex = options.keyHex {
        return dataFromHex(hex)
    }
    if let path = options.keyFile {
        guard let raw = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return Data(raw.prefix(ArmorABI.keySize))
    }
    if let envHex = ProcessInfo.processInfo.environment["CPRISK_ARMOR_KEY"] {
        return dataFromHex(envHex)
    }
    return nil
}

private func dataFromHex(_ hex: String) -> Data? {
    let cleaned = hex.trimmingCharacters(in: .whitespacesAndNewlines)
    guard cleaned.count == ArmorABI.keySize * 2 else { return nil }

    var data = Data(capacity: ArmorABI.keySize)
    var index = cleaned.startIndex
    for _ in 0..<ArmorABI.keySize {
        let nextIndex = cleaned.index(index, offsetBy: 2)
        guard let byte = UInt8(cleaned[index..<nextIndex], radix: 16) else { return nil }
        data.append(byte)
        index = nextIndex
    }
    return data
}

enum BuildSeedOrigin: String {
    case cli = "cli"
    case env = "env"
    case random = "random"
}

struct BuildSeedResolution {
    let seed: UInt64
    let origin: BuildSeedOrigin
}

private func parseBuildSeed(_ raw: String) -> UInt64? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    if trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") {
        return UInt64(trimmed.dropFirst(2), radix: 16)
    }
    return UInt64(trimmed, radix: 10)
}

private func secureRandomSeed() throws -> UInt64 {
    var randomBytes: UInt64 = 0
    let status = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt64>.size, &randomBytes)
    if status != errSecSuccess {
        throw NSError(
            domain: "cprisk-armor",
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed with status \(status)"]
        )
    }
    return randomBytes == 0 ? 1 : randomBytes
}

/// Resolve Pass 2 Swift metadata scrub level: CLI > env > conservative (default).
private func resolveSwiftMetadataScrubLevel(from options: CLIOptions) -> SwiftMetadataScrubLevel {
    if let raw = options.metadataScrubLevelRaw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        if raw == "aggressive" { return .aggressive }
        return .conservative
    }
    if let env = ProcessInfo.processInfo.environment["CPRISK_METADATA_SCRUB_LEVEL"]?
        .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    {
        if env == "aggressive" { return .aggressive }
    }
    return .conservative
}

/// Pass 2 optional Swift semantic CString scan / scrub / decoys: CLI flags OR env toggles.
private func resolveSwiftSemanticLeakOptions(from options: CLIOptions) -> SwiftSemanticLeakOptions {
    func envBool(_ key: String) -> Bool {
        let v = ProcessInfo.processInfo.environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return v == "1" || v == "true" || v == "yes"
    }
    return SwiftSemanticLeakOptions(
        reportCStringSemanticMatches: options.swiftSemanticReport || envBool("CPRISK_SWIFT_SEMANTIC_REPORT"),
        scrubCStringSemanticMatches: options.swiftSemanticScrubCString
            || envBool("CPRISK_SWIFT_SEMANTIC_SCRUB_CSTRING"),
        injectSemanticDecoys: options.swiftSemanticDecoys || envBool("CPRISK_SWIFT_SEMANTIC_DECOYS")
    )
}

private func resolveBuildSeed(from options: CLIOptions) throws -> BuildSeedResolution {
    if let cliRaw = options.buildSeedRaw {
        guard let parsed = parseBuildSeed(cliRaw) else {
            throw NSError(
                domain: "cprisk-armor",
                code: 1001,
                userInfo: [NSLocalizedDescriptionKey: "invalid --build-seed value '\(cliRaw)'"]
            )
        }
        return BuildSeedResolution(seed: parsed == 0 ? 1 : parsed, origin: .cli)
    }

    if let envRaw = ProcessInfo.processInfo.environment["CPRISK_ARMOR_BUILD_SEED"] {
        guard let parsed = parseBuildSeed(envRaw) else {
            throw NSError(
                domain: "cprisk-armor",
                code: 1002,
                userInfo: [NSLocalizedDescriptionKey: "invalid CPRISK_ARMOR_BUILD_SEED value '\(envRaw)'"]
            )
        }
        return BuildSeedResolution(seed: parsed == 0 ? 1 : parsed, origin: .env)
    }

    if let envRaw = ProcessInfo.processInfo.environment["CPRISK_BUILD_SEED"] {
        guard let parsed = parseBuildSeed(envRaw) else {
            throw NSError(
                domain: "cprisk-armor",
                code: 1003,
                userInfo: [NSLocalizedDescriptionKey: "invalid CPRISK_BUILD_SEED value '\(envRaw)'"]
            )
        }
        return BuildSeedResolution(seed: parsed == 0 ? 1 : parsed, origin: .env)
    }

    return BuildSeedResolution(seed: try secureRandomSeed(), origin: .random)
}

// MARK: - Main

let options = parseArguments()

guard let inputPath = options.inputPath else {
    fputs("Error: --input is required\n", stderr)
    printUsage()
    exit(1)
}

let outputPath = options.outputPath ?? (inputPath + "_armored")
let verbose = options.verbose
let enabledPasses: Set<Int> = options.allPasses ? [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13] : options.passes

if enabledPasses.isEmpty {
    fputs("Warning: No passes enabled. Use --all or --passN flags.\n", stderr)
}

// Pass 3 (Data Segment Encryption) depends on Pass 4 (Integrity Anchor) for loader descriptor layout.
if enabledPasses.contains(3) && !enabledPasses.contains(4) {
    fputs("Error: --pass3 (Data Segment Encryption) requires --pass4 (Integrity Anchor).\n", stderr)
    fputs("Enable both with --pass3 --pass4 or use --all.\n", stderr)
    exit(1)
}

if enabledPasses.contains(12) && !enabledPasses.contains(4) {
    fputs("Error: --pass12 requires --pass4 (Integrity Anchor).\n", stderr)
    fputs("Enable both with --pass12 --pass4 or use --all.\n", stderr)
    exit(1)
}

let encryptionPassIDs: Set<Int> = [1, 3, 4, 10, 11, 12]
let needsKey = !enabledPasses.isDisjoint(with: encryptionPassIDs)
let keyData = resolveEncryptionKey(from: options)

if needsKey && keyData == nil {
    fputs("Error: encryption passes (1, 3, 4, 10, 11, 12) require a key.\n", stderr)
    fputs("Provide one via --key <hex>, --key-file <path>, or CPRISK_ARMOR_KEY env var.\n", stderr)
    exit(1)
}

if let key = keyData, key.allSatisfy({ $0 == 0 }) {
    fputs("Error: all-zero key rejected — the armor chain would be trivially reversible.\n", stderr)
    exit(1)
}

let buildSeed: BuildSeedResolution
do {
    buildSeed = try resolveBuildSeed(from: options)
} catch {
    fputs("Error: \(error.localizedDescription)\n", stderr)
    exit(1)
}

let safetyProfile: ArmorSafetyProfile
if let raw = options.safetyProfileRaw?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
    guard let parsed = ArmorSafetyProfile(cliToken: raw) else {
        fputs("Error: invalid --safety-profile '\(raw)' (use standard or appstore-safe)\n", stderr)
        exit(1)
    }
    safetyProfile = parsed
} else {
    safetyProfile = .standard
}

let resolvedCffPolicyPath: String? = options.cffPolicyPath ?? (
    safetyProfile == .appStoreSafe ? ArmorPolicyPathResolver.resolveDefaultCffPolicyPath(profile: safetyProfile) : nil
)
let resolvedVmpPolicyPath: String? = options.vmpPolicyPath ?? (
    safetyProfile == .appStoreSafe ? ArmorPolicyPathResolver.resolveDefaultVmpPolicyPath(profile: safetyProfile) : nil
)

if safetyProfile == .appStoreSafe {
    if enabledPasses.contains(9), resolvedCffPolicyPath == nil {
        fputs(
            "Error: --safety-profile appstore-safe requires cff_policy_appstore_safe.yaml (or pass --cff-policy)\n",
            stderr
        )
        exit(1)
    }
    if enabledPasses.contains(13), resolvedVmpPolicyPath == nil {
        fputs(
            "Error: --safety-profile appstore-safe requires vmp_policy_appstore_safe.yaml (or pass --vmp-policy)\n",
            stderr
        )
        exit(1)
    }
}

do {
    let inputURL = URL(fileURLWithPath: inputPath)
    let outputURL = URL(fileURLWithPath: outputPath)

    if verbose { print("[*] Loading Mach-O: \(inputPath)") }
    let machoFile = try MachOFile(url: inputURL)

    let metadataScrubLevel = resolveSwiftMetadataScrubLevel(from: options)
    let swiftSemanticLeak = resolveSwiftSemanticLeakOptions(from: options)
    let config = PassConfig(
        verbose: verbose,
        encryptionKey: keyData,
        randomSeed: buildSeed.seed,
        buildSeed: buildSeed.seed,
        swiftMetadataScrubLevel: metadataScrubLevel,
        swiftSemanticLeakOptions: swiftSemanticLeak
    )

    if verbose {
        let validity = machoFile.header.isValid ? "valid" : "INVALID"
        print("[*] Header: \(validity) | Commands: \(machoFile.header.numberOfCommands) | Type: \(machoFile.header.fileType)")
        print("[*] Segments: \(try machoFile.segments().map(\.name).joined(separator: ", "))")
        if keyData != nil { print("[*] Encryption key: provided (\(ArmorABI.keySize) bytes)") }
        print(String(format: "[*] Build seed: 0x%016llX (%@)", buildSeed.seed, buildSeed.origin.rawValue))
        print("[*] Safety profile: \(safetyProfile.rawValue)")
        if let p = resolvedCffPolicyPath { print("[*] CFF policy path: \(p)") }
        if let p = resolvedVmpPolicyPath { print("[*] VMP policy path: \(p)") }
        print(
            "[*] Pass 2 semantic leak: report=\(swiftSemanticLeak.reportCStringSemanticMatches) scrub_cstring=\(swiftSemanticLeak.scrubCStringSemanticMatches) decoys=\(swiftSemanticLeak.injectSemanticDecoys)"
        )
    }

    var allResults = [PassResult]()
    let passes: [(Int, ArmorPass)] = [
        (1, StringEncryptorPass()),
        (2, MetadataScrubberPass()),
        (8, InstructionSubstitutionPass()),
        (4, IntegrityAnchorPass()),
        (3, DataSegmentEncryptorPass()),
        (11, HeaderEncryptorPass()),
        (5, StructureObfuscatorPass()),
        (7, AntiDebugInjectorPass()),
        (9, ControlFlowOrchestratorPass(policyFilePath: resolvedCffPolicyPath)),
        (10, ImportEncryptorPass()),
        (13, VMProtectorPass(policyFilePath: resolvedVmpPolicyPath)),
        (12, TextSegmentEncryptorPass()),
        (6, SymbolStripperPass()),
        (6, ExportTrieScrubberPass()),
    ]

    for (index, pass) in passes {
        guard enabledPasses.contains(index) else { continue }
        if verbose { print("[*] Running Pass \(index): \(pass.name)") }
        let result = try pass.execute(on: machoFile, config: config)
        allResults.append(result)
        if verbose {
            print("    Items: \(result.itemsProcessed) | Bytes: \(result.bytesModified)")
            for detail in result.details { print("    - \(detail)") }
        }
    }

    // Always attempt __objc_data2 scrub after selected passes.
    // This keeps metadata clean even when users skip Pass 7 but input binary already contains the section.
    if !enabledPasses.isEmpty {
        let scrubPass = ObjCData2ScrubberPass()
        if verbose { print("[*] Running Post Pass: \(scrubPass.name)") }
        let scrubResult = try scrubPass.execute(on: machoFile, config: config)
        allResults.append(scrubResult)
        if verbose {
            print("    Items: \(scrubResult.itemsProcessed) | Bytes: \(scrubResult.bytesModified)")
            for detail in scrubResult.details { print("    - \(detail)") }
        }
    }

    let writeValidation = try machoFile.write(to: outputURL)

    print("[+] Armored binary written to: \(outputPath)")
    if verbose {
        let codesignState = writeValidation.codeSignatureWasInvalidated ? "invalidated" : "unchanged"
        print("[*] Write validation: \(writeValidation.report.segmentCount) segments, \(writeValidation.report.sectionCount) sections, code signature \(codesignState)")
    }
    print("[+] Summary:")
    for result in allResults {
        print("    \(result.passName): \(result.itemsProcessed) items, \(result.bytesModified) bytes modified")
    }
} catch {
    fputs("Error: \(error)\n", stderr)
    exit(1)
}
