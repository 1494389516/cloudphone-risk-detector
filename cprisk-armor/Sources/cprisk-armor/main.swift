import Foundation
import MachOKit
import StringEncryptor
import MetadataScrubber
import DataSegmentEncryptor
import IntegrityAnchor
import StructureObfuscator
import AntiDebugInjector
import SymbolStripper

// MARK: - CLI Options

struct CLIOptions {
    var inputPath: String?
    var outputPath: String?
    var passes: Set<Int> = []
    var allPasses: Bool = false
    var verbose: Bool = false
    var keyHex: String?
    var keyFile: String?
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
        case "--pass1": options.passes.insert(1)
        case "--pass2": options.passes.insert(2)
        case "--pass3": options.passes.insert(3)
        case "--pass4": options.passes.insert(4)
        case "--pass5": options.passes.insert(5)
        case "--pass6": options.passes.insert(6)
        case "--pass7": options.passes.insert(7)
        case "--all":   options.allPasses = true
        case "--verbose": options.verbose = true
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
      --pass6           Pass 6: Symbol Stripping (nlist obfuscation)
      --pass7           Pass 7: Anti-Debug Metadata Injection
      --all             Enable all passes
      --verbose         Verbose output
      --help            Show this help

    Environment:
      CPRISK_ARMOR_KEY  Hex-encoded key (fallback when --key/--key-file not set)

    A key is REQUIRED when any encryption pass (1, 3, 4) or --all is enabled.
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

// MARK: - Main

let options = parseArguments()

guard let inputPath = options.inputPath else {
    fputs("Error: --input is required\n", stderr)
    printUsage()
    exit(1)
}

let outputPath = options.outputPath ?? (inputPath + "_armored")
let verbose = options.verbose
let enabledPasses: Set<Int> = options.allPasses ? [1, 2, 3, 4, 5, 6, 7] : options.passes

if enabledPasses.isEmpty {
    fputs("Warning: No passes enabled. Use --all or --passN flags.\n", stderr)
}

// Pass 3 (Data Segment Encryption) depends on Pass 4 (Integrity Anchor) for loader descriptor layout.
if enabledPasses.contains(3) && !enabledPasses.contains(4) {
    fputs("Error: --pass3 (Data Segment Encryption) requires --pass4 (Integrity Anchor).\n", stderr)
    fputs("Enable both with --pass3 --pass4 or use --all.\n", stderr)
    exit(1)
}

let encryptionPassIDs: Set<Int> = [1, 3, 4]
let needsKey = !enabledPasses.isDisjoint(with: encryptionPassIDs)
let keyData = resolveEncryptionKey(from: options)

if needsKey && keyData == nil {
    fputs("Error: encryption passes (1, 3, 4) require a key.\n", stderr)
    fputs("Provide one via --key <hex>, --key-file <path>, or CPRISK_ARMOR_KEY env var.\n", stderr)
    exit(1)
}

if let key = keyData, key.allSatisfy({ $0 == 0 }) {
    fputs("Error: all-zero key rejected — the armor chain would be trivially reversible.\n", stderr)
    exit(1)
}

do {
    let inputURL = URL(fileURLWithPath: inputPath)
    let outputURL = URL(fileURLWithPath: outputPath)

    if verbose { print("[*] Loading Mach-O: \(inputPath)") }
    let machoFile = try MachOFile(url: inputURL)

    if verbose {
        let validity = machoFile.header.isValid ? "valid" : "INVALID"
        print("[*] Header: \(validity) | Commands: \(machoFile.header.numberOfCommands) | Type: \(machoFile.header.fileType)")
        print("[*] Segments: \(try machoFile.segments().map(\.name).joined(separator: ", "))")
        if keyData != nil { print("[*] Encryption key: provided (\(ArmorABI.keySize) bytes)") }
    }

    let config = PassConfig(verbose: verbose, encryptionKey: keyData)
    var allResults = [PassResult]()

    let passes: [(Int, ArmorPass)] = [
        (1, StringEncryptorPass()),
        (2, MetadataScrubberPass()),
        (4, IntegrityAnchorPass()),
        (3, DataSegmentEncryptorPass()),
        (5, StructureObfuscatorPass()),
        (7, AntiDebugInjectorPass()),
        (6, SymbolStripperPass()),
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
