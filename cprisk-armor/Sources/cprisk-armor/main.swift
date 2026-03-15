import Foundation
import MachOKit
import StringEncryptor
import MetadataScrubber
import DataSegmentEncryptor
import IntegrityAnchor
import StructureObfuscator

// MARK: - CLI Options

struct CLIOptions {
    var inputPath: String?
    var outputPath: String?
    var passes: Set<Int> = []
    var allPasses: Bool = false
    var verbose: Bool = false
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
        case "--pass1": options.passes.insert(1)
        case "--pass2": options.passes.insert(2)
        case "--pass3": options.passes.insert(3)
        case "--pass4": options.passes.insert(4)
        case "--pass5": options.passes.insert(5)
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
      --pass1           Pass 1: String Encryption
      --pass2           Pass 2: Metadata Scrubbing
      --pass3           Pass 3: Data Segment Encryption
      --pass4           Pass 4: Integrity Anchor
      --pass5           Pass 5: Structure Obfuscation
      --all             Enable all passes
      --verbose         Verbose output
      --help            Show this help
    """)
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
let enabledPasses: Set<Int> = options.allPasses ? [1, 2, 3, 4, 5] : options.passes

if enabledPasses.isEmpty {
    fputs("Warning: No passes enabled. Use --all or --passN flags.\n", stderr)
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
    }

    let config = PassConfig(verbose: verbose)
    var allResults = [PassResult]()

    let passes: [(Int, ArmorPass)] = [
        (1, StringEncryptorPass()),
        (2, MetadataScrubberPass()),
        (4, IntegrityAnchorPass()),
        (3, DataSegmentEncryptorPass()),
        (5, StructureObfuscatorPass()),
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
