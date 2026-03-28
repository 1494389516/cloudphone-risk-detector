import Darwin
import Foundation
import MachO

/// Detects Frida/Gum/Gadget traits from loaded in-memory modules.
///
/// The detector intentionally prefers stable heuristics over brittle byte signatures:
/// - dyld image names
/// - suspicious Mach-O section names
/// - string fragments found in loaded `__cstring` / `__const` sections
struct FridaModuleDetector: Detector {
    private static let trampolineMethodPrefix = "frida_module:trampoline:"
    private let suspiciousTrampolineSymbols: [String] = [
        "objc_msgSend",
        "dlopen",
        "dlsym",
        "pthread_create",
        "mach_msg",
        "sysctl",
        "open",
    ]

    struct PrologueObservation: Sendable, Equatable {
        let symbol: String
        let firstInstruction: UInt32
        let secondInstruction: UInt32?
    }

    let moduleMarkers: [String] = ObfuscatedConstants.fridaModuleMarkers

    let suspiciousSectionMarkers: [String] = ObfuscatedConstants.fridaSectionMarkers

    let suspiciousStringMarkers: [String] = ObfuscatedConstants.fridaStringMarkers

    private let scannedSectionNames: Set<String> = ["__cstring", "__const"]
    private let maxStringScanBytes = 64 * 1024

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaModuleUnavailableSimulator])
#else
        var imageHits: [String] = []
        var sectionHits: [String] = []
        var stringHits: [String] = []
        let trampolineHits = detectTrampolineMarkers(in: capturePrologueObservations())

        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            let imageName = _dyld_get_image_name(index).map { String(cString: $0) } ?? ""
            imageHits.append(contentsOf: detectImageMarkers(in: [imageName]))
            imageHits.append(contentsOf: detectImageOriginAnomalies(in: [imageName]))

            guard let header = _dyld_get_image_header(index) else { continue }
            let shouldInspectLayout = !imageName.hasPrefix("/usr/lib/") && !imageName.hasPrefix("/System/")
            guard shouldInspectLayout else { continue }

            let layout = inspectModuleLayout(header: header, imageIndex: index)
            let isMainExecutable = isMainExecutableImage(index: index, imageName: imageName)
            sectionHits.append(contentsOf: detectSectionMarkers(in: layout.sectionNames))
            stringHits.append(contentsOf: detectStringMarkers(in: layout.stringBlobs))
            if isMainExecutable {
                sectionHits.append(contentsOf: detectSectionMarkers(in: layout.sectionNames, mainBinary: true))
                stringHits.append(contentsOf: detectStringMarkers(in: layout.stringBlobs, mainBinary: true))
            }
        }

        return Self.buildResult(
            imageHits: imageHits,
            sectionHits: sectionHits,
            stringHits: stringHits,
            trampolineHits: trampolineHits
        )
#endif
    }

    func detectImageMarkers(in imageNames: [String]) -> [String] {
        var hits = Set<String>()

        for imageName in imageNames {
            let normalized = imageName.lowercased()
            for marker in moduleMarkers where normalized.contains(marker) {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)\(marker)")
            }
        }

        return hits.sorted()
    }

    func detectImageOriginAnomalies(in imageNames: [String]) -> [String] {
        var hits = Set<String>()

        for imageName in imageNames {
            let normalized = imageName.lowercased()
            guard !normalized.isEmpty else { continue }
            guard !normalized.hasPrefix("/usr/lib/"), !normalized.hasPrefix("/system/") else { continue }

            if normalized.contains("/tmp/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)tmp_origin")
            }
            if normalized.contains("/documents/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)documents_origin")
            }
            if normalized.contains("/library/caches/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)caches_origin")
            }
            if normalized.contains("/containers/data/application/"),
               normalized.hasSuffix(".dylib") || normalized.contains(".framework/") {
                hits.insert("\(ObfuscatedConstants.methodPrefixFridaModuleImage)sandbox_data_origin")
            }
        }

        return hits.sorted()
    }

    func detectSectionMarkers(in sectionNames: [String], mainBinary: Bool = false) -> [String] {
        var hits = Set<String>()
        let prefix = mainBinary
            ? "\(ObfuscatedConstants.methodPrefixFridaModuleSection)main_binary:"
            : ObfuscatedConstants.methodPrefixFridaModuleSection

        for sectionName in sectionNames {
            let normalized = sectionName.lowercased()
            for marker in suspiciousSectionMarkers where normalized.contains(marker) {
                hits.insert("\(prefix)\(marker)")
            }
        }

        return hits.sorted()
    }

    func detectStringMarkers(in blobs: [String], mainBinary: Bool = false) -> [String] {
        var hits = Set<String>()
        let prefix = mainBinary
            ? "\(ObfuscatedConstants.methodPrefixFridaModuleString)main_binary:"
            : ObfuscatedConstants.methodPrefixFridaModuleString

        for blob in blobs {
            let normalized = blob.lowercased()
            for marker in suspiciousStringMarkers where normalized.contains(marker) {
                hits.insert("\(prefix)\(marker)")
            }
        }

        return hits.sorted()
    }

    func detectTrampolineMarkers(in observations: [PrologueObservation]) -> [String] {
        let branchDetector = PrologueBranchDetector()
        var hits = Set<String>()

        for observation in observations where suspiciousTrampolineSymbols.contains(observation.symbol) {
            guard branchDetector.isHooked(
                firstInstruction: observation.firstInstruction,
                secondInstruction: observation.secondInstruction
            ) else {
                continue
            }

            let detail: String
            if branchDetector.isLiteralLoad(observation.firstInstruction),
               let second = observation.secondInstruction,
               branchDetector.isRegisterBranch(second) {
                detail = "\(observation.symbol):literal_branch"
            } else if branchDetector.isRegisterBranch(observation.firstInstruction) {
                detail = "\(observation.symbol):register_branch"
            } else {
                detail = "\(observation.symbol):branch"
            }
            hits.insert("\(Self.trampolineMethodPrefix)\(detail)")
        }

        return hits.sorted()
    }

    static func buildResult(
        imageHits: [String],
        sectionHits: [String],
        stringHits: [String],
        trampolineHits: [String] = []
    ) -> DetectorResult {
        let uniqueImageHits = Array(Set(imageHits)).sorted()
        let uniqueSectionHits = Array(Set(sectionHits)).sorted()
        let uniqueStringHits = Array(Set(stringHits)).sorted()
        let uniqueTrampolineHits = Array(Set(trampolineHits)).sorted()
        let mainBinarySectionHits = uniqueSectionHits.filter { $0.contains(":main_binary:") }
        let mainBinaryStringHits = uniqueStringHits.filter { $0.contains(":main_binary:") }

        let imageScore = uniqueImageHits.isEmpty ? 0.0 : min(14.0 + Double(max(0, uniqueImageHits.count - 1)) * 3.0, 20.0)
        let sectionScore = uniqueSectionHits.isEmpty ? 0.0 : min(8.0 + Double(max(0, uniqueSectionHits.count - 1)) * 2.0, 12.0)
        let stringScore = uniqueStringHits.isEmpty ? 0.0 : min(12.0 + Double(max(0, uniqueStringHits.count - 1)) * 3.0, 18.0)
        let trampolineScore = uniqueTrampolineHits.isEmpty
            ? 0.0
            : min(14.0 + Double(max(0, uniqueTrampolineHits.count - 1)) * 4.0, 18.0)
        let mainBinaryBoost = min(
            Double(mainBinarySectionHits.count) * 3.0 + Double(mainBinaryStringHits.count) * 4.0,
            12.0
        )

        return DetectorResult(
            score: min(imageScore + sectionScore + stringScore + trampolineScore + mainBinaryBoost, 44),
            methods: uniqueImageHits + uniqueSectionHits + uniqueStringHits + uniqueTrampolineHits
        )
    }

    static func asSignals(result: DetectorResult) -> [RiskSignal] {
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        let imageMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaModuleImage) }
        let sectionMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaModuleSection) }
        let stringMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaModuleString) }
        let trampolineMethods = result.methods.filter { $0.hasPrefix(Self.trampolineMethodPrefix) }

        signals.append(RiskSignal(
            id: SignalID.fridaModuleDetected,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: min(result.score, 28),
            evidence: [
                "methods": result.methods.joined(separator: ","),
                "detector": ObfuscatedConstants.detectorNameFridaModuleDetector,
            ],
            state: .tampered,
            layer: 2,
            weightHint: 82
        ))

        if !imageMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleImage,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(imageMethods.count) * 8, 16),
                evidence: ["detail": imageMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 78
            ))
        }

        if !sectionMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleSection,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(sectionMethods.count) * 6, 12),
                evidence: ["detail": sectionMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 72
            ))
        }

        if !stringMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleString,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(stringMethods.count) * 8, 16),
                evidence: ["detail": stringMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        if !trampolineMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleTrampoline,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(trampolineMethods.count) * 10, 18),
                evidence: ["detail": trampolineMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 84
            ))
        }

        return signals
    }

    private func capturePrologueObservations() -> [PrologueObservation] {
        let branchDetector = PrologueBranchDetector()
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

        return suspiciousTrampolineSymbols.compactMap { symbol in
            guard let addr = dlsym(rtldDefault, symbol) else {
                return nil
            }
            let pointer = UnsafeRawPointer(addr)
            guard let first = branchDetector.readInstruction(pointer) else {
                return nil
            }
            let second = branchDetector.readInstruction(
                pointer.advanced(by: MemoryLayout<UInt32>.size)
            )
            return PrologueObservation(
                symbol: symbol,
                firstInstruction: first,
                secondInstruction: second
            )
        }
    }

    private func isMainExecutableImage(index: UInt32, imageName: String) -> Bool {
        if index == 0 {
            return true
        }
        if let executablePath = Bundle.main.executablePath {
            return imageName == executablePath
        }
        return false
    }

    private func inspectModuleLayout(
        header: UnsafePointer<mach_header>,
        imageIndex: UInt32
    ) -> (sectionNames: [String], stringBlobs: [String]) {
        let rawHeader = UnsafeRawPointer(header)
        let header64 = rawHeader.assumingMemoryBound(to: mach_header_64.self)
        let slide = Int64(_dyld_get_image_vmaddr_slide(imageIndex))

        guard header64.pointee.magic == MH_MAGIC_64 || header64.pointee.magic == MH_CIGAM_64 else {
            return ([], [])
        }

        var sectionNames: [String] = []
        var stringBlobs: [String] = []
        var command = rawHeader.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<Int(header64.pointee.ncmds) {
            let loadCommand = command.assumingMemoryBound(to: load_command.self).pointee
            guard loadCommand.cmdsize >= MemoryLayout<load_command>.size else { break }
            defer { command = command.advanced(by: Int(loadCommand.cmdsize)) }

            guard loadCommand.cmd == LC_SEGMENT_64 else { continue }

            let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
            var sectionPtr = command.advanced(by: MemoryLayout<segment_command_64>.size)

            for _ in 0..<Int(segment.nsects) {
                let section = sectionPtr.assumingMemoryBound(to: section_64.self).pointee
                let sectionName = cString(from: section.sectname)
                sectionNames.append(sectionName)

                if scannedSectionNames.contains(sectionName),
                   let blob = readBlob(section: section, slide: slide),
                   !blob.isEmpty {
                    stringBlobs.append(blob)
                }

                sectionPtr = sectionPtr.advanced(by: MemoryLayout<section_64>.size)
            }
        }

        return (sectionNames, stringBlobs)
    }

    private func readBlob(section: section_64, slide: Int64) -> String? {
        guard section.addr != 0, section.size > 0 else { return nil }

        let byteCount = Int(min(section.size, UInt64(maxStringScanBytes)))
        let runtimeAddress = Int64(section.addr) + slide
        guard byteCount > 0,
              runtimeAddress > 0,
              let base = UnsafeRawPointer(bitPattern: Int(runtimeAddress)) else {
            return nil
        }

        let data = Data(bytes: base, count: byteCount)
        var normalized = [UInt8]()
        normalized.reserveCapacity(data.count)

        for byte in data {
            if (32...126).contains(byte) {
                normalized.append(byte)
            } else {
                normalized.append(0x20)
            }
        }

        return String(decoding: normalized, as: UTF8.self)
    }

    private func cString<T>(from tuple: T) -> String {
        withUnsafeBytes(of: tuple) { rawBuffer in
            let bytes = rawBuffer.prefix { $0 != 0 }
            return String(decoding: bytes, as: UTF8.self)
        }
    }
}

extension FridaModuleDetector {
    func asSignals() throws -> [RiskSignal] {
        Self.asSignals(result: try detect())
    }
}
