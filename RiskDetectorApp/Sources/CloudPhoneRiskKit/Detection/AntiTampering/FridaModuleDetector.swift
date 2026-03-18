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
    let moduleMarkers: [String] = [
        "frida",
        "frida-agent",
        "frida-gadget",
        "frida-server",
        "gadget",
        "libgum",
        "gum-core",
        "fridagum",
        "gum-js-loop",
        "gumjs",
    ]

    let suspiciousSectionMarkers: [String] = [
        "__frida",
        "__frida_gadget",
        "__frida_data",
        "__gum",
        "__gumjs",
    ]

    let suspiciousStringMarkers: [String] = [
        "frida:rpc",
        "frida-agent",
        "frida-gadget",
        "gum-js-loop",
        "gum-interceptor",
        "gum-core",
        "gumstalker",
        "linjector",
    ]

    private let scannedSectionNames: Set<String> = ["__cstring", "__const"]
    private let maxStringScanBytes = 64 * 1024

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["frida_module:unavailable_simulator"])
#else
        var imageHits: [String] = []
        var sectionHits: [String] = []
        var stringHits: [String] = []

        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            let imageName = _dyld_get_image_name(index).map { String(cString: $0) } ?? ""
            imageHits.append(contentsOf: detectImageMarkers(in: [imageName]))

            guard let header = _dyld_get_image_header(index) else { continue }
            let shouldInspectLayout = !imageName.hasPrefix("/usr/lib/") && !imageName.hasPrefix("/System/")
            guard shouldInspectLayout else { continue }

            let layout = inspectModuleLayout(header: header, imageIndex: index)
            sectionHits.append(contentsOf: detectSectionMarkers(in: layout.sectionNames))
            stringHits.append(contentsOf: detectStringMarkers(in: layout.stringBlobs))
        }

        return Self.buildResult(
            imageHits: imageHits,
            sectionHits: sectionHits,
            stringHits: stringHits
        )
#endif
    }

    func detectImageMarkers(in imageNames: [String]) -> [String] {
        var hits = Set<String>()

        for imageName in imageNames {
            let normalized = imageName.lowercased()
            for marker in moduleMarkers where normalized.contains(marker) {
                hits.insert("frida_module:image:\(marker)")
            }
        }

        return hits.sorted()
    }

    func detectSectionMarkers(in sectionNames: [String]) -> [String] {
        var hits = Set<String>()

        for sectionName in sectionNames {
            let normalized = sectionName.lowercased()
            for marker in suspiciousSectionMarkers where normalized.contains(marker) {
                hits.insert("frida_module:section:\(marker)")
            }
        }

        return hits.sorted()
    }

    func detectStringMarkers(in blobs: [String]) -> [String] {
        var hits = Set<String>()

        for blob in blobs {
            let normalized = blob.lowercased()
            for marker in suspiciousStringMarkers where normalized.contains(marker) {
                hits.insert("frida_module:string:\(marker)")
            }
        }

        return hits.sorted()
    }

    static func buildResult(
        imageHits: [String],
        sectionHits: [String],
        stringHits: [String]
    ) -> DetectorResult {
        let uniqueImageHits = Array(Set(imageHits)).sorted()
        let uniqueSectionHits = Array(Set(sectionHits)).sorted()
        let uniqueStringHits = Array(Set(stringHits)).sorted()

        let imageScore = uniqueImageHits.isEmpty ? 0.0 : min(14.0 + Double(max(0, uniqueImageHits.count - 1)) * 3.0, 20.0)
        let sectionScore = uniqueSectionHits.isEmpty ? 0.0 : min(8.0 + Double(max(0, uniqueSectionHits.count - 1)) * 2.0, 12.0)
        let stringScore = uniqueStringHits.isEmpty ? 0.0 : min(12.0 + Double(max(0, uniqueStringHits.count - 1)) * 3.0, 18.0)

        return DetectorResult(
            score: min(imageScore + sectionScore + stringScore, 40),
            methods: uniqueImageHits + uniqueSectionHits + uniqueStringHits
        )
    }

    static func asSignals(result: DetectorResult) -> [RiskSignal] {
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        let imageMethods = result.methods.filter { $0.hasPrefix("frida_module:image:") }
        let sectionMethods = result.methods.filter { $0.hasPrefix("frida_module:section:") }
        let stringMethods = result.methods.filter { $0.hasPrefix("frida_module:string:") }

        signals.append(RiskSignal(
            id: SignalID.fridaModuleDetected,
            category: "anti_tamper",
            score: min(result.score, 28),
            evidence: [
                "methods": result.methods.joined(separator: ","),
                "detector": "FridaModuleDetector",
            ],
            state: .tampered,
            layer: 2,
            weightHint: 82
        ))

        if !imageMethods.isEmpty {
            signals.append(RiskSignal(
                id: SignalID.fridaModuleImage,
                category: "anti_tamper",
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
                category: "anti_tamper",
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
                category: "anti_tamper",
                score: min(Double(stringMethods.count) * 8, 16),
                evidence: ["detail": stringMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        return signals
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
              let base = UnsafeRawPointer(bitPattern: UInt(truncatingIfNeeded: runtimeAddress)) else {
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
