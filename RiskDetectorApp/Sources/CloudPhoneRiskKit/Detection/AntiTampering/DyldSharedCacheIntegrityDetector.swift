import Darwin
import Foundation
import MachO

/// Validates dyld shared-cache integrity via:
/// 1) UUID presence for critical cache images
/// 2) slide consistency across critical cache images
/// 3) critical symbol ownership / in-text-range consistency
struct DyldSharedCacheIntegrityDetector: Detector {
    struct ImageSnapshot {
        let id: String
        let path: String
        let uuidHex: String?
        let slide: Int64
    }

    struct Snapshot {
        let criticalImages: [ImageSnapshot]
        let slideMismatchCount: Int
        let missingUUIDCount: Int
        let symbolMismatches: [String]
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let slideMismatchCount: Int
        let missingUUIDCount: Int
        let symbolMismatchCount: Int
    }

    private let criticalImageSuffixes: [(id: String, suffix: String)] = [
        ("libsystem_kernel", "/usr/lib/system/libsystem_kernel.dylib"),
        ("libsystem_c", "/usr/lib/libsystem_c.dylib"),
        ("libobjc", "/usr/lib/libobjc.A.dylib"),
        ("libdispatch", "/usr/lib/system/libdispatch.dylib"),
    ]

    private let criticalSymbols: [(symbol: String, expectedTokens: [String])] = [
        ("open", ["libsystem", "/usr/lib/system"]),
        ("malloc", ["libsystem", "/usr/lib/system"]),
        ("objc_msgSend", ["libobjc"]),
        ("dispatch_async", ["libdispatch"]),
    ]

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dyld_shared_cache:unavailable_simulator"])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(snapshot: Snapshot) -> Assessment {
        guard !snapshot.criticalImages.isEmpty || !snapshot.symbolMismatches.isEmpty else {
            return Assessment(
                score: 0,
                methods: ["dyld_shared_cache:clean"],
                slideMismatchCount: 0,
                missingUUIDCount: 0,
                symbolMismatchCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        if snapshot.missingUUIDCount > 0 {
            score += min(20 + Double(snapshot.missingUUIDCount - 1) * 9, 42)
            methods.append("dyld_shared_cache:uuid_missing:\(snapshot.missingUUIDCount)")
        }

        if snapshot.slideMismatchCount > 0 {
            score += min(28 + Double(snapshot.slideMismatchCount - 1) * 12, 48)
            methods.append("dyld_shared_cache:slide_mismatch:\(snapshot.slideMismatchCount)")
        }

        let symbolMismatchCount = snapshot.symbolMismatches.count
        if symbolMismatchCount >= 2 {
            score += min(24 + Double(symbolMismatchCount - 2) * 8, 44)
            methods.append("dyld_shared_cache:symbol_mismatch:\(symbolMismatchCount)")
        } else if symbolMismatchCount == 1 {
            score += 8
            methods.append("dyld_shared_cache:symbol_mismatch_hint:1")
        }

        if snapshot.slideMismatchCount > 0 && symbolMismatchCount > 0 {
            score += 12
            methods.append("dyld_shared_cache:correlated_anomaly")
        }

        return Assessment(
            score: min(score, 95),
            methods: methods,
            slideMismatchCount: snapshot.slideMismatchCount,
            missingUUIDCount: snapshot.missingUUIDCount,
            symbolMismatchCount: symbolMismatchCount
        )
    }

    private func collectSnapshot() -> Snapshot {
        var images: [ImageSnapshot] = []
        var seen = Set<String>()

        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let cPath = _dyld_get_image_name(index), let header = _dyld_get_image_header(index) else { continue }
            let path = String(cString: cPath)
            for rule in criticalImageSuffixes where path.hasSuffix(rule.suffix) {
                guard !seen.contains(rule.id) else { break }
                let uuid = extractUUID(from: UnsafeRawPointer(header))
                let slide = Int64(_dyld_get_image_vmaddr_slide(index))
                images.append(
                    ImageSnapshot(
                        id: rule.id,
                        path: path,
                        uuidHex: uuid,
                        slide: slide
                    )
                )
                seen.insert(rule.id)
                break
            }
        }

        let missingUUIDCount = images.filter { $0.uuidHex == nil || $0.uuidHex?.isEmpty == true }.count
        var slideMismatchCount = 0
        if let baselineSlide = images.first?.slide {
            slideMismatchCount = images.filter { $0.slide != baselineSlide }.count
        }

        let symbolMismatches = collectSymbolMismatches()

        return Snapshot(
            criticalImages: images,
            slideMismatchCount: slideMismatchCount,
            missingUUIDCount: missingUUIDCount,
            symbolMismatches: symbolMismatches
        )
    }

    private func collectSymbolMismatches() -> [String] {
        var mismatches: [String] = []
        for item in criticalSymbols {
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.symbol) else {
                mismatches.append("\(item.symbol):dlsym")
                continue
            }

            var info = Dl_info()
            guard dladdr(ptr, &info) != 0, let cName = info.dli_fname else {
                mismatches.append("\(item.symbol):dladdr")
                continue
            }

            let path = String(cString: cName)
            let normalized = path.lowercased()
            if !item.expectedTokens.contains(where: { normalized.contains($0) }) {
                mismatches.append("\(item.symbol):unexpected_image:\(path)")
                continue
            }

            if let imageBase = info.dli_fbase,
               let textRange = MachOTextRange.textRange(header: UnsafeRawPointer(imageBase)) {
                let address = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
                if address < textRange.lowerBound || address >= textRange.upperBound {
                    mismatches.append("\(item.symbol):out_of_text")
                }
            }
        }
        return mismatches
    }

    private func extractUUID(from header: UnsafeRawPointer) -> String? {
        let header64 = header.assumingMemoryBound(to: mach_header_64.self)
        guard header64.pointee.magic == MH_MAGIC_64 || header64.pointee.magic == MH_CIGAM_64 else {
            return nil
        }

        var command = header.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandLimit = command.advanced(by: Int(header64.pointee.sizeofcmds))
        for _ in 0..<header64.pointee.ncmds {
            guard command < commandLimit else { break }
            let load = command.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize > 0 else { break }
            if load.cmd == LC_UUID {
                let uuidCommand = command.assumingMemoryBound(to: uuid_command.self).pointee
                let bytes = withUnsafeBytes(of: uuidCommand.uuid) { Array($0) }
                return bytes.map { String(format: "%02x", $0) }.joined()
            }
            command = command.advanced(by: Int(load.cmdsize))
        }
        return nil
    }
}

extension DyldSharedCacheIntegrityDetector {
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        if assessment.missingUUIDCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.dyldSharedCacheUUIDMismatch,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(30 + Double(assessment.missingUUIDCount) * 8, 55),
                    evidence: [
                        "missing_uuid_count": "\(assessment.missingUUIDCount)",
                        "images": snapshot.criticalImages.map(\.path).joined(separator: ","),
                    ],
                    state: assessment.missingUUIDCount >= 2 ? .tampered : .soft(confidence: 0.65),
                    layer: 2,
                    weightHint: assessment.missingUUIDCount >= 2 ? 82 : 52
                )
            )
        }

        if assessment.slideMismatchCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.dyldSharedCacheSlideMismatch,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(42 + Double(assessment.slideMismatchCount) * 10, 76),
                    evidence: [
                        "slide_mismatch_count": "\(assessment.slideMismatchCount)",
                        "slides": snapshot.criticalImages
                            .map { "\($0.id)=\($0.slide)" }
                            .sorted()
                            .joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        if assessment.symbolMismatchCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.dyldSharedCacheSymbolMismatch,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: assessment.symbolMismatchCount >= 2
                        ? min(36 + Double(assessment.symbolMismatchCount) * 8, 70)
                        : 12,
                    evidence: [
                        "symbol_mismatches": snapshot.symbolMismatches.joined(separator: ","),
                    ],
                    state: assessment.symbolMismatchCount >= 2 ? .tampered : .soft(confidence: 0.58),
                    layer: 2,
                    weightHint: assessment.symbolMismatchCount >= 2 ? 86 : 40
                )
            )
        }

        let hasHardAnomaly = signals.contains(where: { $0.state == .tampered })
        signals.append(
            RiskSignal(
                id: SignalID.dyldSharedCacheIntegrity,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.score,
                evidence: [
                    "methods": assessment.methods.joined(separator: ","),
                    "critical_image_count": "\(snapshot.criticalImages.count)",
                ],
                state: hasHardAnomaly ? .tampered : .soft(confidence: 0.7),
                layer: 2,
                weightHint: hasHardAnomaly ? 88 : 58
            )
        )

        return signals
    }
}
