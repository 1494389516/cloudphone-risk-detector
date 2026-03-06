import Darwin
import Foundation
import MachO

struct DyldInterposeDetector: Detector {

    func detect() -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        // 1. Check for __DATA.__interpose sections in loaded images
        let interpose = detectInterposeSection()
        score += interpose.score
        methods.append(contentsOf: interpose.methods)

        // 2. Check for suspicious dyld environment variables
        let dyldEnv = detectDyldEnvAbuse()
        score += dyldEnv.score
        methods.append(contentsOf: dyldEnv.methods)

        // 3. Check dyld image count anomaly
        let imageCount = detectImageCountAnomaly()
        score += imageCount.score
        methods.append(contentsOf: imageCount.methods)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    /// Scan all loaded Mach-O images for __DATA.__interpose section
    private func detectInterposeSection() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let header = _dyld_get_image_header(i) else { continue }
            let name = _dyld_get_image_name(i).map { String(cString: $0) } ?? "unknown"

            // Skip system frameworks
            if name.hasPrefix("/usr/lib/") || name.hasPrefix("/System/") { continue }

            let ptr = UnsafeRawPointer(header)
            guard header.pointee.magic == MH_MAGIC_64 || header.pointee.magic == MH_CIGAM_64 else { continue }

            let header64 = ptr.assumingMemoryBound(to: mach_header_64.self)
            var cmd = ptr.advanced(by: MemoryLayout<mach_header_64>.size)

            for _ in 0..<header64.pointee.ncmds {
                let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
                if loadCmd.cmd == LC_SEGMENT_64 {
                    let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                    let segName = withUnsafePointer(to: seg.segname) { ptr in
                        ptr.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                    }
                    if segName == "__DATA" || segName == "__DATA_CONST" {
                        var sect = cmd.advanced(by: MemoryLayout<segment_command_64>.size)
                            .assumingMemoryBound(to: section_64.self)
                        for _ in 0..<seg.nsects {
                            let sectName = withUnsafePointer(to: sect.pointee.sectname) { ptr in
                                ptr.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                            }
                            if sectName == "__interpose" {
                                score += 25
                                let shortName = (name as NSString).lastPathComponent
                                methods.append("dyld_interpose:section_found:\(shortName)")
                            }
                            sect = sect.advanced(by: 1)
                        }
                    }
                }
                cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
            }
        }

        return (min(score, 30), methods)
    }

    /// Check dangerous dyld environment variables beyond DYLD_INSERT_LIBRARIES
    private func detectDyldEnvAbuse() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let dangerousVars = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_PRINT_LIBRARIES",
            "DYLD_PRINT_APIS",
        ]

        let env = ProcessInfo.processInfo.environment
        for varName in dangerousVars {
            if let value = env[varName], !value.isEmpty {
                score += 15
                methods.append("dyld_env:\(varName)")
            }
        }

        return (min(score, 25), methods)
    }

    /// Anomalous image count (too many loaded dylibs)
    private func detectImageCountAnomaly() -> (score: Double, methods: [String]) {
        let count = _dyld_image_count()
        // Normal iOS app loads ~300-400 dylibs. Injection adds more.
        if count > 500 {
            return (12, ["dyld_image_count:\(count)"])
        } else if count > 450 {
            return (6, ["dyld_image_count:\(count)"])
        }
        return (0, [])
    }

    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let interposeMethods = result.methods.filter { $0.hasPrefix("dyld_interpose") }
        if !interposeMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_interpose_detected",
                category: "anti_tamper",
                score: min(Double(interposeMethods.count) * 20, 30),
                evidence: ["detail": interposeMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 88
            ))
        }

        let envMethods = result.methods.filter { $0.hasPrefix("dyld_env") }
        if !envMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_env_abuse",
                category: "anti_tamper",
                score: min(Double(envMethods.count) * 12, 25),
                evidence: ["vars": envMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 78
            ))
        }

        let countMethods = result.methods.filter { $0.hasPrefix("dyld_image_count") }
        if !countMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_image_overload",
                category: "anti_tamper",
                score: 10,
                evidence: ["detail": countMethods.joined(separator: ",")],
                state: .soft(confidence: 0.5),
                layer: 2,
                weightHint: 45
            ))
        }

        return signals
    }
}
