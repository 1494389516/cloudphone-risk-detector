import Darwin
import Foundation
import MachO

struct SDKIntegrityChecker: Detector {
    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        if getenv("DYLD_INSERT_LIBRARIES") != nil {
            score += 20
            methods.append("integrity:dyld_insert_libraries")
        }

        if let suspicious = firstSuspiciousImage() {
            score += 25
            methods.append("integrity:suspicious_image:\(suspicious)")
        }

        if !isMainExecutableInBundle() {
            score += 15
            methods.append("integrity:main_executable_path")
        }

        if !hasCodeSignatureCommand() {
            score += 20
            methods.append("integrity:missing_code_signature")
        }

        let baseline = PLTIntegrityGuard.captureBaseline()
        let pltResult = PLTIntegrityGuard.verify(baseline: baseline)
        if !pltResult.isIntact {
            score += 30
            for fn in pltResult.hookedFunctions {
                methods.append("integrity:plt_hooked:\(fn)")
            }
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func firstSuspiciousImage() -> String? {
        let patterns = ["frida", "substrate", "libhooker", "ellekit", "substitute"]
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let raw = _dyld_get_image_name(index) else { continue }
            let image = String(cString: raw)
            let lower = image.lowercased()
            if patterns.contains(where: { lower.contains($0) }) {
                return (image as NSString).lastPathComponent
            }
        }
        return nil
    }

    private func isMainExecutableInBundle() -> Bool {
        guard let executable = Bundle.main.executablePath else { return true }
        return executable.contains(".app/")
    }

    private func hasCodeSignatureCommand() -> Bool {
        guard let headerPtr = _dyld_get_image_header(0) else {
            return true
        }
        guard headerPtr.pointee.magic == MH_MAGIC_64 else {
            return true
        }

        let header64 = UnsafeRawPointer(headerPtr).assumingMemoryBound(to: mach_header_64.self)
        var cmd = UnsafeRawPointer(header64).advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<header64.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            if load.cmd == LC_CODE_SIGNATURE {
                return true
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }

        return false
    }
}

struct PLTIntegrityResult {
    var isIntact: Bool
    var hookedFunctions: [String]
    var details: [String: String]
}

struct PLTIntegrityGuard {
    private static let criticalFunctions: [String] = [
        "sysctlbyname",
        "sysctl",
        "stat",
        "access",
        "dlsym",
        "getenv",
        "ptrace",
        "_dyld_image_count",
        "_dyld_get_image_name",
        "_dyld_get_image_header",
    ]

    struct FunctionRecord {
        let name: String
        let address: UInt64
        let moduleBase: UInt64
        let moduleSize: UInt64
    }

    static func captureBaseline() -> [FunctionRecord] {
        var records: [FunctionRecord] = []
        for name in criticalFunctions {
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { continue }
            var info = Dl_info()
            guard dladdr(ptr, &info) != 0, let imageHeader = info.dli_fbase else { continue }
            let (base, size) = textSegmentRange(header: imageHeader)
            let addr = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
            records.append(FunctionRecord(name: name, address: addr, moduleBase: base, moduleSize: size))
        }
        return records
    }

    static func verify(baseline: [FunctionRecord]) -> PLTIntegrityResult {
        var hooked: [String] = []
        var details: [String: String] = [:]
        for record in baseline {
            guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), record.name) else {
                hooked.append(record.name)
                details[record.name] = "dlsym_failed"
                continue
            }
            let currentAddr = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
            var info = Dl_info()
            guard dladdr(ptr, &info) != 0, let imageHeader = info.dli_fbase else {
                hooked.append(record.name)
                details[record.name] = "dladdr_failed"
                continue
            }
            let (base, size) = textSegmentRange(header: imageHeader)
            let inRange = currentAddr >= base && currentAddr < base + size
            let sameModule = base == record.moduleBase
            if !inRange || !sameModule {
                hooked.append(record.name)
                details[record.name] = "addr=0x\(String(currentAddr, radix: 16)) expected_base=0x\(String(record.moduleBase, radix: 16))"
            }
        }
        return PLTIntegrityResult(
            isIntact: hooked.isEmpty,
            hookedFunctions: hooked,
            details: details
        )
    }

    private static func textSegmentRange(header: UnsafeRawPointer) -> (base: UInt64, size: UInt64) {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return (0, 0) }
        let imageBase = UInt64(bitPattern: Int64(Int(bitPattern: header)))
        var cmd = UnsafeRawPointer(ptr).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    var sect = cmd.advanced(by: MemoryLayout<segment_command_64>.size)
                        .assumingMemoryBound(to: section_64.self)
                    for _ in 0..<seg.nsects {
                        if tupleStringEquals(sect.pointee.sectname, "__text") {
                            return (imageBase + sect.pointee.addr, sect.pointee.size)
                        }
                        sect = sect.advanced(by: 1)
                    }
                }
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return (0, 0)
    }
}

private func tupleStringEquals<T>(_ tuple: T, _ target: String) -> Bool {
    withUnsafePointer(to: tuple) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
            strncmp(cPtr, target, MemoryLayout<T>.size) == 0
        }
    }
}

extension PLTIntegrityGuard {
    static func asSignals(result: PLTIntegrityResult) -> [RiskSignal] {
        if !result.hookedFunctions.isEmpty {
            return [
                RiskSignal(
                    id: "plt_integrity_tampered",
                    category: "integrity",
                    score: 0,
                    evidence: ["hooked": result.hookedFunctions.joined(separator: ","), "details": (try? JSON.stringify(result.details)) ?? "{}"],
                    state: .tampered,
                    layer: 2,
                    weightHint: 92
                )
            ]
        }
        return [
            RiskSignal(
                id: "plt_integrity_ok",
                category: "integrity",
                score: 0,
                evidence: [:],
                state: .hard(detected: false),
                layer: 2,
                weightHint: 0
            )
        ]
    }
}
