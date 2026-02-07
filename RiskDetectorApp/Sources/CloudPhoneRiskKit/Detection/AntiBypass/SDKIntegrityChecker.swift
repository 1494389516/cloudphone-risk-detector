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
