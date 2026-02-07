import Darwin
import Foundation
import MachO

struct CodeSignatureValidator: Detector {
    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        if !hasMachOCodeSignatureLoadCommand() {
            score += 25
            methods.append("code_signature:missing_load_command")
        }

        if hasSuspiciousInjectedLibrary() {
            score += 20
            methods.append("code_signature:suspicious_dylib")
        }

        if getenv("DYLD_INSERT_LIBRARIES") != nil {
            score += 20
            methods.append("code_signature:dyld_insert")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    private func hasMachOCodeSignatureLoadCommand() -> Bool {
        guard let imageIndex = findMainImageIndex(),
              let header = _dyld_get_image_header(imageIndex) else {
            return true
        }

        if header.pointee.magic != MH_MAGIC_64 {
            return true
        }

        let header64 = UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self)
        var commandPointer = UnsafeRawPointer(header64).advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<header64.pointee.ncmds {
            let command = commandPointer.assumingMemoryBound(to: load_command.self).pointee
            if command.cmd == LC_CODE_SIGNATURE {
                return true
            }
            commandPointer = commandPointer.advanced(by: Int(command.cmdsize))
        }

        return false
    }

    private func findMainImageIndex() -> UInt32? {
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: imageName)
            if path.contains(".app/") {
                return index
            }
        }
        return nil
    }

    private func hasSuspiciousInjectedLibrary() -> Bool {
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let name = _dyld_get_image_name(index) else { continue }
            let path = String(cString: name).lowercased()
            if path.contains("frida") || path.contains("substrate") || path.contains("libhooker") {
                return true
            }
        }
        return false
    }
}
