import Darwin
import Foundation
import MachO

struct CodeSignatureValidator: Detector {
    var suspiciousInjectedLibraryTokens: [String] { ObfuscatedConstants.suspiciousInjectedLibraryTokens }

    let suspiciousEnvKeys: [String] = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
    ]

    func detect() throws -> DetectorResult {
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

        if let envKey = suspiciousEnvKeys.first(where: { getenv($0) != nil }) {
            score += 20
            methods.append("code_signature:env:\(envKey.lowercased())")
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
        let loadCommandsStart = UnsafeRawPointer(header64).advanced(by: MemoryLayout<mach_header_64>.size)
        let loadCommandsEnd = loadCommandsStart.advanced(by: Int(header64.pointee.sizeofcmds))
        var commandPointer = loadCommandsStart

        let ncmds = header64.pointee.ncmds
        guard ncmds <= 4096 else { return false }

        for _ in 0..<ncmds {
            guard commandPointer < loadCommandsEnd else { break }
            let command = commandPointer.assumingMemoryBound(to: load_command.self).pointee
            let cmdSize = Int(command.cmdsize)
            guard cmdSize >= MemoryLayout<load_command>.size, cmdSize <= 0x100000 else { break }
            guard commandPointer.advanced(by: cmdSize) <= loadCommandsEnd else { break }
            if command.cmd == LC_CODE_SIGNATURE {
                return true
            }
            commandPointer = commandPointer.advanced(by: cmdSize)
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
            let path = String(cString: name)
            if isSuspiciousInjectedLibraryPath(path) {
                return true
            }
        }
        return false
    }

    func isSuspiciousInjectedLibraryPath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return suspiciousInjectedLibraryTokens.contains(where: { normalized.contains($0) })
    }
}
