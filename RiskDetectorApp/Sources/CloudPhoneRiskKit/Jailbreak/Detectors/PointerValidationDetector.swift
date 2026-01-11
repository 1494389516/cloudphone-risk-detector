import Darwin
import Foundation
import MachO

struct PointerValidationDetector: Detector {
    struct Check: Sendable {
        var symbol: String
        var expectedPathPrefixes: [String]
        var score: Double
    }

    private let checks: [Check] = [
        .init(symbol: "open", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 8),
        .init(symbol: "stat", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 8),
        .init(symbol: "lstat", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 8),
        .init(symbol: "access", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 8),
        .init(symbol: "sysctl", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 8),
        .init(symbol: "getenv", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 6),
        .init(symbol: "dlopen", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 6),
        .init(symbol: "dlsym", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 6),
        .init(symbol: "dladdr", expectedPathPrefixes: ["/usr/lib/system/", "/usr/lib/libSystem.B.dylib"], score: 6),
        .init(symbol: "objc_msgSend", expectedPathPrefixes: ["/usr/lib/libobjc.A.dylib", "/usr/lib/system/"], score: 10),
        .init(symbol: "objc_getClass", expectedPathPrefixes: ["/usr/lib/libobjc.A.dylib", "/usr/lib/system/"], score: 8),
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        for check in checks {
            guard let addr = resolve(symbol: check.symbol) else { continue }
            guard let info = dlInfo(addr) else { continue }

            let imagePath = info.path
            let isPathOK = check.expectedPathPrefixes.contains(where: { imagePath.hasPrefix($0) })
            if !isPathOK {
                score += check.score
                methods.append("ptr_path:\(check.symbol)")
                Logger.log("jailbreak.ptr.hit: \(check.symbol) unexpected_image=\(imagePath) (+\(check.score))")
                continue
            }

            if let base = info.base, let range = MachOTextRange.textRange(header: base) {
                let p = UInt64(UInt(bitPattern: addr))
                if p < range.lowerBound || p >= range.upperBound {
                    score += check.score
                    methods.append("ptr_range:\(check.symbol)")
                    Logger.log("jailbreak.ptr.hit: \(check.symbol) out_of_text image=\(imagePath) (+\(check.score))")
                }
            }
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func resolve(symbol: String) -> UnsafeMutableRawPointer? {
        dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) // RTLD_DEFAULT
    }

    private func dlInfo(_ addr: UnsafeMutableRawPointer) -> (path: String, base: UnsafeRawPointer?)? {
        var info = Dl_info()
        guard dladdr(addr, &info) != 0 else { return nil }
        guard let cPath = info.dli_fname else { return nil }
        let path = String(cString: cPath)
        return (path: path, base: UnsafeRawPointer(info.dli_fbase))
    }
}

enum MachOTextRange {
    static func textRange(header: UnsafeRawPointer) -> Range<UInt64>? {
        let h = header.bindMemory(to: mach_header_64.self, capacity: 1).pointee
        guard h.magic == MH_MAGIC_64 || h.magic == MH_CIGAM_64 else { return nil }

        var cmdPtr = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<h.ncmds {
            let lc = cmdPtr.bindMemory(to: load_command.self, capacity: 1).pointee
            if lc.cmd == LC_SEGMENT_64 {
                let seg = cmdPtr.bindMemory(to: segment_command_64.self, capacity: 1).pointee
                let segname = withUnsafeBytes(of: seg.segname) { raw -> String in
                    let bytes = raw.prefix { $0 != 0 }
                    return String(decoding: bytes, as: UTF8.self)
                }
                if segname == "__TEXT" {
                    let start = UInt64(UInt(bitPattern: header))
                    let end = start &+ seg.vmsize
                    return start..<end
                }
            }
            cmdPtr = cmdPtr.advanced(by: Int(lc.cmdsize))
        }
        return nil
    }
}

