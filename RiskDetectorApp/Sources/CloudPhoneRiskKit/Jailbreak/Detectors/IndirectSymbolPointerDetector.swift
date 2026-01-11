import Darwin
import Foundation
import MachO

/// Detects fishhook-style rebinding by inspecting indirect symbol pointer tables.
/// Best-effort: focuses on a small watchlist and only flags when the resolved pointer
/// points to a non-system image.
struct IndirectSymbolPointerDetector: Detector {
    private let watch: [(symbol: String, score: Double)] = [
        ("open", 12),
        ("stat", 12),
        ("lstat", 12),
        ("access", 12),
        ("sysctl", 12),
        ("getenv", 10),
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        let needles = Dictionary(uniqueKeysWithValues: watch.map { ($0.symbol, $0.score) })

        let imageCount = Int(_dyld_image_count())
        let maxImages = min(imageCount, 40)
        for i in 0..<maxImages {
            guard let header = _dyld_get_image_header(UInt32(i)) else { continue }
            let slide = Int64(_dyld_get_image_vmaddr_slide(UInt32(i)))
            let result = scanImage(header: header, slide: slide, needles: needles)
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if score > 60 { score = 60 }
        return DetectorResult(score: score, methods: methods)
    }

    private func scanImage(header: UnsafePointer<mach_header>, slide: Int64, needles: [String: Double]) -> DetectorResult {
        // Only 64-bit images expected here.
        guard header.pointee.magic == MH_MAGIC_64 || header.pointee.magic == MH_CIGAM_64 else { return .empty }
        let h64 = UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self).pointee

        var symtab: symtab_command?
        var dysymtab: dysymtab_command?
        var linkedit: segment_command_64?
        var sections: [section_64] = []

        var cmdPtr = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<h64.ncmds {
            let lc = cmdPtr.assumingMemoryBound(to: load_command.self).pointee
            if lc.cmd == LC_SYMTAB {
                symtab = cmdPtr.assumingMemoryBound(to: symtab_command.self).pointee
            } else if lc.cmd == LC_DYSYMTAB {
                dysymtab = cmdPtr.assumingMemoryBound(to: dysymtab_command.self).pointee
            } else if lc.cmd == LC_SEGMENT_64 {
                let seg = cmdPtr.assumingMemoryBound(to: segment_command_64.self).pointee
                let segname = withUnsafeBytes(of: seg.segname) { raw -> String in
                    let bytes = raw.prefix { $0 != 0 }
                    return String(decoding: bytes, as: UTF8.self)
                }
                if segname == "__LINKEDIT" {
                    linkedit = seg
                }
                if seg.nsects > 0 {
                    var secPtr = cmdPtr.advanced(by: MemoryLayout<segment_command_64>.size)
                    for _ in 0..<seg.nsects {
                        let sec = secPtr.assumingMemoryBound(to: section_64.self).pointee
                        let type = sec.flags & UInt32(SECTION_TYPE)
                        if type == UInt32(S_LAZY_SYMBOL_POINTERS) || type == UInt32(S_NON_LAZY_SYMBOL_POINTERS) {
                            sections.append(sec)
                        }
                        secPtr = secPtr.advanced(by: MemoryLayout<section_64>.size)
                    }
                }
            }
            cmdPtr = cmdPtr.advanced(by: Int(lc.cmdsize))
        }

        guard let symtab, let dysymtab, let linkedit else { return .empty }
        guard dysymtab.nindirectsyms > 0 else { return .empty }

        // Compute LINKEDIT base in memory.
        let linkeditBase = UInt64(Int64(linkedit.vmaddr) + slide) - UInt64(linkedit.fileoff)
        guard linkeditBase != 0 else { return .empty }

        let symPtr = UnsafeRawPointer(bitPattern: UInt(linkeditBase + UInt64(symtab.symoff)))
        let strPtr = UnsafeRawPointer(bitPattern: UInt(linkeditBase + UInt64(symtab.stroff)))
        let indirectPtr = UnsafeRawPointer(bitPattern: UInt(linkeditBase + UInt64(dysymtab.indirectsymoff)))
        guard
            let symPtr,
            let strPtr,
            let indirectPtr
        else { return .empty }

        let symbols = symPtr.bindMemory(to: nlist_64.self, capacity: Int(symtab.nsyms))
        let strings = strPtr.bindMemory(to: CChar.self, capacity: Int(symtab.strsize))
        let indirect = indirectPtr.bindMemory(to: UInt32.self, capacity: Int(dysymtab.nindirectsyms))

        var score: Double = 0
        var methods: [String] = []

        for sec in sections {
            let count = Int(sec.size / 8)
            if count <= 0 { continue }
            let startIndex = Int(sec.reserved1)
            if startIndex + count > Int(dysymtab.nindirectsyms) { continue }

            let tableAddr = UInt64(Int64(sec.addr) + slide)
            guard let tablePtr = UnsafeRawPointer(bitPattern: UInt(tableAddr)) else { continue }
            let ptrs = tablePtr.bindMemory(to: UInt64.self, capacity: count)

            for j in 0..<count {
                let symIndex = indirect[startIndex + j]
                if symIndex == UInt32(INDIRECT_SYMBOL_ABS) || symIndex == UInt32(INDIRECT_SYMBOL_LOCAL) { continue }
                if symIndex >= symtab.nsyms { continue }

                let n = symbols[Int(symIndex)]
                let strx = Int(n.n_un.n_strx)
                if strx <= 0 || strx >= Int(symtab.strsize) { continue }
                let rawName = String(cString: strings.advanced(by: strx))
                let name = rawName.hasPrefix("_") ? String(rawName.dropFirst()) : rawName
                guard let s = needles[name] else { continue }

                let target = ptrs[j]
                guard target != 0 else { continue }
                if isSystemAddress(target) { continue }

                score += s
                methods.append("indirect_ptr:\(name)")
                Logger.log("jailbreak.fishhook.hit: \(name) ptr=0x\(String(target, radix: 16)) (+\(s))")
            }
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func isSystemAddress(_ addr: UInt64) -> Bool {
        let p = UnsafeRawPointer(bitPattern: UInt(addr))
        guard let p else { return false }
        var info = Dl_info()
        guard dladdr(p, &info) != 0, let cPath = info.dli_fname else { return false }
        let path = String(cString: cPath)
        return path.hasPrefix("/usr/lib/") || path.hasPrefix("/System/Library/")
    }
}

