import Foundation
import MachOKit

private enum InjectMode {
    case fnv
    case hmac
}

private func usage() -> Never {
    FileHandle.standardError.write(Data("""
        usage: cprisk-vm-self-expect --in <mach-o-path> [--fnv | --hmac] [--material-hex <64-hex-chars>]

        Post-link: writes __DATA,__swift5_mdvsk (LE u32 magic + LE u32 FNV-1a or CPSH tag). The hashed
        TEXT windows are taken from __DATA,__swift5_mdvsi (CPSV) when present; otherwise from symtab
        symbols _cprisk_vm_execute, _cprisk_vm_interp_loop_a, _cprisk_vm_dispatch_lookup — matching
        CRiskCore cprisk_vm_interpreter.c (48 + 64 + 64 byte prefixes).

          --fnv          Write CPSF + FNV-1a (default).
          --hmac         Write CPSH + custom-pad HMAC-SHA256 tag (first 4 bytes LE).
          --material-hex 32-byte runtime material as 64 hex digits (HMAC key derivation; default: all zero).

        """.utf8))
    exit(2)
}

private func parseMaterialHex(_ s: String) throws -> Data {
    let hex = s.filter { !$0.isWhitespace }
    guard hex.count == 64 else {
        throw MachOError.invalidData("--material-hex must be exactly 64 hex characters")
    }
    var out = Data()
    out.reserveCapacity(32)
    var i = hex.startIndex
    while i < hex.endIndex {
        let j = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
        guard let b = UInt8(String(hex[i..<j]), radix: 16) else {
            throw MachOError.invalidData("--material-hex contains non-hex data")
        }
        out.append(b)
        i = j
    }
    return out
}

@main
struct CLI {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        guard !args.isEmpty else { usage() }

        var inPath: String?
        var mode: InjectMode = .fnv
        var materialHex: String?
        var i = args.startIndex
        while i < args.endIndex {
            let a = args[i]
            switch a {
            case "--in":
                let n = args.index(after: i)
                guard n < args.endIndex else { usage() }
                inPath = args[n]
                i = args.index(after: n)
            case "--fnv":
                mode = .fnv
                i = args.index(after: i)
            case "--hmac":
                mode = .hmac
                i = args.index(after: i)
            case "--material-hex":
                let n = args.index(after: i)
                guard n < args.endIndex else { usage() }
                materialHex = args[n]
                i = args.index(after: n)
            default:
                usage()
            }
        }
        guard let path = inPath else { usage() }
        let url = URL(fileURLWithPath: path, isDirectory: false)

        do {
            switch mode {
            case .fnv:
                let r = try VMSelfExpectInjector.inject(into: url)
                let fnvHex = String(format: "%08x", r.fnvExpect)
                let names = r.resolvedSymbolNames.joined(separator: ",")
                let vmaddrs = r.symbolVMAddresses.map { String(format: "0x%llx", $0) }.joined(separator: ",")
                let fileoffs = r.fileOffsets.map { String($0) }.joined(separator: ",")
                let span = r.usedCPSVSpanMap ? "cpsv" : "symtab"
                print(
                    "cprisk-vm-self-expect: ok mode=fnv fnv=0x\(fnvHex) source=\(span) symbols=\(names) vmaddr=\(vmaddrs) fileoff=\(fileoffs)"
                )
            case .hmac:
                let mat: Data?
                if let h = materialHex {
                    mat = try parseMaterialHex(h)
                } else {
                    mat = nil
                }
                let r = try VMSelfExpectInjector.injectHmac(into: url, runtimeMaterial32: mat)
                let tagHex = String(format: "%08x", r.fnvExpect)
                let names = r.resolvedSymbolNames.joined(separator: ",")
                let vmaddrs = r.symbolVMAddresses.map { String(format: "0x%llx", $0) }.joined(separator: ",")
                let fileoffs = r.fileOffsets.map { String($0) }.joined(separator: ",")
                let span = r.usedCPSVSpanMap ? "cpsv" : "symtab"
                print(
                    "cprisk-vm-self-expect: ok mode=hmac tag=0x\(tagHex) source=\(span) symbols=\(names) vmaddr=\(vmaddrs) fileoff=\(fileoffs)"
                )
            }
        } catch {
            FileHandle.standardError.write(Data("cprisk-vm-self-expect: error: \(error)\n".utf8))
            exit(1)
        }
    }
}
