import Foundation
import MachOKit

private enum InjectMode {
    case fnv
    case hmac
}

private func usage() -> Never {
    FileHandle.standardError.write(Data("""
        usage: cprisk-vm-self-expect --in <mach-o-path> [--hmac | --fnv] [--material-hex <64-hex-chars>] [--allow-zero-material]

        Post-link: writes __DATA,__swift5_mdvsk (LE u32 magic + LE u32 FNV-1a or CPSH tag). The hashed
        TEXT windows are taken from __DATA,__swift5_mdvsi (CPSV) when present; otherwise from symtab
        symbols _cprisk_vm_execute, _cprisk_vm_interp_loop_a, _cprisk_vm_dispatch_lookup — matching
        CRiskCore cprisk_vm_interpreter.c (48 + 64 + 64 byte prefixes).

          --hmac         Write CPSH + custom-pad HMAC-SHA256 tag (first 4 bytes LE). DEFAULT (keyed).
          --fnv          Write CPSF + keyless FNV-1a. WEAK: no secret — anyone who edits the TEXT
                         windows can recompute the expected value. Compatibility / no-key use only.
          --material-hex 32-byte runtime material as 64 hex digits (HMAC key derivation). REQUIRED for
                         --hmac in production: must match runtime cprisk_get_runtime_material.
          --allow-zero-material
                         Permit --hmac with all-zero material (CI / fixtures only). Without it, --hmac
                         refuses to run when --material-hex is absent — a zero key lets an attacker
                         recompute the self-check tag after patching the TEXT windows.

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
        // Default to the keyed HMAC path. The keyless FNV path is opt-in (--fnv) because its
        // expected value carries no secret and is trivially recomputable after a TEXT patch.
        var mode: InjectMode = .hmac
        var materialHex: String?
        var allowZeroMaterial = false
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
            case "--allow-zero-material":
                allowZeroMaterial = true
                i = args.index(after: i)
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
                FileHandle.standardError.write(Data(
                    "cprisk-vm-self-expect: WARNING: --fnv writes a keyless self-check; the expected value is recomputable after a TEXT patch. Prefer --hmac with real runtime material for shipping builds.\n".utf8
                ))
                print(
                    "cprisk-vm-self-expect: ok mode=fnv fnv=0x\(fnvHex) source=\(r.source.rawValue) symbols=\(names) vmaddr=\(vmaddrs) fileoff=\(fileoffs)"
                )
            case .hmac:
                let mat: Data?
                if let h = materialHex {
                    mat = try parseMaterialHex(h)
                } else if allowZeroMaterial {
                    // injectHmac defaults to 32 zero bytes when mat == nil.
                    mat = nil
                    FileHandle.standardError.write(Data(
                        "cprisk-vm-self-expect: WARNING: --hmac with all-zero material (CI mode). The self-check tag is recomputable; DO NOT ship this artifact.\n".utf8
                    ))
                } else {
                    FileHandle.standardError.write(Data(
                        "cprisk-vm-self-expect: error: --hmac requires --material-hex (or --allow-zero-material for CI). Refusing to write a zero-key self-check that an attacker could forge.\n".utf8
                    ))
                    exit(2)
                }
                let r = try VMSelfExpectInjector.injectHmac(into: url, runtimeMaterial32: mat)
                let tagHex = String(format: "%08x", r.fnvExpect)
                let names = r.resolvedSymbolNames.joined(separator: ",")
                let vmaddrs = r.symbolVMAddresses.map { String(format: "0x%llx", $0) }.joined(separator: ",")
                let fileoffs = r.fileOffsets.map { String($0) }.joined(separator: ",")
                print(
                    "cprisk-vm-self-expect: ok mode=hmac tag=0x\(tagHex) source=\(r.source.rawValue) symbols=\(names) vmaddr=\(vmaddrs) fileoff=\(fileoffs)"
                )
            }
        } catch {
            FileHandle.standardError.write(Data("cprisk-vm-self-expect: error: \(error)\n".utf8))
            exit(1)
        }
    }
}
