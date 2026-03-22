import Foundation
import MachOKit

private func usage() -> Never {
    FileHandle.standardError.write(Data("""
        usage: cprisk-vm-self-expect --in <mach-o-path>

        Post-link: writes __DATA,__swift5_mdvsk (LE u32 magic + LE u32 FNV-1a) from the first
        96 bytes of _cprisk_vm_execute, matching CRiskCore cprisk_vm_interpreter.c.

        """.utf8))
    exit(2)
}

@main
struct CLI {
    static func main() {
        let args = CommandLine.arguments
        guard args.count == 3, args[1] == "--in" else {
            usage()
        }
        let url = URL(fileURLWithPath: args[2], isDirectory: false)
        do {
            let r = try VMSelfExpectInjector.inject(into: url)
            let fnvHex = String(format: "%08x", r.fnvExpect)
            print(
                "cprisk-vm-self-expect: ok fnv=0x\(fnvHex) symbol=\(r.resolvedSymbolName) vmaddr=0x\(String(r.symbolVMA, radix: 16)) fileoff=\(r.fileOffset)"
            )
        } catch {
            FileHandle.standardError.write(Data("cprisk-vm-self-expect: error: \(error)\n".utf8))
            exit(1)
        }
    }
}
