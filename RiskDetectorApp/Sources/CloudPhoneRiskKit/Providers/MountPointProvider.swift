import Darwin
import Foundation

#if targetEnvironment(simulator)
final class MountPointProvider: RiskSignalProvider {
    static let shared = MountPointProvider()
    private init() {}
    let id = "mount_point"
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        return [
            RiskSignal(
                id: "mount_unavailable",
                category: "device",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 2,
                weightHint: 0
            ),
        ]
    }
}
#else
private let virtualFSBlacklist: [String] = [
    "virtfs", "9p", "virtiofs", "fuse", "overlay", "aufs", "vboxsf", "vmhgfs",
]

private func extractCString<T>(from tuple: T) -> String {
    withUnsafePointer(to: tuple) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) {
            String(cString: $0)
        }
    }
}

final class MountPointProvider: RiskSignalProvider {
    static let shared = MountPointProvider()
    private init() {}
    let id = "mount_point"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var mntbuf: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&mntbuf, MNT_NOWAIT)
        guard count > 0, let buf = mntbuf else {
            Logger.log("mount_point: getmntinfo failed")
            return [
                RiskSignal(
                    id: "mount_unavailable",
                    category: "device",
                    score: 0,
                    evidence: ["detail": "getmntinfo_failed"],
                    state: .unavailable,
                    layer: 2,
                    weightHint: 0
                ),
            ]
        }

        var out: [RiskSignal] = []
        var hasApfs = false
        var hasRoot = false
        var hitVirtualFS: String?
        let mountCount = Int(count)

        for i in 0..<count {
            let stat = buf[Int(i)]
            let fsType = extractCString(from: stat.f_fstypename)
            let mnton = extractCString(from: stat.f_mntonname)
            let fsLower = fsType.lowercased()
            let mntonNorm = mnton.trimmingCharacters(in: .whitespaces)

            if fsLower == "apfs" { hasApfs = true }
            if mntonNorm == "/" { hasRoot = true }

            if hitVirtualFS == nil {
                for black in virtualFSBlacklist {
                    if fsLower.contains(black) {
                        hitVirtualFS = fsType
                        break
                    }
                }
            }
        }

        if let vfs = hitVirtualFS {
            out.append(
                RiskSignal(
                    id: "mount_virtual_fs",
                    category: "device",
                    score: 0,
                    evidence: ["fstype": vfs],
                    state: .soft(confidence: 0.85),
                    layer: 2,
                    weightHint: 75
                )
            )
        }

        if !hasApfs || !hasRoot {
            var missing: [String] = []
            if !hasApfs { missing.append("apfs") }
            if !hasRoot { missing.append("/") }
            out.append(
                RiskSignal(
                    id: "mount_missing_required",
                    category: "device",
                    score: 0,
                    evidence: ["missing": missing.joined(separator: ",")],
                    state: .soft(confidence: 0.6),
                    layer: 2,
                    weightHint: 60
                )
            )
        }

        if mountCount < 2 || mountCount > 30 {
            out.append(
                RiskSignal(
                    id: "mount_count_anomaly",
                    category: "device",
                    score: 0,
                    evidence: ["count": "\(mountCount)"],
                    state: .soft(confidence: 0.5),
                    layer: 2,
                    weightHint: 45
                )
            )
        }

        return out
    }
}
#endif
