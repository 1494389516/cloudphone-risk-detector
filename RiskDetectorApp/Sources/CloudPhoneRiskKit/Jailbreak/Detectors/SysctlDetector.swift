import Darwin
import Foundation

struct SysctlDetector: Detector {
    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        // Simulator behavior differs from real iOS devices and can false-positive.
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []

        if let infos = readProcessList() {
            score += 20
            methods.append("sysctl:process_list_access")
            Logger.log("jailbreak.sysctl.hit: process_list_access (+20)")

            if infos.count > 400 {
                score += 10
                methods.append("sysctl:process_count:\(infos.count)")
                Logger.log("jailbreak.sysctl.hit: process_count=\(infos.count) (+10)")
            }

            let suspicious = suspiciousProcessesFound(infos: infos)
            if !suspicious.isEmpty {
                score += 22
                for name in suspicious.prefix(3) {
                    methods.append("proc:\(name)")
                }
                Logger.log("jailbreak.sysctl.hit: suspicious_processes=\(suspicious.joined(separator: ",")) (+22)")
            }
        }

        if let parent = parentProcessName(), isSuspiciousParent(parent) {
            score += 20
            methods.append("parent:\(parent)")
            Logger.log("jailbreak.sysctl.hit: parent_process=\(parent) (+20)")
        }

        if isDebuggerAttached() {
            score += 10
            methods.append("sysctl:debugger_attached")
            Logger.log("jailbreak.sysctl.hit: debugger_attached (+10)")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    private func readProcessList() -> [kinfo_proc]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var length: size_t = 0
        guard sysctl(&mib, 4, nil, &length, nil, 0) == 0, length > 0 else { return nil }

        let buf = UnsafeMutableRawPointer.allocate(byteCount: length, alignment: MemoryLayout<kinfo_proc>.alignment)
        defer { buf.deallocate() }
        guard sysctl(&mib, 4, buf, &length, nil, 0) == 0, length > 0 else { return nil }

        let count = Int(length) / MemoryLayout<kinfo_proc>.stride
        let infos = buf.bindMemory(to: kinfo_proc.self, capacity: count)
        var out: [kinfo_proc] = []
        out.reserveCapacity(min(count, 512))
        for i in 0..<min(count, 512) {
            out.append(infos[i])
        }
        return out
    }

    private func suspiciousProcessesFound(infos: [kinfo_proc]) -> [String] {
        let suspicious = [
            "cydia",
            "sileo",
            "filza",
            "sshd",
            "dropbear",
            "frida",
            "debugserver",
            "cycript",
            "substrated",
            "apt",
            "dpkg",
        ]
        var found: [String] = []
        found.reserveCapacity(3)

        for info in infos {
            let n = processComm(info).lowercased()
            if let hit = suspicious.first(where: { n.contains($0) }) {
                found.append(hit)
                if found.count >= 3 { break }
            }
        }
        return Array(Set(found)).sorted()
    }

    private func processComm(_ info: kinfo_proc) -> String {
        // kinfo_proc.kp_proc.p_comm is a fixed-size C char array.
        let bytes = withUnsafeBytes(of: info.kp_proc.p_comm) { raw in
            Array(raw.prefix { $0 != 0 })
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private func parentProcessName() -> String? {
        let ppid = getppid()
        guard let info = readProcessInfo(pid: ppid) else { return nil }
        let name = processComm(info)
        return name.isEmpty ? nil : name
    }

    private func isSuspiciousParent(_ name: String) -> Bool {
        let needles = ["cydia", "sileo", "filza", "frida", "debugserver"]
        let n = name.lowercased()
        return needles.contains(where: { n.contains($0) })
    }

    private func readProcessInfo(pid: Int32) -> kinfo_proc? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
        return info
    }

    private func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.size
        let sysctlResult = sysctl(&mib, 4, &info, &size, nil, 0)
        guard sysctlResult == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
}
