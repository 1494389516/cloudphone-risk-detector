import Darwin
import Foundation

struct SysctlDetector: Detector {
    let suspiciousProcessNeedles: [String] = [
        "cydia",
        "sileo",
        "filza",
        "sshd",
        "dropbear",
        "frida",
        "debugserver",
        "cycript",
        "substrated",
        "substitute",
        "ellekit",
        "apt",
        "dpkg",
    ]

    let suspiciousParentNeedles: [String] = [
        "cydia",
        "sileo",
        "filza",
        "frida",
        "debugserver",
        "lldb",
        "gdb",
    ]

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        // Simulator behavior differs from real iOS devices and can false-positive.
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []

        if let processList = readProcessList() {
            let infos = processList.infos
            score += 20
            methods.append("sysctl:process_list_access")
            Logger.log("jailbreak.sysctl.hit: process_list_access (+20)")

            if processList.tampered {
                score += 18
                methods.append("hook:sysctl_process_list_mismatch")
                Logger.log("jailbreak.sysctl.hit: process_list_mismatch (+18)")
            }

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

        let parentLookup = parentProcessName()
        if parentLookup.tampered {
            score += 12
            methods.append("hook:sysctl_parent_lookup_mismatch")
            Logger.log("jailbreak.sysctl.hit: parent_lookup_mismatch (+12)")
        }

        if let parent = parentLookup.name, isSuspiciousParent(parent) {
            score += 20
            methods.append("parent:\(parent)")
            Logger.log("jailbreak.sysctl.hit: parent_process=\(parent) (+20)")
        }

        let debugger = debuggerStatus()
        if debugger.tampered {
            score += 12
            methods.append("hook:sysctl_pid_flags_mismatch")
            Logger.log("jailbreak.sysctl.hit: pid_flags_mismatch (+12)")
        }

        if debugger.attached {
            score += 10
            methods.append("sysctl:debugger_attached")
            Logger.log("jailbreak.sysctl.hit: debugger_attached (+10)")
        }

        let criticalSysctlKeys = ["hw.machine", "hw.model", "kern.osversion"]
        for key in criticalSysctlKeys {
            let (_, tampered) = DualPathValidator.validateSysctl(key: key)
            if tampered {
                score += 25
                methods.append("sysctl_dual_path_mismatch:\(key)")
                Logger.log("jailbreak.sysctl.hit: dual_path_mismatch key=\(key) (+25)")
            }
        }

        return DetectorResult(score: min(score, 85), methods: methods)
#endif
    }

    private struct SysctlDataResult {
        var data: Data
        var tampered: Bool
    }

    private struct ProcessListResult {
        var infos: [kinfo_proc]
        var tampered: Bool
    }

    private struct ProcessInfoResult {
        var info: kinfo_proc
        var tampered: Bool
    }

    private func readProcessList() -> ProcessListResult? {
        guard let result = readSysctlData(mib: [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]) else { return nil }

        let count = result.data.count / MemoryLayout<kinfo_proc>.stride
        guard count > 0 else { return nil }

        var out: [kinfo_proc] = []
        out.reserveCapacity(min(count, 512))
        result.data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            let infos = baseAddress.bindMemory(to: kinfo_proc.self, capacity: count)
            for i in 0..<min(count, 512) {
                out.append(infos[i])
            }
        }
        return ProcessListResult(infos: out, tampered: result.tampered)
    }

    private func suspiciousProcessesFound(infos: [kinfo_proc]) -> [String] {
        var found: [String] = []
        found.reserveCapacity(3)

        for info in infos {
            let n = processComm(info)
            if let hit = firstSuspiciousProcessToken(in: n) {
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

    private func parentProcessName() -> (name: String?, tampered: Bool) {
        let ppid = getppid()
        guard let result = readProcessInfo(pid: ppid) else { return (nil, false) }
        let name = processComm(result.info)
        return (name.isEmpty ? nil : name, result.tampered)
    }

    private func isSuspiciousParent(_ name: String) -> Bool {
        firstSuspiciousParentToken(in: name) != nil
    }

    private func readProcessInfo(pid: Int32) -> ProcessInfoResult? {
        guard let result = readSysctlData(mib: [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]) else { return nil }
        guard result.data.count >= MemoryLayout<kinfo_proc>.size else { return nil }

        var info = kinfo_proc()
        withUnsafeMutableBytes(of: &info) { rawBuffer in
            rawBuffer.copyBytes(from: result.data.prefix(MemoryLayout<kinfo_proc>.size))
        }
        return ProcessInfoResult(info: info, tampered: result.tampered)
    }

    private func debuggerStatus() -> (attached: Bool, tampered: Bool) {
        guard let result = readProcessInfo(pid: getpid()) else { return (false, false) }
        let attached = (result.info.kp_proc.p_flag & P_TRACED) != 0
        return (attached, result.tampered)
    }

    private func readSysctlData(mib: [Int32]) -> SysctlDataResult? {
        let validation = DualPathValidator.validateSysctlData(mib: mib)
        guard let data = validation.data, !data.isEmpty else { return nil }
        return SysctlDataResult(data: data, tampered: validation.tampered)
    }

    func firstSuspiciousProcessToken(in processName: String) -> String? {
        let normalized = normalizeProcessName(processName)
        return suspiciousProcessNeedles.first(where: { normalized.contains($0) })
    }

    func firstSuspiciousParentToken(in parentProcessName: String) -> String? {
        let normalized = normalizeProcessName(parentProcessName)
        return suspiciousParentNeedles.first(where: { normalized.contains($0) })
    }

    func normalizeProcessName(_ name: String) -> String {
        name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
