import CRiskCore
import Darwin
import Foundation

struct SysctlDetector: Detector {
    private var suspiciousProcessNeedles: [String] {
        ObfuscatedConstants.sysctlSuspiciousProcessNeedles
    }

    private var suspiciousParentNeedles: [String] {
        ObfuscatedConstants.sysctlSuspiciousParentNeedles
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        // Simulator behavior differs from real iOS devices and can false-positive.
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []
        let hookPrefix = "\(ObfuscatedConstants.keywordHook):"
        let logPrefix = "\(ObfuscatedConstants.keywordJailbreak).sysctl.hit: "

        // [4.4.7] ExpectedBaseline: 低版本上空进程列表视为被 Hook
        if let processList = readProcessList() {
            let infos = processList.infos
            score += 20
            methods.append("sysctl:process_list_access")
            Logger.log("\(logPrefix)process_list_access (+20)")

            if infos.isEmpty && ExpectedBaseline.emptyProcessListIsSuspicious {
                score += 20
                methods.append("\(hookPrefix)empty_process_list_suspicious")
                Logger.log("\(logPrefix)empty_process_list_suspicious (+20)")
            }

            if processList.tampered {
                score += 18
                methods.append("\(hookPrefix)sysctl_process_list_mismatch")
                Logger.log("\(logPrefix)process_list_mismatch (+18)")
            }

            if processList.traced {
                score += 25
                methods.append("dbi_stalker_traced:process_list")
                Logger.log("\(logPrefix)dbi_stalker_traced process_list (+25)")
            }

            if infos.count > 400 {
                score += 10
                methods.append("sysctl:process_count:\(infos.count)")
                Logger.log("\(logPrefix)process_count=\(infos.count) (+10)")
            }

            let suspicious = suspiciousProcessesFound(infos: infos)
            if !suspicious.isEmpty {
                score += 22
                for name in suspicious.prefix(3) {
                    methods.append("proc:\(name)")
                }
                Logger.log("\(logPrefix)suspicious_processes=\(suspicious.joined(separator: ",")) (+22)")
            }
        } else if ExpectedBaseline.emptyProcessListIsSuspicious {
            // [4.4.7] 无法读取进程列表（nil）在低版本上视为被 Hook
            score += 20
            methods.append("\(hookPrefix)empty_process_list_suspicious")
            Logger.log("\(logPrefix)empty_process_list_suspicious (nil) (+20)")
        }

        let parentLookup = parentProcessName()
        if parentLookup.tampered {
            score += 12
            methods.append("\(hookPrefix)sysctl_parent_lookup_mismatch")
            Logger.log("\(logPrefix)parent_lookup_mismatch (+12)")
        }

        if let parent = parentLookup.name, isSuspiciousParent(parent) {
            score += 20
            methods.append("parent:\(parent)")
            Logger.log("\(logPrefix)parent_process=\(parent) (+20)")
        }

        let debugger = debuggerStatus()
        if debugger.tampered {
            score += 12
            methods.append("\(hookPrefix)sysctl_pid_flags_mismatch")
            Logger.log("\(logPrefix)pid_flags_mismatch (+12)")
        }

        if debugger.attached {
            score += 10
            methods.append("sysctl:debugger_attached")
            Logger.log("\(logPrefix)debugger_attached (+10)")
        }

        let criticalSysctlKeys = ["hw.machine", "hw.model", "kern.osversion"]
        for key in criticalSysctlKeys {
            let (_, tampered, bypassed, traced, _) = DualPathValidator.validateSysctl(key: key)
            if tampered {
                score += 25
                methods.append("sysctl_dual_path_mismatch:\(key)")
                Logger.log("\(logPrefix)dual_path_mismatch key=\(key) (+25)")
            }
            if bypassed {
                score += 20
                methods.append("sysctl_short_circuit_\(ObfuscatedConstants.keywordHook):\(key)")
                Logger.log("\(logPrefix)short_circuit \(ObfuscatedConstants.keywordHook) key=\(key) (+20)")
            }
            if traced {
                score += 25
                methods.append("dbi_stalker_traced:\(key)")
                Logger.log("\(logPrefix)dbi_stalker_traced key=\(key) (+25)")
            }
        }

        return DetectorResult(score: min(score, 85), methods: methods)
#endif
    }

    private struct SysctlDataResult {
        var data: Data
        var tampered: Bool
        var traced: Bool
    }

    private struct ProcessListResult {
        var infos: [kinfo_proc]
        var tampered: Bool
        var traced: Bool
    }

    private struct ProcessInfoResult {
        var info: kinfo_proc
        var tampered: Bool
        var traced: Bool
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
        return ProcessListResult(infos: out, tampered: result.tampered, traced: result.traced)
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
        let ppid = cprisk_getppid_direct()
        guard let result = readProcessInfo(pid: ppid) else { return (nil, true) }
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
        return ProcessInfoResult(info: info, tampered: result.tampered, traced: result.traced)
    }

    private func debuggerStatus() -> (attached: Bool, tampered: Bool) {
        guard let result = readProcessInfo(pid: cprisk_getpid_direct()) else { return (false, false) }
        let attached = (result.info.kp_proc.p_flag & P_TRACED) != 0
        return (attached, result.tampered)
    }

    private func readSysctlData(mib: [Int32]) -> SysctlDataResult? {
        let validation = DualPathValidator.validateSysctlData(mib: mib)
        guard let data = validation.data, !data.isEmpty else { return nil }
        return SysctlDataResult(data: data, tampered: validation.tampered, traced: validation.traced)
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
