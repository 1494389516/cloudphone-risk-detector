import CRiskCore
import Darwin
import Foundation

// MARK: - Direct Syscall Cross-Validator
//
// KernelHookSideChannel / FridaSocketDetector 的时序侧信道属于概率型检测，
// 依赖 Frida Stalker 的 DBT 开销。不使用 Stalker 的 hook 工具时序异常不明显。
//
// 本检测器采用"结果一致性"验证——确定性检测，非概率型：
// - 通过 libc 包装器调用系统调用（可能被 hook 篡改返回值）
// - 通过 CRiskCore 直接 SVC #0x80 调用同一系统调用（绕过 libc hook）
// - 比较两条路径的返回值：不一致 = libc 层存在活跃 hook 且正在篡改结果
//
// 探针维度：
// 1. getpid()  vs  cprisk_getpid_direct()   — 最小化测试，不可能自然不一致
// 2. stat()    vs  cprisk_stat_direct()      — 文件存在性交叉验证
// 3. access()  vs  cprisk_access_direct()    — 文件权限交叉验证
//
// 覆盖场景：Substrate/Dobby/Ellekit/fishhook 对 libc 函数的 hook；
//           越狱隐藏工具（如 Shadow、A-Bypass）篡改文件检测结果

struct DirectSyscallCrossValidator: Detector {

    // MARK: - Test Probes

    /// File paths that must exist on any stock iOS device.
    /// We probe these to check if libc returns the same result as a direct SVC.
    private static let probePaths: [String] = [
        "/usr/lib/dyld",
        "/bin/sh",
        "/usr/lib/system/libsystem_kernel.dylib",
        "/usr/lib/system/libsystem_pthread.dylib",
    ]

    /// A path that should NOT exist — used to verify consistent "not found" responses.
    private static let nonExistentPath = "/var/tmp/cprisk_probe_nonexistent_\(arc4random())"

    // MARK: - Scoring
    private static let scoreGetpidMismatch: Double   = 40  // Almost impossible without hook
    private static let scoreStatMismatch: Double     = 30  // Strong indicator
    private static let scoreAccessMismatch: Double   = 25
    private static let scoreMultiMismatch: Double    = 20  // Bonus for ≥2 mismatches
    private static let maxScore: Double              = 80

    // MARK: - Detector Protocol

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dscv:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    @inline(never)
    private func detectKernel() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        var mismatchCount = 0

        // --- Probe 1: getpid consistency ---
        let libcPid = getpid()
        let directPid = cprisk_getpid_direct()
        if libcPid != directPid {
            score += Self.scoreGetpidMismatch
            methods.append("dscv:getpid_mismatch:\(libcPid)_vs_\(directPid)")
            mismatchCount += 1
        }

        // --- Probe 2: stat() consistency ---
        let statMismatches = checkStatConsistency()
        if statMismatches > 0 {
            score += Self.scoreStatMismatch
            methods.append("dscv:stat_mismatch:\(statMismatches)")
            mismatchCount += 1
        }

        // --- Probe 3: access() consistency ---
        let accessMismatches = checkAccessConsistency()
        if accessMismatches > 0 {
            score += Self.scoreAccessMismatch
            methods.append("dscv:access_mismatch:\(accessMismatches)")
            mismatchCount += 1
        }

        // Multi-mismatch bonus: multiple hooked syscalls = active instrumentation
        if mismatchCount >= 2 {
            score += Self.scoreMultiMismatch
            methods.append("dscv:multi_mismatch:\(mismatchCount)")
        }

        if methods.isEmpty {
            methods.append("dscv:clean")
        }

        return DetectorResult(score: min(score, Self.maxScore), methods: methods)
    }

    // MARK: - stat() Cross-Check

    /// Returns the number of probe paths where libc `stat` and CRiskCore `stat_direct` disagree.
    private func checkStatConsistency() -> Int {
        var mismatches = 0

        for path in Self.probePaths {
            let (libcExists, directExists) = statBothPaths(path)
            if libcExists != directExists {
                mismatches += 1
            }
        }

        // Also check non-existent path — hook may fabricate existence
        let (libcNonExist, directNonExist) = statBothPaths(Self.nonExistentPath)
        if libcNonExist != directNonExist {
            mismatches += 1
        }

        return mismatches
    }

    /// Returns (libcSuccess, directSuccess) for stat() on a given path.
    private func statBothPaths(_ path: String) -> (Bool, Bool) {
        var libcSb = stat()
        let libcRc = path.withCString { cPath in
            Darwin.lstat(cPath, &libcSb)
        }

        var directSb = stat()
        let directRc = path.withCString { cPath in
            cprisk_stat_direct(cPath, &directSb, nil)
        }

        return (libcRc == 0, directRc == 0)
    }

    // MARK: - access() Cross-Check

    /// Returns the number of probe paths where libc `access` and CRiskCore `access_direct` disagree.
    private func checkAccessConsistency() -> Int {
        var mismatches = 0

        for path in Self.probePaths {
            let (libcOK, directOK) = accessBothPaths(path, mode: F_OK)
            if libcOK != directOK {
                mismatches += 1
            }
        }

        // Non-existent path: both should return error (-1)
        let (libcNonExist, directNonExist) = accessBothPaths(Self.nonExistentPath, mode: F_OK)
        if libcNonExist != directNonExist {
            mismatches += 1
        }

        return mismatches
    }

    /// Returns (libcSuccess, directSuccess) for access() on a given path.
    private func accessBothPaths(_ path: String, mode: Int32) -> (Bool, Bool) {
        let libcRc = path.withCString { cPath in
            Darwin.access(cPath, mode)
        }

        let directRc = path.withCString { cPath in
            cprisk_access_direct(cPath, mode, nil)
        }

        return (libcRc == 0, directRc == 0)
    }
}

// MARK: - Signal Bridge

extension DirectSyscallCrossValidator {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        let hasGetpidMismatch = result.methods.contains(where: { $0.hasPrefix("dscv:getpid_mismatch") })
        let hasStatMismatch = result.methods.contains(where: { $0.hasPrefix("dscv:stat_mismatch") })

        return [RiskSignal(
            id: "syscall_result_mismatch",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: result.score,
            evidence: [
                "getpid_mismatch": hasGetpidMismatch ? "1" : "0",
                "stat_mismatch": hasStatMismatch ? "1" : "0",
                "channels": "\(result.methods.filter { !$0.hasSuffix(":clean") }.count)",
            ],
            state: hasGetpidMismatch ? .hard(detected: true) : .soft(confidence: 0.85),
            layer: 2,
            weightHint: 85
        )]
    }
}
