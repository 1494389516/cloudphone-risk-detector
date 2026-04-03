import Darwin
import Foundation

/// Detects unidbg / Unicorn-engine emulation by inspecting process-context
/// fingerprints that differ between a real iOS app and a unidbg-hosted JNI
/// execution on a Linux host.
///
/// ## Threat model
/// unidbg runs as a JVM process on Linux. The emulated native code sees a
/// synthetic process environment assembled by unidbg's emulation layer.
/// Several invariants that hold on real iOS are absent or anomalous.
///
/// Each signal contributes a partial score; the composite is capped at 40
/// to act as a supplementary factor alongside EmulatorLayoutDetector.
struct EmulatorBehaviorDetector: Detector {

    // MARK: - Score constants

    private enum Score {
        static let suspiciousProcessName: Double  = 12
        static let threadCountAnomaly: Double     = 8
        static let jvmEnvVarPresent: Double       = 14
        static let kernelOSTypeAnomaly: Double    = 8
        static let cpuTimeStalled: Double         = 6
        static let max: Double                    = 40
    }

    // MARK: - Detector

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["emulator_behavior:unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // ── 1. Process name ──────────────────────────────────────────────────
        if checkProcessName() {
            score += Score.suspiciousProcessName
            methods.append("emulator_behavior:suspicious_process_name")
        } else {
            methods.append("emulator_behavior:process_name_ok")
        }

        // ── 2. Thread count ──────────────────────────────────────────────────
        let threadCount = countActiveThreads()
        if threadCount > 0 && threadCount < 4 {
            score += Score.threadCountAnomaly
            methods.append("emulator_behavior:low_thread_count(\(threadCount))")
        } else {
            methods.append("emulator_behavior:thread_count_ok(\(threadCount))")
        }

        // ── 3. JVM indicator environment variables ───────────────────────────
        if jvmEnvVarsPresent() {
            score += Score.jvmEnvVarPresent
            methods.append("emulator_behavior:jvm_env_var_found")
        } else {
            methods.append("emulator_behavior:env_clean")
        }

        // ── 4. kern.ostype sysctl ────────────────────────────────────────────
        if !kernelOSTypeIsDarwin() {
            score += Score.kernelOSTypeAnomaly
            methods.append("emulator_behavior:ostype_anomaly")
        } else {
            methods.append("emulator_behavior:ostype_ok")
        }

        // ── 5. CLOCK_PROCESS_CPUTIME_ID advance ─────────────────────────────
        if cpuClockAppearsStalled() {
            score += Score.cpuTimeStalled
            methods.append("emulator_behavior:cpu_clock_stalled")
        } else {
            methods.append("emulator_behavior:cpu_clock_ok")
        }

        return DetectorResult(score: min(score, Score.max), methods: methods)
#endif
    }

    // MARK: - Private probes

    // All sentinel strings are XOR-obfuscated with key 0x55 to prevent
    // trivial string-scan discovery of the detection logic.

    /// Returns true if the process name resembles a JVM launcher or unidbg stub.
    private func checkProcessName() -> Bool {
        // Sentinels XOR 0x55:
        //   "java"    → [0x3F, 0x34, 0x23, 0x34]
        //   "unidbg"  → [0x20, 0x3B, 0x3C, 0x31, 0x37, 0x32]
        //   "qemu"    → [0x24, 0x30, 0x38, 0x20]
        //   "unicorn" → [0x20, 0x3B, 0x3C, 0x36, 0x3A, 0x27, 0x3B]
        let sentinels: [[UInt8]] = [
            [0x3F, 0x34, 0x23, 0x34],
            [0x20, 0x3B, 0x3C, 0x31, 0x37, 0x32],
            [0x24, 0x30, 0x38, 0x20],
            [0x20, 0x3B, 0x3C, 0x36, 0x3A, 0x27, 0x3B],
        ]

        let processName = ProcessInfo.processInfo.processName.lowercased()
        guard !processName.isEmpty else { return true }

        for sentinel in sentinels {
            let decoded = String(sentinel.map { Character(UnicodeScalar($0 ^ 0x55)) })
            if processName.contains(decoded) { return true }
        }

        // Suspicious: path separators in process name (unidbg may pass full path).
        if processName.contains("/") { return true }

        return false
    }

    /// Returns the number of active Mach threads in the current task, or 0 on error.
    private func countActiveThreads() -> Int {
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &threadList, &threadCount) == KERN_SUCCESS,
              let list = threadList else { return 0 }
        let count = Int(threadCount)
        for i in 0..<count { mach_port_deallocate(mach_task_self_, list[i]) }
        vm_deallocate(mach_task_self_,
                      vm_address_t(UInt(bitPattern: list)),
                      vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.stride))
        return count
    }

    /// Returns true if any JVM-indicator environment variable is set.
    ///
    /// Env var names XOR-obfuscated with key 0x1F:
    ///   "JAVA_HOME"       → [0x55, 0x5E, 0x49, 0x5E, 0x40, 0x57, 0x50, 0x52, 0x5A]
    ///   "CLASSPATH"       → [0x5C, 0x53, 0x5E, 0x4C, 0x4C, 0x4F, 0x5E, 0x4B, 0x57]
    ///   "JVM_ARGS"        → [0x55, 0x49, 0x52, 0x40, 0x5E, 0x4D, 0x58, 0x4C]
    ///   "LD_LIBRARY_PATH" → [0x53, 0x5B, 0x40, 0x53, 0x56, 0x5D, 0x4D, 0x5E,
    ///                        0x4D, 0x46, 0x40, 0x4F, 0x5E, 0x4B, 0x57]
    private func jvmEnvVarsPresent() -> Bool {
        let candidates: [[UInt8]] = [
            [0x55, 0x5E, 0x49, 0x5E, 0x40, 0x57, 0x50, 0x52, 0x5A],
            [0x5C, 0x53, 0x5E, 0x4C, 0x4C, 0x4F, 0x5E, 0x4B, 0x57],
            [0x55, 0x49, 0x52, 0x40, 0x5E, 0x4D, 0x58, 0x4C],
            [0x53, 0x5B, 0x40, 0x53, 0x56, 0x5D, 0x4D, 0x5E,
             0x4D, 0x46, 0x40, 0x4F, 0x5E, 0x4B, 0x57],
        ]
        let env = ProcessInfo.processInfo.environment
        for candidate in candidates {
            let name = String(candidate.map { Character(UnicodeScalar($0 ^ 0x1F)) })
            if env[name] != nil { return true }
        }
        return false
    }

    /// Returns true if `kern.ostype` sysctl returns "Darwin".
    ///
    /// "kern.ostype" XOR 0x04 → [0x6F, 0x61, 0x76, 0x6A, 0x2A, 0x6B, 0x77, 0x70, 0x7D, 0x74, 0x61]
    /// "Darwin"      XOR 0x04 → [0x40, 0x65, 0x76, 0x73, 0x6D, 0x6A]
    private func kernelOSTypeIsDarwin() -> Bool {
        let nameEncoded: [UInt8] = [0x6F, 0x61, 0x76, 0x6A, 0x2A, 0x6B, 0x77, 0x70, 0x7D, 0x74, 0x61]
        let sysctlName = String(nameEncoded.map { Character(UnicodeScalar($0 ^ 0x04)) })

        var buf = [CChar](repeating: 0, count: 64)
        var size = buf.count
        guard sysctlbyname(sysctlName, &buf, &size, nil, 0) == 0 else {
            // Failure to query kern.ostype is itself anomalous.
            return false
        }

        let result = String(cString: buf)
        let expectedEncoded: [UInt8] = [0x40, 0x65, 0x76, 0x73, 0x6D, 0x6A]
        let expected = String(expectedEncoded.map { Character(UnicodeScalar($0 ^ 0x04)) })
        return result == expected
    }

    /// Returns true if CLOCK_PROCESS_CPUTIME_ID appears frozen — characteristic
    /// of unidbg's time stub returning a constant value.
    private func cpuClockAppearsStalled() -> Bool {
        var t1 = timespec(), t2 = timespec()
        guard clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1) == 0 else { return false }
        // Burn enough CPU cycles that any real process-time clock must advance.
        var dummy: UInt64 = 0xDEAD_BEEF_1234_5678
        for _ in 0..<8192 {
            dummy = dummy &* 6364136223846793005 &+ 1442695040888963407
        }
        // Volatile-style use of dummy to prevent elimination by the optimiser.
        withUnsafePointer(to: dummy) { _ = $0.pointee }
        guard clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2) == 0 else { return false }
        let ns1 = Int64(t1.tv_sec) &* 1_000_000_000 &+ Int64(t1.tv_nsec)
        let ns2 = Int64(t2.tv_sec) &* 1_000_000_000 &+ Int64(t2.tv_nsec)
        return ns2 <= ns1
    }
}
