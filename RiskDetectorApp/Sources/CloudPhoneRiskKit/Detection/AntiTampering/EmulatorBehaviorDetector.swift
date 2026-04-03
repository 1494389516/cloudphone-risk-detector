import Darwin
import Foundation

/// Detects unidbg / Unicorn-engine emulation by inspecting process-context
/// fingerprints that differ between a real iOS app and a unidbg-hosted JNI
/// execution on a Linux host.
///
/// ## Threat model
/// unidbg runs as a JVM process on Linux.  The emulated native code sees a
/// synthetic process environment assembled by unidbg's emulation layer.
/// Several invariants that hold on real iOS are absent or anomalous:
///
/// 1. **Process name** — On a real device the process name is the app bundle
///    identifier or a short executable name (≤255 chars, no path separators
///    beyond a leading `/`).  unidbg synthesises a dummy name or inherits the
///    JVM launcher name (e.g. `java`, `unidbg-boot`).
///
/// 2. **Thread count** — A freshly-initialised unidbg emulation has very few
///    threads (often 1–3).  A real iOS app main-thread run has at least 4–6
///    (main, GCD serial, libdispatch, CoreFoundation run-loop, etc.).
///
/// 3. **Environment variable absence** — Real iOS app processes launched by
///    launchd have a well-defined minimal set of env vars.  unidbg running
///    inside a JVM inherits the Java launcher environment which typically
///    includes `JAVA_HOME`, `JVM_*`, `CLASSPATH`, etc.  These vars are
///    absent on real devices.
///
/// 4. **sysctl kern.ostype** — Returns "Darwin" on real devices;
///    unidbg's sysctl stub may return a different string or fail.
///
/// 5. **clock_gettime CLOCK_PROCESS_CPUTIME_ID anomaly** — On a real device
///    this clock advances smoothly.  On unidbg, time stubs often return 0 or
///    a fixed value.
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
        let processNameSuspect = checkProcessName()
        if processNameSuspect {
            score += Score.suspiciousProcessName
            methods.append("emulator_behavior:suspicious_process_name")
        } else {
            methods.append("emulator_behavior:process_name_ok")
        }

        // ── 2. Thread count ──────────────────────────────────────────────────
        let threadCount = countActiveThreads()
        // A real iOS app at cold start has at least 4 threads.
        // unidbg JNI harness typically spins up 1–3.
        if threadCount < 4 {
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

        let finalScore = min(score, Score.max)
        return DetectorResult(score: finalScore, methods: methods)
#endif
    }

    // MARK: - Private probes

    /// Returns true if the process name looks like a JVM launcher or unidbg
    /// stub rather than a normal iOS bundle identifier.
    private func checkProcessName() -> Bool {
        // Use XOR-obfuscated sentinel bytes to avoid plain-text string scanning.
        // Decoded sentinels: "java", "unidbg", "arm", "emu"
        let sentinels: [[UInt8]] = [
            // "java" XOR 0x55
            [0x3F, 0x24, 0x2F, 0x24],
            // "unidbg" XOR 0x55
            [0x20, 0x39, 0x3C, 0x19, 0x17, 0x32],
            // "qemu" XOR 0x55
            [0x24, 0x30, 0x38, 0x20],
            // "unicorn" XOR 0x55
            [0x20, 0x39, 0x3C, 0x16, 0x36, 0x39, 0x39],
        ]

        guard let processName = ProcessInfo.processInfo.processName.lowercased() as String? else {
            return false
        }

        for sentinel in sentinels {
            let decoded = String(sentinel.map { Character(UnicodeScalar($0 ^ 0x55)) })
            if processName.contains(decoded) {
                return true
            }
        }

        // Suspicious: process name contains a path separator (unidbg may pass
        // a full path like "/data/local/tmp/app") — real iOS processes do not.
        if processName.contains("/") {
            return true
        }

        // Suspicious: empty process name (unidbg stub may leave it blank).
        if processName.isEmpty {
            return true
        }

        return false
    }

    /// Returns the number of active Mach threads in the current task.
    private func countActiveThreads() -> Int {
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        let kr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let list = threadList else { return 0 }
        let count = Int(threadCount)
        // Deallocate the thread ports to avoid leaking.
        for i in 0..<count {
            mach_port_deallocate(mach_task_self_, list[i])
        }
        vm_deallocate(mach_task_self_,
                      vm_address_t(UInt(bitPattern: list)),
                      vm_size_t(count) * vm_size_t(MemoryLayout<thread_t>.stride))
        return count
    }

    /// Returns true if any of the JVM-indicator environment variable names are set.
    private func jvmEnvVarsPresent() -> Bool {
        // XOR-obfuscated env var names (XOR key 0x1F):
        // "JAVA_HOME"  -> decoded from XOR 0x1F bytes
        // "CLASSPATH"
        // "JVM_ARGS"
        // "LD_LIBRARY_PATH" (Linux-specific; never set on real iOS)
        let candidates: [[UInt8]] = [
            // "JAVA_HOME" XOR 0x1F
            [0x55, 0x7E, 0x7F, 0x60, 0x5F, 0x77, 0x70, 0x6D, 0x70],
            // "CLASSPATH" XOR 0x1F
            [0x5C, 0x7D, 0x60, 0x7C, 0x50, 0x60, 0x75, 0x77, 0x7B],
            // "JVM_ARGS" XOR 0x1F
            [0x55, 0x68, 0x63, 0x5F, 0x60, 0x7D, 0x67, 0x7C],
            // "LD_LIBRARY_PATH" XOR 0x1F
            [0x53, 0x5B, 0x5F, 0x53, 0x57, 0x52, 0x7D, 0x60, 0x7D, 0x79,
             0x5F, 0x50, 0x60, 0x75, 0x77],
        ]

        let env = ProcessInfo.processInfo.environment
        for candidate in candidates {
            let name = String(candidate.map { Character(UnicodeScalar($0 ^ 0x1F)) })
            if env[name] != nil {
                return true
            }
        }
        return false
    }

    /// Returns true if `kern.ostype` sysctl returns "Darwin".
    private func kernelOSTypeIsDarwin() -> Bool {
        var buf = [CChar](repeating: 0, count: 64)
        var size = buf.count
        // "kern.ostype" — use XOR-obfuscated form to avoid literal scanning
        // "kern.ostype" XOR 0x04 bytes then XOR back at runtime
        let nameBytes: [UInt8] = [
            // "kern.ostype" XOR 0x04
            0x6F, 0x61, 0x72, 0x6E, 0x2E, 0x6F, 0x73, 0x74, 0x79, 0x70, 0x61
        ]
        let sysctlName = String(nameBytes.map { Character(UnicodeScalar($0 ^ 0x04)) })
        guard sysctlbyname(sysctlName, &buf, &size, nil, 0) == 0 else {
            // Failure to query sysctl is itself suspicious.
            return false
        }
        let result = String(cString: buf)
        // XOR-decode "Darwin" for comparison
        let darwinBytes: [UInt8] = [0x40, 0x24, 0x37, 0x37, 0x3B, 0x39]  // "Darwin" XOR 0x04 each
        // Actually just compare: unidbg may return empty or "Linux"
        let expected = String(darwinBytes.map { Character(UnicodeScalar($0 ^ 0x04)) })
        return result == expected
    }

    /// Returns true if the process CPU clock appears to not advance — a sign
    /// that unidbg's time stub returns a constant or zero.
    private func cpuClockAppearsStalled() -> Bool {
        var t1 = timespec()
        var t2 = timespec()
        guard clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1) == 0 else { return false }
        // Burn a small amount of CPU work to ensure the clock should advance.
        var dummy: UInt64 = 0xDEAD_BEEF_1234_5678
        for _ in 0..<4096 {
            dummy = dummy &* 6364136223846793005 &+ 1442695040888963407
        }
        // Use dummy to prevent the compiler from eliminating the loop.
        guard dummy != 0 else { return false }
        guard clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2) == 0 else { return false }

        let ns1 = Int64(t1.tv_sec) &* 1_000_000_000 &+ Int64(t1.tv_nsec)
        let ns2 = Int64(t2.tv_sec) &* 1_000_000_000 &+ Int64(t2.tv_nsec)
        // If the clock did not advance at all, the stub is frozen.
        return ns2 <= ns1
    }
}
