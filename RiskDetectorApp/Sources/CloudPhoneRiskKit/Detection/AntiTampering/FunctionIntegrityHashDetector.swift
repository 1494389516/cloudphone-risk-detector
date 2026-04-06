import CRiskCore
import Darwin
import Foundation
import MachO

// MARK: - Function Integrity Hash Detector
//
// GumTrampolineDetector 依赖已知的 hook 指令模式（LDR+BR、ADRP+ADD+BR 等），
// 但 Dobby、Ellekit 等非 Frida hook 引擎使用不同的跳板序列，
// 更高级的攻击者可能整体重编译函数代码，完全规避模式匹配。
//
// 本检测器采用"基线快照 + 变更检测"策略：
// 1. SDK 初始化时，对关键系统函数的前 32 字节计算 FNV-1a 哈希作为基线
// 2. 后续评估时重新计算哈希并与基线对比
// 3. 任何字节变化（不管 hook 使用何种指令序列或工具）均触发报警
//
// 覆盖场景：Substrate、Dobby、Ellekit inline hook；函数体重编译；任意非标准 hook 变体

/// Thread-safe baseline storage for prologue hashes.
/// Populated on first `detect()` call; subsequent calls validate against this snapshot.
private final class PrologueHashBaseline {
    static let shared = PrologueHashBaseline()
    private let lock = NSLock()
    private var baseline: [String: UInt64] = [:]
    private var isSealed = false

    private init() {}

    func store(symbol: String, hash: UInt64) {
        lock.withLock {
            guard !isSealed else { return }
            baseline[symbol] = hash
        }
    }

    func seal() {
        lock.withLock { isSealed = true }
    }

    func hash(for symbol: String) -> UInt64? {
        lock.withLock { baseline[symbol] }
    }

    var hasBaseline: Bool {
        lock.withLock { isSealed && !baseline.isEmpty }
    }
}

struct FunctionIntegrityHashDetector: Detector {

    // MARK: - Configuration

    /// Number of ARM64 instructions (4 bytes each) to snapshot per function.
    private static let prologueInstructions = 8      // 32 bytes
    private static let prologueByteCount   = prologueInstructions * 4

    /// High-value system functions targeted by hook engines.
    /// Using (name, library) tuples consistent with GumTrampolineDetector.
    private static let monitoredSymbols: [(name: String, library: String)] = [
        ("open",          "/usr/lib/system/libsystem_kernel.dylib"),
        ("openat",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("stat",          "/usr/lib/system/libsystem_kernel.dylib"),      // libc stat wrapper — not the raw syscall stub
        ("lstat",         "/usr/lib/system/libsystem_kernel.dylib"),
        ("access",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("dlopen",        "/usr/lib/system/libdyld.dylib"),
        ("dlsym",         "/usr/lib/system/libdyld.dylib"),
        ("mmap",          "/usr/lib/system/libsystem_kernel.dylib"),
        ("mprotect",      "/usr/lib/system/libsystem_kernel.dylib"),
        ("sysctl",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("sysctlbyname",  "/usr/lib/system/libsystem_kernel.dylib"),
        ("pthread_create","/usr/lib/system/libsystem_pthread.dylib"),
        ("fork",          "/usr/lib/system/libsystem_kernel.dylib"),
        ("posix_spawn",   "/usr/lib/system/libsystem_kernel.dylib"),
        ("objc_msgSend",  "/usr/lib/libobjc.A.dylib"),
        ("socket",        "/usr/lib/system/libsystem_kernel.dylib"),
        ("connect",       "/usr/lib/system/libsystem_kernel.dylib"),
    ]

    // MARK: - Detector Protocol

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["fih:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    @inline(never)
    private func detectKernel() -> DetectorResult {
        let baseline = PrologueHashBaseline.shared

        if !baseline.hasBaseline {
            seedBaseline()
            // First call: seed only, no verdict yet — return clean to avoid false positive at init
            return DetectorResult(score: 0, methods: ["fih:baseline_seeded"])
        }

        return validateAgainstBaseline()
    }

    // MARK: - Baseline Seeding

    private func seedBaseline() {
        let baseline = PrologueHashBaseline.shared
        for sym in Self.monitoredSymbols {
            guard let ptr = resolveSymbol(sym.name, library: sym.library) else { continue }
            let hash = prologueHash(ptr)
            baseline.store(symbol: sym.name, hash: hash)
        }
        baseline.seal()
    }

    // MARK: - Validation

    private func validateAgainstBaseline() -> DetectorResult {
        let baseline = PrologueHashBaseline.shared
        var score: Double = 0
        var methods: [String] = []
        var changedCount = 0
        var missingCount = 0

        for sym in Self.monitoredSymbols {
            guard let expectedHash = baseline.hash(for: sym.name) else {
                // Symbol wasn't resolvable at baseline time — skip
                continue
            }

            guard let ptr = resolveSymbol(sym.name, library: sym.library) else {
                // Symbol no longer resolvable — suspicious (library unloaded / address hidden)
                missingCount += 1
                score += 8
                methods.append("fih:missing:\(sym.name)")
                continue
            }

            let currentHash = prologueHash(ptr)
            if currentHash != expectedHash {
                changedCount += 1
                score += 18  // Binary change = high confidence hook
                methods.append("fih:changed:\(sym.name)")
            }
        }

        // Bonus: multiple functions changed → higher confidence
        if changedCount >= 3 {
            score += 20
            methods.append("fih:multi_change:\(changedCount)")
        }
        if changedCount >= 1 && missingCount >= 1 {
            score += 10
            methods.append("fih:change_and_missing")
        }

        if methods.isEmpty {
            methods.append("fih:clean")
        }

        return DetectorResult(score: min(score, 80), methods: methods)
    }

    // MARK: - Helpers

    /// Resolve a symbol from a specific library using `dlopen` + `dlsym`.
    private func resolveSymbol(_ name: String, library: String) -> UnsafeRawPointer? {
        guard let handle = dlopen(library, RTLD_NOLOAD | RTLD_NOW) else { return nil }
        defer { dlclose(handle) }
        guard let addr = dlsym(handle, name) else { return nil }
        return UnsafeRawPointer(addr)
    }

    /// Compute a 64-bit FNV-1a hash of the first `prologueByteCount` bytes at `ptr`.
    /// FNV-1a is fast and collision-resistant enough for integrity checking.
    private func prologueHash(_ ptr: UnsafeRawPointer) -> UInt64 {
        let bytes = ptr.assumingMemoryBound(to: UInt8.self)
        var hash: UInt64 = 0xcbf29ce484222325
        for i in 0..<Self.prologueByteCount {
            hash ^= UInt64(bytes[i])
            hash &*= 0x100000001b3
        }
        return hash
    }
}

// MARK: - Signal Bridge

extension FunctionIntegrityHashDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        let changed = result.methods.filter { $0.hasPrefix("fih:changed:") }
        let missing = result.methods.filter { $0.hasPrefix("fih:missing:") }

        return [RiskSignal(
            id: "function_integrity_hash_changed",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: result.score,
            evidence: [
                "changed_count": "\(changed.count)",
                "missing_count": "\(missing.count)",
                "symbols": changed.prefix(5).joined(separator: ","),
            ],
            state: .soft(confidence: min(0.5 + Double(changed.count) * 0.15, 0.95)),
            layer: 2,
            weightHint: 75
        )]
    }
}
