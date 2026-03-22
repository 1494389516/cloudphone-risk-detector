import Darwin
import Foundation
import MachO

/// Continuous dylib monitoring inspired by Frida 17.8.0's `map_gen` mechanism.
///
/// Tracks a generation counter (`dyldGen`) that increments on every image add/remove,
/// records a baseline at `start()`, and detects anomalies at `evaluate()`:
/// - Suspicious libraries injected after baseline
/// - Generation counter jumps (image loaded then unloaded to hide traces)
/// - Image count decrease (removal to evade detection)
final class DyldImageMonitor: @unchecked Sendable {
    static let shared = DyldImageMonitor()

    private struct State {
        var dyldGen: UInt64 = 0
        var baselineImageCount: UInt32 = 0
        var baselineImageHash: UInt64 = 0
        var baselineDyldGen: UInt64 = 0
        var isStarted = false
        var addImageCallbackCount: UInt32 = 0
        var suspiciousAdditions: [(name: String, gen: UInt64)] = []
    }
    private let stateLock = UnfairLock()
    private var state = State()

    private var suspiciousTokens: [String] {
        DynamicFeatureList.shared.suspiciousLibraries
    }

    private init() {}

    // MARK: - Lifecycle

    func start() {
    #if targetEnvironment(simulator)
        return
    #else
        let shouldRegister = stateLock.withLock { () -> Bool in
            guard !state.isStarted else { return false }
            state.isStarted = true
            state.baselineImageCount = _dyld_image_count()
            state.baselineImageHash = computeImageListHash()
            state.baselineDyldGen = state.dyldGen
            return true
        }
        guard shouldRegister else { return }

        _dyld_register_func_for_add_image { mh, slide in
            DyldImageMonitor.shared.onImageAdded(mh, slide: slide)
        }

        // dyld 同步为每个已加载 image 调用回调，返回时 dyldGen 已累加完毕
        stateLock.withLock {
            state.baselineDyldGen = state.dyldGen
        }
    #endif
    }

    // MARK: - Callback

    private func onImageAdded(_ mh: UnsafePointer<mach_header>?, slide: Int) {
        stateLock.withLock {
            state.dyldGen &+= 1
            state.addImageCallbackCount &+= 1

            guard state.isStarted else { return }
            // 注册时 dyld 会为已加载的每个 image 同步回调，前 baselineImageCount 次为基线，不计入 suspiciousAdditions
            if state.addImageCallbackCount <= state.baselineImageCount { return }

            let imageName = resolveImageName(for: mh)
            guard let imageName, !imageName.isEmpty else { return }

            let lower = imageName.lowercased()
            let isSuspicious = suspiciousTokens.contains { lower.contains($0) }
            if isSuspicious {
                state.suspiciousAdditions.append((name: imageName, gen: state.dyldGen))
            }
        }
    }

    // MARK: - Evaluate

    func evaluate() -> DetectorResult {
    #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dyld_monitor:unavailable_simulator"])
    #else
        let snapshot = stateLock.withLock { () -> (gen: UInt64, baseGen: UInt64, baseCount: UInt32, baseHash: UInt64, additions: [(name: String, gen: UInt64)])? in
            guard state.isStarted else { return nil }
            return (state.dyldGen, state.baselineDyldGen, state.baselineImageCount, state.baselineImageHash, state.suspiciousAdditions)
        }
        guard let snapshot else { return DetectorResult(score: 0, methods: ["dyld_monitor:not_started"]) }

        var score: Double = 0
        var methods: [String] = []

        // 1. Suspicious libraries loaded after baseline
        for entry in snapshot.additions {
            score += 70
            methods.append("dyld_monitor:suspicious_load:\(entry.name):gen=\(entry.gen)")
        }

        // 2. Generation jump: images added since baseline beyond visible suspicious set
        let genDelta = snapshot.gen - snapshot.baseGen
        let visibleNewCount = UInt64(snapshot.additions.count)
        if genDelta > visibleNewCount &+ 2 {
            score += 50
            methods.append(
                "dyld_monitor:gen_jump:delta=\(genDelta):visible=\(visibleNewCount)"
            )
        }

        // 3. Image count decreased (unloaded to hide)
        let currentCount = _dyld_image_count()
        if currentCount < snapshot.baseCount {
            score += 40
            methods.append(
                "dyld_monitor:count_decrease:baseline=\(snapshot.baseCount):current=\(currentCount)"
            )
        }

        // 4. Image list hash divergence without any gen change recorded (deep tampering)
        let currentHash = computeImageListHash()
        if currentHash != snapshot.baseHash && genDelta == 0 {
            score += 50
            methods.append("dyld_monitor:hash_divergence_silent")
        }

        return DetectorResult(score: min(score, 100), methods: methods)
    #endif
    }

    // MARK: - Helpers

    private func resolveImageName(for mh: UnsafePointer<mach_header>?) -> String? {
        guard mh != nil else { return nil }
        let count = _dyld_image_count()
        for i in 0..<count {
            if _dyld_get_image_header(i) == mh, let cName = _dyld_get_image_name(i) {
                return String(cString: cName)
            }
        }
        return nil
    }

    private func computeImageListHash() -> UInt64 {
        var hash: UInt64 = 14695981039346656037 // FNV-1a offset basis
        let count = _dyld_image_count()
        let maxPathLen = 256
        for i in 0..<count {
            guard let cName = _dyld_get_image_name(i) else { continue }
            var ptr = cName
            var left = maxPathLen
            while left > 0 && ptr.pointee != 0 {
                hash ^= UInt64(UInt8(bitPattern: ptr.pointee))
                hash &*= 1099511628211 // FNV-1a prime
                ptr = ptr.advanced(by: 1)
                left -= 1
            }
            hash ^= 0xFF
            hash &*= 1099511628211
        }
        return hash
    }
}

// MARK: - Detector Conformance

extension DyldImageMonitor: Detector {
    func detect() throws -> DetectorResult {
        return evaluate()
    }
}

// MARK: - RiskSignal Conversion

extension DyldImageMonitor {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let suspiciousLoads = result.methods.filter { $0.contains("suspicious_load") }
        if !suspiciousLoads.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_suspicious_injection",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(suspiciousLoads.count) * 70, 100),
                evidence: ["detail": suspiciousLoads.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }

        let genJumps = result.methods.filter { $0.contains("gen_jump") }
        if !genJumps.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_gen_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: ["detail": genJumps.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        let countDecreases = result.methods.filter { $0.contains("count_decrease") }
        if !countDecreases.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_image_removed",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 40,
                evidence: ["detail": countDecreases.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        let hashDivergences = result.methods.filter { $0.contains("hash_divergence") }
        if !hashDivergences.isEmpty {
            signals.append(RiskSignal(
                id: "dyld_monitor_silent_mutation",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: ["detail": hashDivergences.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        return signals
    }
}
