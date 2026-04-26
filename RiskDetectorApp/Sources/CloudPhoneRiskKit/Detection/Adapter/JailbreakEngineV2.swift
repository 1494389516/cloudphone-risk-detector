import Foundation
import CryptoKit
import CRiskCore

/// JailbreakEngine V2 - 集成新架构检测器
///
/// 这个适配器将新的反篡改检测器集成到现有的 JailbreakEngine 中，
/// 保持向后兼容的同时增强检测能力。
///
/// ## 设计原则
/// 1. **向后兼容**: 保持现有 API 不变
/// 2. **渐进增强**: 通过配置启用新检测器
/// 3. **职责分离**: 检测器专注检测，引擎负责编排
/// 4. **可观测性**: 详细的日志输出
public final class JailbreakEngineV2 {
    
    // MARK: - 配置
    
    /// V2 扩展配置
    public struct V2Config {
        /// 是否启用反篡改检测
        var enableAntiTampering: Bool = true
        
        /// 是否启用调试器检测
        var enableDebugger: Bool = true
        
        /// 是否启用 Frida 检测
        var enableFrida: Bool = true
        
        /// 是否启用代码签名验证
        var enableCodeSignature: Bool = true
        
        /// 是否启用内存完整性检查
        var enableMemoryIntegrity: Bool = true

        /// 是否启用 dylib 注入检测
        var enableDylibInjection: Bool = true
        
        /// 检测器超时时间（毫秒）
        var detectionTimeout: Int = 5000
        
        /// 是否启用详细日志
        var verboseLogging: Bool = false
        
        public static let `default` = V2Config()
        
        /// 严格配置（所有检测启用）
        public static let strict = V2Config(
            enableAntiTampering: true,
            enableDebugger: true,
            enableFrida: true,
            enableCodeSignature: true,
            enableMemoryIntegrity: true,
            enableDylibInjection: true,
            verboseLogging: true
        )
        
        /// 性能优先配置（跳过耗时检测）
        public static let performance = V2Config(
            enableAntiTampering: true,
            enableDebugger: true,
            enableFrida: true,
            enableCodeSignature: false,
            enableMemoryIntegrity: false,
            enableDylibInjection: true,
            verboseLogging: false
        )
    }
    
    // MARK: - 属性
    
    private let legacyEngine: JailbreakEngine
    private let v2Config: V2Config
    
    // MARK: - 初始化
    
    public init(v2Config: V2Config = .default) {
        self.v2Config = v2Config
        self.legacyEngine = JailbreakEngine()
    }
    
    // MARK: - 公开 API
    
    /// 执行检测（V2 增强版）
    /// - Parameter config: 检测配置
    /// - Returns: 检测结果
    public func detect(config: JailbreakConfig) -> DetectionResult {
        Logger.log("JailbreakEngineV2: start detection")
        
#if targetEnvironment(simulator)
        return handleSimulator(config: config)
#else
        // 1. 执行原有检测
        let legacyResult = legacyEngine.detect(config: config)
        var score = legacyResult.confidence
        var methods = legacyResult.detectedMethods
        
        Logger.log("JailbreakEngineV2: legacy score=\(score), methods=\(methods.count)")
        
        // 2. 执行 V2 新增检测
        let v2Result = detectV2(baseScore: score)
        score += v2Result.score
        methods.append(contentsOf: v2Result.methods)
        
        // 3. 去重并排序
        methods = Array(Set(methods)).sorted()
        
        let finalScore = min(score, 100)
        let isJailbroken = finalScore >= config.threshold
        
        Logger.log("JailbreakEngineV2: final score=\(finalScore), isJailbroken=\(isJailbroken), methods=\(methods.count)")
        
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: finalScore,
            detectedMethods: methods,
            details: buildDetails(
                score: finalScore,
                methods: methods,
                legacyScore: legacyResult.confidence,
                v2Score: v2Result.score
            )
        )
#endif
    }
    
    /// 快速检测（仅执行关键检测）
    /// - Returns: 简化的检测结果
    public func quickDetect() -> QuickDetectionResult {
        Logger.log("JailbreakEngineV2: quick detect")
        
#if targetEnvironment(simulator)
        return QuickDetectionResult(
            isRisky: false,
            riskLevel: .none,
            detectedCategories: []
        )
#else
        var detectedCategories: [String] = []
        var totalScore: Double = 0
        
        // 只执行快速检测项
        let quickDetectors: [(String, Detector)] = [
            (ObfuscatedConstants.categoryAntiTamper, AntiTamperingDetector()),
            (ObfuscatedConstants.detectorIDDebugger, DebuggerDetector()),
            (ObfuscatedConstants.keywordFrida, FridaDetector()),
            (ObfuscatedConstants.detectorIDDylibInjection, DylibInjectionDetector()),
        ]
        
        for (category, detector) in quickDetectors {
            do {
                let result = try detector.detect()
                if result.score > 0 {
                    detectedCategories.append(category)
                    totalScore += result.score
                }
            } catch {
                detectedCategories.append(category)
                totalScore += 80
            }
        }
        
        let riskLevel = QuickDetectionResult.RiskLevel.from(score: totalScore)
        
        return QuickDetectionResult(
            isRisky: !detectedCategories.isEmpty,
            riskLevel: riskLevel,
            detectedCategories: detectedCategories
        )
#endif
    }
    
    /// 获取检测器状态
    /// - Returns: 检测器状态信息
    public func detectorStatus() -> DetectorStatus {
        var status = DetectorStatus()
        
        // 检查各检测器状态
        status.antiTampering = v2Config.enableAntiTampering
        status.debugger = v2Config.enableDebugger
        status.frida = v2Config.enableFrida
        status.codeSignature = v2Config.enableCodeSignature
        status.memoryIntegrity = v2Config.enableMemoryIntegrity
        status.dylibInjection = v2Config.enableDylibInjection
        
        return status
    }
    
    // MARK: - 私有方法

    private var detectionTimeoutSeconds: TimeInterval {
        Double(v2Config.detectionTimeout) / 1000.0
    }

    /// Numeric identifier replacing the previous `detectorName: String` parameter.
    /// String literals like "FridaDetector" were a static-analysis goldmine — an
    /// attacker grepping `__cstring` for the suffix `Detector` immediately
    /// located every dispatch site. The enum compiles to small integer constants
    /// and the lookup logger string is decrypted from the encrypted string table
    /// only when actually emitted (debug builds + log enabled).
    private enum DetectorID: UInt8 {
        case antiTampering = 0x11
        case debugger      = 0x23
        case frida         = 0x37
        case codeSignature = 0x4D
        case memoryIntegrity = 0x59
        case dylibInjection  = 0x6B
        case canary          = 0x7F
    }

    private func runDetectorWithTimeout(_ work: @escaping () throws -> DetectorResult, id: DetectorID, timeout: TimeInterval) -> DetectorResult {
        let semaphore = DispatchSemaphore(value: 0)
        final class ResultBox: @unchecked Sendable {
            var value: DetectorResult
            init(_ v: DetectorResult) { value = v }
        }
        let box = ResultBox(Self.emptyDetectorResult)
        let queue = DispatchQueue(label: "detector.timeout", qos: .userInitiated)
        queue.async {
            do {
                box.value = try work()
            } catch {
                Logger.log("detector id=\(id.rawValue) threw: \(error)")
                box.value = DetectorResult(score: 80, methods: ["detector_anomaly:\(id.rawValue)"])
            }
            semaphore.signal()
        }
        let waitResult = semaphore.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            Logger.log("detector id=\(id.rawValue) timeout after \(timeout)s")
            return DetectorResult(score: 80, methods: ["detector_timeout:\(id.rawValue)"])
        }
        return box.value
    }

    private static let emptyDetectorResult = DetectorResult.empty

    /// Per-process build-seeded RNG used to randomize detector execution order
    /// per call. The seed is derived from a static base XOR'd with a session
    /// nonce so every `detectV2` invocation produces a different ordering;
    /// this defeats the static "attacker waits for the AntiTampering window"
    /// strategy described in the red-team self-audit.
    private static func detectorOrderSeed() -> UInt64 {
        var raw: UInt64 = 0
        let _ = withUnsafeMutableBytes(of: &raw) { buf in
            arc4random_buf(buf.baseAddress, buf.count)
        }
        // mix in mach_absolute_time to ensure that even if arc4random_buf
        // is hooked to return a constant, the schedule still varies per call.
        return raw ^ UInt64(Date().timeIntervalSinceReferenceDate.bitPattern)
    }

    /// Canary detector: returns a known fixed result. After the dispatch
    /// loop the engine verifies that this exact result came back. A blanket
    /// hook on `runDetectorWithTimeout` that returns "all-clean" for every
    /// caller will fail this canary check, exposing the hook.
    private static let canaryExpectedScore: Double = 13.0
    private static let canaryExpectedMethod = "_cprisk_canary_v1"
    private func canaryDetectorClosure() -> () throws -> DetectorResult {
        return {
            DetectorResult(score: Self.canaryExpectedScore, methods: [Self.canaryExpectedMethod])
        }
    }

#if !targetEnvironment(simulator)

    /// One slot in the randomized detector dispatch table.
    /// Closures are not stored as property types directly because the
    /// ResultBox path requires `@escaping`; we keep them as opaque trailing
    /// thunks captured at slot construction.
    private struct DispatchSlot {
        let id: DetectorID
        let work: () throws -> DetectorResult
    }

    /// Build the dispatch slot array based on enabled detectors. The order of
    /// elements here is the *deterministic registration* order; the actual
    /// execution order is decided by `executeRandomized()` below using a
    /// per-call RNG seed.
    private func buildEnabledSlots() -> [DispatchSlot] {
        var slots: [DispatchSlot] = []
        if v2Config.enableAntiTampering {
            slots.append(DispatchSlot(id: .antiTampering) { try AntiTamperingDetector().detect() })
        }
        if v2Config.enableDebugger {
            slots.append(DispatchSlot(id: .debugger) { try DebuggerDetector().detect() })
        }
        if v2Config.enableFrida {
            slots.append(DispatchSlot(id: .frida) { try FridaDetector().detect() })
        }
        if v2Config.enableCodeSignature {
            slots.append(DispatchSlot(id: .codeSignature) { try CodeSignatureValidator().detect() })
        }
        if v2Config.enableMemoryIntegrity {
            slots.append(DispatchSlot(id: .memoryIntegrity) { try MemoryIntegrityChecker().detect() })
        }
        if v2Config.enableDylibInjection {
            slots.append(DispatchSlot(id: .dylibInjection) { try DylibInjectionDetector().detect() })
        }
        // Canary slot is always inserted, regardless of v2Config — its purpose
        // is to detect blanket hooks on the dispatch path. A hook returning
        // "all-clean" for every caller will not produce the expected canary
        // score/method tuple, and the post-loop check will flag the bypass.
        slots.append(DispatchSlot(id: .canary, work: canaryDetectorClosure()))
        return slots
    }

    /// SplitMix64 PRNG — used to generate the execution order without leaking
    /// dependencies on Foundation random APIs that an attacker can hook.
    private struct SplitMix64 {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
            z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
            return z ^ (z >> 31)
        }
        mutating func bounded(_ bound: Int) -> Int {
            // unbiased rejection sampling
            let b = UInt64(bound)
            let threshold = (0 &- b) % b
            while true {
                let r = next()
                if r >= threshold { return Int(r % b) }
            }
        }
    }

    /// 执行 V2 新增检测 — randomized order, per-detector jitter, canary verification,
    /// and cross-language attestation via CRiskCore (P0a full).
    private func detectV2(baseScore: Double) -> V2DetectionResult {
        var score: Double = 0
        var methods: [String] = []
        let timeout = detectionTimeoutSeconds

        var slots = buildEnabledSlots()
        // Fisher-Yates shuffle keyed by per-call seed.
        var rng = SplitMix64(state: Self.detectorOrderSeed())
        if slots.count > 1 {
            for i in stride(from: slots.count - 1, through: 1, by: -1) {
                let j = rng.bounded(i + 1)
                if i != j { slots.swapAt(i, j) }
            }
        }

        // Begin a CRiskCore-side attestation session. The C runtime
        // independently records (id, score, methods_hash) tuples into a
        // running SHA256 chain keyed by a WhiteBox PRF derivation.
        // Hooking only the Swift dispatch leaves the chain inconsistent
        // with what the engine reports — server-side replay then catches
        // the tampering.
        var sessionNonce = [UInt8](repeating: 0, count: 16)
        _ = sessionNonce.withUnsafeMutableBufferPointer { buf in
            cprisk_attest_session_begin(buf.baseAddress)
        }

        var canarySatisfied = false
        for slot in slots {
            // Sub-millisecond jitter (0..1500 microseconds). Visible-from-outside
            // detection windows ("waits exactly 50 ms before AntiTamper") become
            // unreliable. The jitter is bounded so total detection latency
            // stays within the configured timeout budget.
            let jitterMicros = rng.bounded(1500)
            if jitterMicros > 0 {
                usleep(UInt32(jitterMicros))
            }

            let result = runDetectorWithTimeout(slot.work, id: slot.id, timeout: timeout)

            // Record into the C-side attestation chain BEFORE branching on
            // canary, so the canary slot also contributes to the chain (and
            // the server replay must include it). The attacker who skips
            // calling `cprisk_attest_record` for any slot — or skips it
            // entirely — produces a tag that cannot be reconstructed from
            // what the engine reports.
            recordAttestation(id: slot.id, result: result)

            if slot.id == .canary {
                let scoreOK = abs(result.score - Self.canaryExpectedScore) < 0.0001
                let methodsOK = result.methods == [Self.canaryExpectedMethod]
                if scoreOK && methodsOK {
                    canarySatisfied = true
                }
                continue
            }

            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("d:\(slot.id.rawValue)", result.score, result.methods.count)
        }

        // Finalize the C-side attestation. The 32-byte tag and the slot
        // count are emitted as method tags using a stable prefix so the
        // server-side correlator can extract them without protocol
        // changes. Hex-encoded for compatibility with the existing
        // [String] methods field.
        var attestTag = [UInt8](repeating: 0, count: 32)
        var recordedCount: UInt32 = 0
        let finalizeRC = attestTag.withUnsafeMutableBufferPointer { tagBuf in
            cprisk_attest_session_finalize(tagBuf.baseAddress, &recordedCount)
        }
        if finalizeRC == 0 {
            methods.append("attest_nonce:\(Self.hexEncode(sessionNonce))")
            methods.append("attest_count:\(recordedCount)")
            methods.append("attest_tag:\(Self.hexEncode(attestTag))")
        } else {
            // CRiskCore could not finalize — possible early-boot path or
            // malicious hook on the attest module itself. Treat as risk.
            methods.append("attest_unavailable")
            score += 50
        }

        if !canarySatisfied {
            score += 100
            methods.append("dispatch_attest_failed")
        }

        return V2DetectionResult(score: score, methods: methods)
    }

    /// Compute a stable SHA256 over a sorted detector method list and
    /// hand it to the C-side attestation chain. Sorting normalizes
    /// ordering so server replay can reproduce the same hash without
    /// guessing iteration order inside individual detectors.
    private func recordAttestation(id: DetectorID, result: DetectorResult) {
        let sortedMethods = result.methods.sorted()
        var methodsBlob = Data()
        for m in sortedMethods {
            // length-prefixed encoding to prevent ambiguity from method
            // names containing the separator byte.
            var lenLE = UInt32(m.utf8.count).littleEndian
            withUnsafeBytes(of: &lenLE) { methodsBlob.append(contentsOf: $0) }
            methodsBlob.append(Data(m.utf8))
        }
        let hash = SHA256.hash(data: methodsBlob)
        let hashBytes = Array(hash)

        // Score is double on the Swift side; quantize to integer cents to
        // give the C side a stable int32 representation. Manual clamp because
        // direct Int32(_) traps on overflow.
        let cents = result.score.rounded() * 100
        let clamped: Int32
        if cents > Double(Int32.max) {
            clamped = Int32.max
        } else if cents < Double(Int32.min) {
            clamped = Int32.min
        } else {
            clamped = Int32(cents)
        }
        hashBytes.withUnsafeBufferPointer { buf in
            cprisk_attest_record(id.rawValue, clamped, buf.baseAddress)
        }
    }

    private static func hexEncode(_ bytes: [UInt8]) -> String {
        let hexChars: [Character] = Array("0123456789abcdef")
        var out = String()
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(hexChars[Int(b >> 4)])
            out.append(hexChars[Int(b & 0x0F)])
        }
        return out
    }

#endif
    
    /// 处理模拟器环境
    private func handleSimulator(config: JailbreakConfig) -> DetectionResult {
        #if DEBUG
        let simulate = ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1"
        if simulate {
            return DetectionResult(
                isJailbroken: true,
                confidence: 100,
                detectedMethods: ["simulated:simulator"],
                details: "simulated_jailbreak"
            )
        }
        #endif
        
        return DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: ["unavailable_simulator"],
            details: "simulator_environment"
        )
    }
    
    /// 构建详情字符串
    private func buildDetails(
        score: Double,
        methods: [String],
        legacyScore: Double,
        v2Score: Double
    ) -> String {
        """
        total_score=\(score)
        legacy_score=\(legacyScore)
        v2_score=\(v2Score)
        methods_hit=\(methods.count)
        methods=\(methods.prefix(20).joined(separator: ","))
        """
    }
    
    /// V2 日志输出
    private func logV2(_ detector: String, _ score: Double, _ count: Int) {
        if v2Config.verboseLogging {
            Logger.log("JailbreakEngineV2.\(detector): score=\(score), hits=\(count)")
        }
    }
}

// MARK: - 结果类型

/// V2 检测结果
private struct V2DetectionResult {
    let score: Double
    let methods: [String]
}

/// 快速检测结果
public struct QuickDetectionResult {
    /// 是否存在风险
    public let isRisky: Bool
    
    /// 风险等级
    public let riskLevel: RiskLevel
    
    /// 检测到的风险类别
    public let detectedCategories: [String]
    
    /// 风险等级
    public enum RiskLevel {
        case none
        case low
        case medium
        case high
        
        public static func from(score: Double) -> RiskLevel {
            switch score {
            case 0..<10: return .none
            case 10..<30: return .low
            case 30..<60: return .medium
            default: return .high
            }
        }
    }
}

/// 检测器状态
public struct DetectorStatus {
    public var antiTampering: Bool = false
    public var debugger: Bool = false
    public var frida: Bool = false
    public var codeSignature: Bool = false
    public var memoryIntegrity: Bool = false
    public var dylibInjection: Bool = false
    
    /// 启用的检测器数量
    public var enabledCount: Int {
        var count = 0
        if antiTampering { count += 1 }
        if debugger { count += 1 }
        if frida { count += 1 }
        if codeSignature { count += 1 }
        if memoryIntegrity { count += 1 }
        if dylibInjection { count += 1 }
        return count
    }
    
    /// 是否启用了所有检测器
    public var isFullyEnabled: Bool {
        antiTampering && debugger && frida && codeSignature && memoryIntegrity && dylibInjection
    }
}

// MARK: - 向后兼容扩展

extension JailbreakConfig {
    
    /// 创建 V2 配置
    public static func v2(
        threshold: Double = 30,
        v2Config: JailbreakEngineV2.V2Config = .default
    ) -> (JailbreakConfig, JailbreakEngineV2.V2Config) {
        let jailbreakConfig = JailbreakConfig(
            enableFileDetect: true,
            enableDyldDetect: true,
            enableEnvDetect: true,
            enableSysctlDetect: true,
            enableSchemeDetect: true,
            enableHookDetect: true,
            threshold: threshold
        )
        
        return (jailbreakConfig, v2Config)
    }
}

// MARK: - 使用示例

/*
 ## 使用示例
 
 ### 1. 基本使用（向后兼容）
 ```swift
 let engine = JailbreakEngineV2()
 let result = engine.detect(config: .default)
 if result.isJailbroken {
     // 处理越狱设备
 }
 ```
 
 ### 2. 使用 V2 配置
 ```swift
 let v2Config = JailbreakEngineV2.V2Config.strict
 let engine = JailbreakEngineV2(v2Config: v2Config)
 let result = engine.detect(config: .default)
 ```
 
 ### 3. 快速检测
 ```swift
 let engine = JailbreakEngineV2()
 let quickResult = engine.quickDetect()
 if quickResult.isRisky {
     // 处理风险设备
 }
 ```
 
 ### 4. 检查检测器状态
 ```swift
 let engine = JailbreakEngineV2()
 let status = engine.detectorStatus()
 print("启用了 \(status.enabledCount) 个检测器")
 ```
 */
