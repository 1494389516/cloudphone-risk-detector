import Foundation

// MARK: - ChallengeResultStore

/// 存储服务端返回的挑战验证结果，用于下一次 evaluate 的分数偏移
/// adjustedScore 语义：增量偏移（delta），与 baseScore 相加得到调整后分数；非绝对分数。
/// 一次性消费后清除。
public final class ChallengeResultStore: @unchecked Sendable {

    /// 增量偏移的合理范围 [-100, 100]，超出则裁剪并打日志，避免绝对分误用或异常值污染
    private static let offsetRange = -100.0 ... 100.0

    public static let shared = ChallengeResultStore()

    private let lock = NSLock()
    private var _lastChallengeId: String?
    private var _lastAdjustedScore: Double?
    private var _lastPassed: Bool?
    private var _pendingMismatchSignals: [RiskSignal] = []

    private init() {}

    /// 存储 HMAC 校验失败时的信号，供下一次 evaluate 注入
    func storePendingMismatchSignal(_ signal: RiskSignal) {
        lock.lock()
        _pendingMismatchSignals.append(signal)
        lock.unlock()
    }

    /// 消费并返回待注入的 HMAC 校验失败信号
    func consumePendingMismatchSignals() -> [RiskSignal] {
        lock.lock()
        let signals = _pendingMismatchSignals
        _pendingMismatchSignals = []
        lock.unlock()
        return signals
    }

    /// 应用挑战验证结果（由 CPRiskKit.applyChallengeResult 调用）
    /// 对 adjustedScore 做范围校验：超出 [-100, 100] 时裁剪并记录日志，避免负值或超大值污染分数
    public func apply(result: ChallengeVerificationResult) {
        lock.lock()
        defer { lock.unlock() }
        _lastChallengeId = result.challengeId
        _lastPassed = result.passed

        let raw = result.adjustedScore
        if let v = raw {
            if Self.offsetRange.contains(v) {
                _lastAdjustedScore = v
            } else {
                let clamped = min(max(v, Self.offsetRange.lowerBound), Self.offsetRange.upperBound)
                _lastAdjustedScore = clamped
                Logger.log("ChallengeResultStore.apply: adjustedScore=\(v) out of range [\(Self.offsetRange.lowerBound), \(Self.offsetRange.upperBound)], clamped to \(clamped) — check if server returns absolute score instead of delta")
            }
        } else {
            _lastAdjustedScore = nil
        }

        #if DEBUG
        Logger.log("ChallengeResultStore.apply: challengeId=\(result.challengeId) passed=\(result.passed) adjustedScore=\(_lastAdjustedScore?.description ?? "nil")")
        #endif
    }

    /// 消费并返回分数偏移（下一次 evaluate 使用后清除）
    /// - Returns: 偏移量，无则返回 nil
    public func consumeScoreOffset() -> Double? {
        lock.lock()
        defer { lock.unlock() }
        let offset = _lastAdjustedScore
        _lastAdjustedScore = nil
        _lastChallengeId = nil
        _lastPassed = nil
        return offset
    }

    /// 获取当前分数偏移（不消费）
    public func currentScoreOffset() -> Double? {
        lock.lock()
        defer { lock.unlock() }
        return _lastAdjustedScore
    }

    /// 是否有待消费的偏移
    public var hasPendingOffset: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _lastAdjustedScore != nil
    }
}
