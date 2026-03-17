import CryptoKit
import Foundation

// MARK: - ChallengeSession 状态机

/// Challenge 会话状态
/// 状态流转：idle → issued → executing → submitted → verified/failed → closed
public enum ChallengeSessionState: String, Codable, Sendable {
    case idle
    case issued
    case executing
    case submitted
    case verified
    case failed
    case closed
}

/// 挑战会话状态机
/// 每个 session 绑定唯一 challengeId，防止跨 session 混用。
/// 支持多轮递进挑战（nextChallenge）、防重放（submittedChallengeIds）、超时与降级（executionStatus）。
public final class ChallengeSession: @unchecked Sendable {

    // MARK: - 状态

    private let lock = NSLock()
    private var _state: ChallengeSessionState = .idle
    private var _currentChallengeId: String?
    private var _submittedChallengeIds: Set<String> = []
    private var _nextChallenge: ChallengeTrigger.BlindChallenge?
    private var _executionStatus: ChallengeExecutionStatus = .completed

    /// 当前状态
    public var state: ChallengeSessionState {
        lock.lock()
        defer { lock.unlock() }
        return _state
    }

    /// 当前绑定的 challengeId（与 session 一一对应）
    public var currentChallengeId: String? {
        lock.lock()
        defer { lock.unlock() }
        return _currentChallengeId
    }

    /// 已提交的 challengeId 集合（防重放：每个 challengeId 只能提交一次）
    public var submittedChallengeIds: Set<String> {
        lock.lock()
        defer { lock.unlock() }
        return _submittedChallengeIds
    }

    /// 下一轮挑战（服务端通过 nextChallenge 下发，用于多轮递进）
    /// 第一轮：轻量探针（GPU 渲染、传感器熵）
    /// 第二轮：重量级探针（内存完整性、代码签名验证）
    public var nextChallenge: ChallengeTrigger.BlindChallenge? {
        lock.lock()
        defer { lock.unlock() }
        return _nextChallenge
    }

    /// 探针执行状态（超时/不支持时上报）
    public var executionStatus: ChallengeExecutionStatus {
        lock.lock()
        defer { lock.unlock() }
        return _executionStatus
    }

    // MARK: - 合法状态转换

    private static let validTransitions: [ChallengeSessionState: Set<ChallengeSessionState>] = [
        .idle: [.issued],
        .issued: [.executing],
        .executing: [.submitted],
        .submitted: [.verified, .failed],
        .verified: [.closed],
        .failed: [.closed],
        .closed: []
    ]

    // MARK: - 初始化

    public init() {}

    /// 共享会话实例（用于防重放、多轮挑战等）
    public static let shared = ChallengeSession()

    // MARK: - 状态转换

    /// 转换到目标状态，校验合法转换
    /// - Parameter to: 目标状态
    /// - Returns: 是否转换成功
    @discardableResult
    public func transition(to target: ChallengeSessionState) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard let allowed = Self.validTransitions[_state], allowed.contains(target) else {
            #if DEBUG
            Logger.log("ChallengeSession.transition rejected: \(_state.rawValue) -> \(target.rawValue)")
            #endif
            return false
        }

        _state = target
        #if DEBUG
        Logger.log("ChallengeSession.transition: \(target.rawValue)")
        #endif
        return true
    }

    /// 推进到下一合法状态（按预设流转顺序）
    /// - Returns: 是否推进成功
    @discardableResult
    public func advance() -> Bool {
        lock.lock()
        defer { lock.unlock() }

        let next: ChallengeSessionState?
        switch _state {
        case .idle: next = .issued
        case .issued: next = .executing
        case .executing: next = .submitted
        case .submitted: next = nil  // 需显式 transition(to: .verified/.failed)
        case .verified, .failed: next = .closed
        case .closed: next = nil
        }

        guard let target = next else {
            return false
        }
        _state = target
        return true
    }

    // MARK: - 业务方法

    /// 绑定 challenge 并进入 issued 状态
    /// - Parameter challenge: 当前挑战
    /// - Returns: 是否成功（需从 idle 转换）
    @discardableResult
    public func bindChallenge(_ challenge: ChallengeTrigger.BlindChallenge) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard _state == .idle else {
            #if DEBUG
            Logger.log("ChallengeSession.bindChallenge rejected: state=\(_state.rawValue)")
            #endif
            return false
        }

        _currentChallengeId = challenge.challengeId
        _state = .issued
        return true
    }

    /// 检查 challengeId 是否与当前 session 绑定一致
    public func isChallengeIdBound(_ challengeId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return _currentChallengeId == challengeId
    }

    /// 检查 challengeId 是否已提交（防重放）
    public func hasSubmitted(_ challengeId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return _submittedChallengeIds.contains(challengeId)
    }

    /// 标记 challengeId 已提交（防重放：每个 challengeId 只能提交一次）
    /// - Parameter challengeId: 已提交的 challengeId
    /// - Returns: 是否成功（未重复提交）
    @discardableResult
    public func markSubmitted(_ challengeId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        if _submittedChallengeIds.contains(challengeId) {
            #if DEBUG
            Logger.log("ChallengeSession.markSubmitted rejected: challengeId=\(challengeId) already submitted (replay)")
            #endif
            return false
        }
        _submittedChallengeIds.insert(challengeId)
        return true
    }

    /// 设置下一轮挑战（服务端下发）
    public func setNextChallenge(_ challenge: ChallengeTrigger.BlindChallenge?) {
        lock.lock()
        defer { lock.unlock() }
        _nextChallenge = challenge
    }

    /// 设置探针执行状态（超时/不支持时调用）
    public func setExecutionStatus(_ status: ChallengeExecutionStatus) {
        lock.lock()
        defer { lock.unlock() }
        _executionStatus = status
    }

    /// 重置 session 到 idle（用于新一轮）
    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        _state = .idle
        _currentChallengeId = nil
        _nextChallenge = nil
        _executionStatus = .completed
        // 保留 _submittedChallengeIds 以持续防重放
    }

    /// 完全清空（包括已提交记录，慎用）
    public func clearAll() {
        lock.lock()
        defer { lock.unlock() }
        _state = .idle
        _currentChallengeId = nil
        _submittedChallengeIds.removeAll()
        _nextChallenge = nil
        _executionStatus = .completed
    }
}

// MARK: - ChallengeVerificationResult

/// 服务端返回的挑战验证结果
/// 客户端解析并应用，用于回注到下一次 evaluate 的分数调整
public struct ChallengeVerificationResult: Codable, Sendable {
    public let challengeId: String
    public let passed: Bool
    public let failedProbes: [String]
    public let adjustedScore: Double?
    public let hmac: String?

    private enum CodingKeys: String, CodingKey {
        case challengeId = "ci"
        case passed = "p"
        case failedProbes = "fp"
        case adjustedScore = "as"
        case hmac = "h"
    }

    public init(
        challengeId: String,
        passed: Bool,
        failedProbes: [String] = [],
        adjustedScore: Double? = nil,
        hmac: String? = nil
    ) {
        self.challengeId = challengeId
        self.passed = passed
        self.failedProbes = failedProbes
        self.adjustedScore = adjustedScore
        self.hmac = hmac
    }
}

// MARK: - Challenge HMAC Verification

extension ChallengeSession {

    private static let challengeKeyLock = NSLock()
    private static var _challengeKey: SymmetricKey?

    /// Configure the HMAC key used to verify `ChallengeVerificationResult`.
    public func configureChallengeKey(_ key: Data) {
        Self.challengeKeyLock.lock()
        defer { Self.challengeKeyLock.unlock() }
        Self._challengeKey = SymmetricKey(data: key)
    }

    /// Verify the HMAC on a `ChallengeVerificationResult`.
    /// Returns a `challenge_hmac_mismatch` signal if verification fails, or nil on success / no key configured.
    public func verifyResult(_ result: ChallengeVerificationResult) -> RiskSignal? {
        Self.challengeKeyLock.lock()
        let key = Self._challengeKey
        Self.challengeKeyLock.unlock()

        guard let key else { return nil }

        guard let hmacHex = result.hmac, !hmacHex.isEmpty else {
            Logger.log("ChallengeSession.verifyResult: hmac field missing")
            return makeMismatchSignal(challengeId: result.challengeId, reason: "hmac_missing")
        }

        let scoreStr = result.adjustedScore.map { "\($0)" } ?? "nil"
        let input = "\(result.challengeId)|\(scoreStr)|\(result.passed)"
        let inputData = Data(input.utf8)
        let expected = HMAC<SHA256>.authenticationCode(for: inputData, using: key)
        let expectedHex = Data(expected).map { String(format: "%02x", $0) }.joined()

        guard hmacHex.lowercased() == expectedHex.lowercased() else {
            Logger.log("ChallengeSession.verifyResult: HMAC mismatch for challengeId=\(result.challengeId)")
            return makeMismatchSignal(challengeId: result.challengeId, reason: "hmac_mismatch")
        }

        return nil
    }

    private func makeMismatchSignal(challengeId: String, reason: String) -> RiskSignal {
        RiskSignal(
            id: "challenge_hmac_mismatch",
            category: "integrity",
            score: 35,
            evidence: ["challenge_id": challengeId, "reason": reason],
            state: .tampered,
            layer: 3,
            weightHint: 80
        )
    }
}

// ChallengeExecutionStatus 定义于 RiskReport.swift
