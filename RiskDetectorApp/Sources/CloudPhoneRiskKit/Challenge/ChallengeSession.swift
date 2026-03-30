import CryptoKit
import Foundation

// MARK: - ChallengeSession 状态机

private enum ChallengeSessionCFF {
    static func salt(
        state: ChallengeSessionState,
        currentChallengeId: String?,
        executionStatus: ChallengeExecutionStatus,
        submittedCount: Int,
        extraStrings: [String] = [],
        extraWords: [UInt64] = []
    ) -> UInt32 {
        CFFRuntimeSalt.combine(
            words: [
                UInt64(state.rawValue.utf8.reduce(0) { ($0 &* 16777619) ^ UInt64($1) }),
                UInt64(executionStatus.rawValue.utf8.reduce(0) { ($0 &* 131) &+ UInt64($1) }),
                UInt64(submittedCount),
            ] + extraWords,
            strings: [currentChallengeId ?? ""] + extraStrings,
            flags: [
                currentChallengeId != nil,
                submittedCount > 0,
                executionStatus != .completed,
            ]
        )
    }
}

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

    private let lock = UnfairLock()
    private var _state: ChallengeSessionState = .idle
    private var _currentChallengeId: String?
    private var _submittedChallengeIds: Set<String> = []
    private var _nextChallenge: ChallengeTrigger.BlindChallenge?
    private var _executionStatus: ChallengeExecutionStatus = .completed
    private var _challengeKey: SymmetricKey?

    /// 当前状态
    public var state: ChallengeSessionState {
        lock.withLock { _state }
    }

    /// 当前绑定的 challengeId（与 session 一一对应）
    public var currentChallengeId: String? {
        lock.withLock { _currentChallengeId }
    }

    /// 已提交的 challengeId 集合（防重放：每个 challengeId 只能提交一次）
    public var submittedChallengeIds: Set<String> {
        lock.withLock { _submittedChallengeIds }
    }

    /// 下一轮挑战（服务端通过 nextChallenge 下发，用于多轮递进）
    /// 第一轮：轻量探针（GPU 渲染、传感器熵）
    /// 第二轮：重量级探针（内存完整性、代码签名验证）
    public var nextChallenge: ChallengeTrigger.BlindChallenge? {
        lock.withLock { _nextChallenge }
    }

    /// 探针执行状态（超时/不支持时上报）
    public var executionStatus: ChallengeExecutionStatus {
        lock.withLock { _executionStatus }
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
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count,
                extraStrings: [target.rawValue]
            )
            let seed: UInt32 = 0x1D4F29B7
            let entryState: UInt32 = 0x11
            let validateState: UInt32 = 0x12
            let rejectState: UInt32 = 0x13
            let commitState: UInt32 = 0x14

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

            while !sink.isResolved {
                let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

                if decodedState == entryState {
                    encodedState = CFFStateCodec.encode(validateState, seed: seed, salt: salt)
                } else if decodedState == validateState {
                    let allowed = Self.validTransitions[_state]?.contains(target) ?? false
                    encodedState = CFFStateCodec.encode(allowed ? commitState : rejectState, seed: seed, salt: salt)
                } else if decodedState == rejectState {
                    #if DEBUG
                    Logger.log("ChallengeSession.transition rejected: \(_state.rawValue) -> \(target.rawValue)")
                    #endif
                    sink.store(false)
                } else if decodedState == commitState {
                    _state = target
                    #if DEBUG
                    Logger.log("ChallengeSession.transition: \(target.rawValue)")
                    #endif
                    sink.store(true)
                } else {
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    /// 推进到下一合法状态（按预设流转顺序）
    /// - Returns: 是否推进成功
    @discardableResult
    public func advance() -> Bool {
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count
            )
            let seed: UInt32 = 0x6B7A3E19
            let entryState: UInt32 = 0x21
            let classifyState: UInt32 = 0x22
            let commitState: UInt32 = 0x23

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
            var nextState: ChallengeSessionState?

            while !sink.isResolved {
                switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
                case entryState:
                    encodedState = CFFStateCodec.encode(classifyState, seed: seed, salt: salt)
                case classifyState:
                    switch _state {
                    case .idle:
                        nextState = .issued
                    case .issued:
                        nextState = .executing
                    case .executing:
                        nextState = .submitted
                    case .submitted:
                        nextState = nil
                    case .verified, .failed:
                        nextState = .closed
                    case .closed:
                        nextState = nil
                    }
                    if nextState != nil {
                        encodedState = CFFStateCodec.encode(commitState, seed: seed, salt: salt)
                    } else {
                        sink.store(false)
                    }
                case commitState:
                    if let nextState {
                        _state = nextState
                        sink.store(true)
                    } else {
                        sink.store(false)
                    }
                default:
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    // MARK: - 业务方法

    /// 绑定 challenge 并进入 issued 状态
    /// - Parameter challenge: 当前挑战
    /// - Returns: 是否成功（需从 idle 转换）
    @discardableResult
    public func bindChallenge(_ challenge: ChallengeTrigger.BlindChallenge) -> Bool {
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count,
                extraStrings: [challenge.challengeId, challenge.seed],
                extraWords: [UInt64(challenge.probeIds.count), UInt64(bitPattern: challenge.expiresAt)]
            )
            let seed: UInt32 = 0x54A73C91
            let entryState: UInt32 = 0x31
            let validateState: UInt32 = 0x32
            let commitState: UInt32 = 0x33
            let rejectState: UInt32 = 0x34

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

            while !sink.isResolved {
                let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

                if decodedState == entryState {
                    encodedState = CFFStateCodec.encode(validateState, seed: seed, salt: salt)
                } else if decodedState == validateState {
                    encodedState = CFFStateCodec.encode(_state == .idle ? commitState : rejectState, seed: seed, salt: salt)
                } else if decodedState == commitState {
                    _currentChallengeId = challenge.challengeId
                    _state = .issued
                    sink.store(true)
                } else if decodedState == rejectState {
                    #if DEBUG
                    Logger.log("ChallengeSession.bindChallenge rejected: state=\(_state.rawValue)")
                    #endif
                    sink.store(false)
                } else {
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    /// 检查 challengeId 是否与当前 session 绑定一致
    public func isChallengeIdBound(_ challengeId: String) -> Bool {
        lock.withLock { _currentChallengeId == challengeId }
    }

    /// 检查 challengeId 是否已提交（防重放）
    public func hasSubmitted(_ challengeId: String) -> Bool {
        lock.withLock { _submittedChallengeIds.contains(challengeId) }
    }

    /// 标记 challengeId 已提交（防重放：每个 challengeId 只能提交一次）
    /// - Parameter challengeId: 已提交的 challengeId
    /// - Returns: 是否成功（未重复提交）
    @discardableResult
    public func markSubmitted(_ challengeId: String) -> Bool {
        lock.withLock {
            let salt = ChallengeSessionCFF.salt(
                state: _state,
                currentChallengeId: _currentChallengeId,
                executionStatus: _executionStatus,
                submittedCount: _submittedChallengeIds.count,
                extraStrings: [challengeId]
            )
            let seed: UInt32 = 0x7C92E40D
            let entryState: UInt32 = 0x41
            let replayCheckState: UInt32 = 0x42
            let insertState: UInt32 = 0x43
            let rejectState: UInt32 = 0x44

            var sink = CFFReturnSink<Bool>()
            var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

            while !sink.isResolved {
                switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
                case entryState:
                    encodedState = CFFStateCodec.encode(replayCheckState, seed: seed, salt: salt)
                case replayCheckState:
                    let nextState = _submittedChallengeIds.contains(challengeId) ? rejectState : insertState
                    encodedState = CFFStateCodec.encode(nextState, seed: seed, salt: salt)
                case insertState:
                    _submittedChallengeIds.insert(challengeId)
                    sink.store(true)
                case rejectState:
                    #if DEBUG
                    Logger.log("ChallengeSession.markSubmitted rejected: challengeId=\(challengeId) already submitted (replay)")
                    #endif
                    sink.store(false)
                default:
                    sink.store(false)
                }
            }

            return sink.resolve(or: false)
        }
    }

    /// 设置下一轮挑战（服务端下发）
    public func setNextChallenge(_ challenge: ChallengeTrigger.BlindChallenge?) {
        lock.withLock { _nextChallenge = challenge }
    }

    /// 设置探针执行状态（超时/不支持时调用）
    public func setExecutionStatus(_ status: ChallengeExecutionStatus) {
        lock.withLock { _executionStatus = status }
    }

    /// 重置 session 到 idle（用于新一轮）
    public func reset() {
        lock.withLock {
            _state = .idle
            _currentChallengeId = nil
            _nextChallenge = nil
            _executionStatus = .completed
            // 保留 _submittedChallengeIds 以持续防重放
        }
    }

    /// 完全清空（包括已提交记录和 challenge key，慎用）
    public func clearAll() {
        lock.withLock {
            _state = .idle
            _currentChallengeId = nil
            _submittedChallengeIds.removeAll()
            _nextChallenge = nil
            _executionStatus = .completed
            _challengeKey = nil
        }
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
    /// Configure the MAC key used to verify `ChallengeVerificationResult`.
    public func configureChallengeKey(_ key: Data) {
        lock.withLock { _challengeKey = SymmetricKey(data: key) }
    }

    /// Verify the custom SHA-256 MAC on a `ChallengeVerificationResult`.
    /// Returns a `challenge_hmac_mismatch` signal if verification fails, or nil on success / no key configured.
    public func verifyResult(_ result: ChallengeVerificationResult) -> RiskSignal? {
        let key: SymmetricKey? = lock.withLock { _challengeKey }

        guard let key else { return nil }

        guard let hmacHex = result.hmac, !hmacHex.isEmpty else {
            Logger.log("ChallengeSession.verifyResult: hmac field missing")
            return makeMismatchSignal(challengeId: result.challengeId, reason: "hmac_missing")
        }

        let scoreStr = result.adjustedScore.map { String(format: "%.6f", $0) } ?? "nil"
        let input = "\(result.challengeId)|\(scoreStr)|\(result.passed)"
        let inputData = Data(input.utf8)
        let expectedHex = CPRiskMessageAuth.authenticationCodeHex(for: inputData, using: key)

        guard timingSafeCompare(hmacHex.lowercased(), expectedHex.lowercased()) else {
            Logger.log("ChallengeSession.verifyResult: MAC mismatch for challengeId=\(result.challengeId)")
            return makeMismatchSignal(challengeId: result.challengeId, reason: "hmac_mismatch")
        }

        return nil
    }

    private func timingSafeCompare(_ lhs: String, _ rhs: String) -> Bool {
        let lhsBytes = Array(lhs.utf8)
        let rhsBytes = Array(rhs.utf8)
        var result: UInt8 = lhsBytes.count == rhsBytes.count ? 0 : 1
        let maxCount = max(lhsBytes.count, rhsBytes.count)
        let lhsN = max(lhsBytes.count, 1)
        let rhsN = max(rhsBytes.count, 1)
        for i in 0..<maxCount {
            result |= lhsBytes[i % lhsN] ^ rhsBytes[i % rhsN]
        }
        return result == 0
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
