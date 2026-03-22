import Foundation

// MARK: - Actor-based Challenge Session Facade
//
// Provides async/await access to ChallengeSession for modern Swift concurrency code paths.

/// Actor-based facade for challenge session operations.
@available(iOS 13.0, macOS 10.15, *)
public actor ChallengeSessionActor {

    public static let shared = ChallengeSessionActor()

    private let session: ChallengeSession

    init(session: ChallengeSession = .shared) {
        self.session = session
    }

    /// Current session state.
    public func state() -> ChallengeSessionState {
        session.state
    }

    /// Bind a challenge and transition to issued state.
    @discardableResult
    public func bindChallenge(_ challenge: ChallengeTrigger.BlindChallenge) -> Bool {
        session.bindChallenge(challenge)
    }

    /// Advance to the next state in the flow.
    @discardableResult
    public func advance() -> Bool {
        session.advance()
    }

    /// Transition to a specific state.
    @discardableResult
    public func transition(to target: ChallengeSessionState) -> Bool {
        session.transition(to: target)
    }

    /// Mark a challenge ID as submitted (anti-replay).
    @discardableResult
    public func markSubmitted(_ challengeId: String) -> Bool {
        session.markSubmitted(challengeId)
    }

    /// Check if a challenge ID has been submitted.
    public func hasSubmitted(_ challengeId: String) -> Bool {
        session.hasSubmitted(challengeId)
    }

    /// Reset session to idle.
    public func reset() {
        session.reset()
    }

    /// Verify a challenge result's HMAC.
    public func verifyResult(_ result: ChallengeVerificationResult) -> RiskSignal? {
        session.verifyResult(result)
    }
}
