import XCTest
@testable import CloudPhoneRiskKit

final class ChallengeTriggerTests: XCTestCase {

    // MARK: - shouldTriggerBlindChallenge (count-based)

    func testNoRulesNoTrigger() {
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 5,
            tamperedCount: 3,
            existingRules: []
        )
        #if DEBUG
        XCTAssertTrue(result.triggered)
        XCTAssertEqual(result.matchedRule?.id, "debug_local_auto_trigger")
        #else
        // In release mode, empty rules = no trigger
        XCTAssertFalse(result.triggered)
        #endif
    }

    func testNoRulesBelowDebugThresholdNoTrigger() {
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 1,
            tamperedCount: 0,
            existingRules: []
        )
        XCTAssertFalse(result.triggered)
    }

    func testMatchingRuleTriggers() {
        let rule = ServerRiskPolicy.BlindRule(
            id: "r1",
            minTamperedCount: 2,
            minCapabilityAnomalyCount: 3,
            weight: 75
        )
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 3,
            tamperedCount: 2,
            existingRules: [rule]
        )

        XCTAssertTrue(result.triggered)
        XCTAssertEqual(result.matchedRule?.id, "r1")
        XCTAssertTrue(result.reason.contains("r1"))
    }

    func testBelowCapabilityThresholdDoesNotTrigger() {
        let rule = ServerRiskPolicy.BlindRule(
            id: "r2",
            minTamperedCount: 1,
            minCapabilityAnomalyCount: 5,
            weight: 75
        )
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 4,
            tamperedCount: 5,
            existingRules: [rule]
        )

        XCTAssertFalse(result.triggered)
    }

    func testBelowTamperedThresholdDoesNotTrigger() {
        let rule = ServerRiskPolicy.BlindRule(
            id: "r3",
            minTamperedCount: 5,
            minCapabilityAnomalyCount: 1,
            weight: 75
        )
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 10,
            tamperedCount: 4,
            existingRules: [rule]
        )

        XCTAssertFalse(result.triggered)
    }

    func testFirstMatchingRuleWins() {
        let rules = [
            ServerRiskPolicy.BlindRule(id: "first", minTamperedCount: 1, minCapabilityAnomalyCount: 1, weight: 50),
            ServerRiskPolicy.BlindRule(id: "second", minTamperedCount: 1, minCapabilityAnomalyCount: 1, weight: 90),
        ]
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 5,
            tamperedCount: 5,
            existingRules: rules
        )

        XCTAssertTrue(result.triggered)
        XCTAssertEqual(result.matchedRule?.id, "first")
    }

    // MARK: - shouldTriggerBlindChallenge (CapabilityScore-based)

    func testCapabilityScoreOverload() {
        let score = CapabilityScore(basicAnomalyCount: 3, qualitySuspicion: 0, totalProbes: 8)
        let rule = ServerRiskPolicy.BlindRule(
            id: "score_rule",
            minTamperedCount: 1,
            minCapabilityAnomalyCount: 2,
            weight: 75
        )
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityScore: score,
            tamperedCount: 3,
            existingRules: [rule]
        )

        XCTAssertTrue(result.triggered)
    }

    // MARK: - validateWithRule

    func testValidateWithRulePass() {
        let rule = ServerRiskPolicy.BlindRule(
            id: "v1",
            minTamperedCount: 2,
            minCapabilityAnomalyCount: 3,
            weight: 75
        )
        XCTAssertTrue(ChallengeTrigger.validateWithRule(
            capabilityAnomalyCount: 3,
            tamperedCount: 2,
            rule: rule
        ))
    }

    func testValidateWithRuleFailCapability() {
        let rule = ServerRiskPolicy.BlindRule(
            id: "v2",
            minTamperedCount: 0,
            minCapabilityAnomalyCount: 5,
            weight: 75
        )
        XCTAssertFalse(ChallengeTrigger.validateWithRule(
            capabilityAnomalyCount: 4,
            tamperedCount: 10,
            rule: rule
        ))
    }

    func testValidateWithRuleFailTampered() {
        let rule = ServerRiskPolicy.BlindRule(
            id: "v3",
            minTamperedCount: 5,
            minCapabilityAnomalyCount: 0,
            weight: 75
        )
        XCTAssertFalse(ChallengeTrigger.validateWithRule(
            capabilityAnomalyCount: 10,
            tamperedCount: 4,
            rule: rule
        ))
    }

    // MARK: - BlindChallenge

    func testBlindChallengeCodable() throws {
        let challenge = ChallengeTrigger.BlindChallenge(
            challengeId: "ch1",
            probeIds: ["stat_bash", "fork_ability"],
            seed: "random_seed",
            expiresAt: 1700000000000
        )
        let data = try JSONEncoder().encode(challenge)
        let decoded = try JSONDecoder().decode(ChallengeTrigger.BlindChallenge.self, from: data)

        XCTAssertEqual(decoded.challengeId, "ch1")
        XCTAssertEqual(decoded.probeIds, ["stat_bash", "fork_ability"])
        XCTAssertEqual(decoded.seed, "random_seed")
        XCTAssertEqual(decoded.expiresAt, 1700000000000)
    }

    // MARK: - isChallengeValid

    func testChallengeValidBeforeExpiry() {
        let challenge = ChallengeTrigger.BlindChallenge(
            challengeId: "ch2",
            probeIds: [],
            seed: "s",
            expiresAt: ChallengeTrigger.nowMillis() + 60_000
        )
        XCTAssertTrue(ChallengeTrigger.isChallengeValid(challenge))
    }

    func testChallengeExpired() {
        let challenge = ChallengeTrigger.BlindChallenge(
            challengeId: "ch3",
            probeIds: [],
            seed: "s",
            expiresAt: ChallengeTrigger.nowMillis() - 1000
        )
        XCTAssertFalse(ChallengeTrigger.isChallengeValid(challenge))
    }

    // MARK: - computeExpectedHash

    func testComputeExpectedHashDeterministic() {
        let h1 = ChallengeTrigger.computeExpectedHash(seed: "abc", deviceFingerprint: "dev1")
        let h2 = ChallengeTrigger.computeExpectedHash(seed: "abc", deviceFingerprint: "dev1")
        XCTAssertEqual(h1, h2)
        XCTAssertEqual(h1.count, 64) // SHA256 hex
    }

    func testComputeExpectedHashDifferentInputs() {
        let h1 = ChallengeTrigger.computeExpectedHash(seed: "abc", deviceFingerprint: "dev1")
        let h2 = ChallengeTrigger.computeExpectedHash(seed: "abc", deviceFingerprint: "dev2")
        XCTAssertNotEqual(h1, h2)
    }

    // MARK: - signChallengePayload / verifyChallengePayloadSignature

    func testSignAndVerifyPayload() {
        let payload: [String: Any] = [
            "capabilityAnomalyCount": 2,
            "tamperedCount": 1,
            "timestamp": 1000
        ]
        let key = "test_signing_key"

        let signature = ChallengeTrigger.signChallengePayload(payload: payload, signingKey: key)
        XCTAssertNotNil(signature)

        let verified = ChallengeTrigger.verifyChallengePayloadSignature(
            payload: payload,
            signature: signature!,
            signingKey: key
        )
        XCTAssertTrue(verified)
    }

    func testVerifyWithWrongKey() {
        let payload: [String: Any] = ["key": "value"]
        let signature = ChallengeTrigger.signChallengePayload(payload: payload, signingKey: "correct_key")!

        let verified = ChallengeTrigger.verifyChallengePayloadSignature(
            payload: payload,
            signature: signature,
            signingKey: "wrong_key"
        )
        XCTAssertFalse(verified)
    }

    func testVerifyWithTamperedPayload() {
        let original: [String: Any] = ["amount": 100]
        let tampered: [String: Any] = ["amount": 999]
        let key = "signing_key"

        let signature = ChallengeTrigger.signChallengePayload(payload: original, signingKey: key)!

        let verified = ChallengeTrigger.verifyChallengePayloadSignature(
            payload: tampered,
            signature: signature,
            signingKey: key
        )
        XCTAssertFalse(verified)
    }

    // MARK: - buildChallengePayload

    func testBuildChallengePayloadContainsExpectedKeys() {
        let score = CapabilityScore(basicAnomalyCount: 2, qualitySuspicion: 3, totalProbes: 8)
        let payload = ChallengeTrigger.buildChallengePayload(
            capabilityScore: score,
            tamperedCount: 1,
            salt: "test_salt",
            timestamp: 12345
        )

        XCTAssertEqual(payload["capabilityAnomalyCount"] as? Int, 2)
        XCTAssertEqual(payload["qualitySuspicion"] as? Int, 3)
        XCTAssertEqual(payload["totalProbes"] as? Int, 8)
        XCTAssertEqual(payload["tamperedCount"] as? Int, 1)
        XCTAssertEqual(payload["salt"] as? String, "test_salt")
        XCTAssertEqual(payload["timestamp"] as? Int64, 12345)
        XCTAssertEqual(payload["probeRiskContribution"] as? Int, score.riskContribution)
    }

    // MARK: - TriggerResult.noTrigger

    func testNoTriggerResult() {
        let result = ChallengeTrigger.TriggerResult.noTrigger
        XCTAssertFalse(result.triggered)
        XCTAssertNil(result.matchedRule)
        XCTAssertEqual(result.reason, "")
    }
}
