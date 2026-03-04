import XCTest
@testable import CloudPhoneRiskKit

final class ChallengeTriggerRoadmapTests: XCTestCase {

    func testCapabilityAutoTrigger() {
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 2,
            tamperedCount: 1,
            existingRules: [
                .init(id: "r1", minTamperedCount: 99, minCapabilityAnomalyCount: 99),
            ]
        )

        XCTAssertTrue(result.triggered)
        XCTAssertEqual(result.matchedRule?.id, "auto_capability_trigger")
    }

    func testCapabilityAutoTriggerWithoutRules() {
        let result = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityAnomalyCount: 2,
            tamperedCount: 1,
            existingRules: []
        )

        XCTAssertTrue(result.triggered)
        XCTAssertEqual(result.matchedRule?.id, "auto_capability_trigger")
    }

    func testBuildChallengePayloadIncludesBindingFields() {
        let challenge = ChallengeTrigger.BlindChallenge(
            challengeId: "ch-1",
            probeIds: ["stat_bash", "sock_27042"],
            seed: "seed-abc",
            expiresAt: Int64(Date().timeIntervalSince1970 * 1000) + 60_000
        )

        let score = CapabilityScore(basicAnomalyCount: 3, qualitySuspicion: 5, totalProbes: 8)
        let payload = ChallengeTrigger.buildChallengePayload(
            challenge: challenge,
            capabilityScore: score,
            tamperedCount: 2,
            executedProbeIDs: ["stat_bash", "sock_27042"]
        )

        XCTAssertEqual(payload["challengeId"] as? String, "ch-1")
        XCTAssertEqual(payload["seed"] as? String, "seed-abc")
        XCTAssertNotNil(payload["probeIds"])
        XCTAssertNotNil(payload["executedProbeIds"])
    }

    func testChallengeExpiryValidation() {
        let expired = ChallengeTrigger.BlindChallenge(
            challengeId: "expired",
            probeIds: ["stat_bash"],
            seed: "seed",
            expiresAt: Int64(Date().timeIntervalSince1970 * 1000) - 1
        )

        XCTAssertFalse(ChallengeTrigger.isChallengeValid(expired))
    }

    func testChallengePayloadSignatureRoundTrip() {
        let payload: [String: Any] = [
            "challengeId": "ch-2",
            "seed": "s-1",
            "timestamp": Int64(1234567890),
            "capabilityAnomalyCount": 2,
        ]

        let signature = ChallengeTrigger.signChallengePayload(payload: payload, signingKey: "secret")
        XCTAssertNotNil(signature)

        let ok = ChallengeTrigger.verifyChallengePayloadSignature(
            payload: payload,
            signature: signature ?? "",
            signingKey: "secret"
        )
        XCTAssertTrue(ok)
    }
}
