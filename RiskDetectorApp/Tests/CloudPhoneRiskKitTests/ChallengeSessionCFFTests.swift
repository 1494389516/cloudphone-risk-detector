import XCTest
@testable import CloudPhoneRiskKit

final class ChallengeSessionCFFTests: XCTestCase {

    private func makeChallenge(id: String = "challenge-1") -> ChallengeTrigger.BlindChallenge {
        ChallengeTrigger.BlindChallenge(
            challengeId: id,
            probeIds: ["gpu_render", "sensor_entropy"],
            seed: "seed-\(id)",
            expiresAt: 1_900_000_000_000
        )
    }

    func testBindAdvanceAndTransitionPreserveExpectedSemantics() {
        let session = ChallengeSession()
        let challenge = makeChallenge()

        XCTAssertTrue(session.bindChallenge(challenge))
        XCTAssertEqual(session.state, .issued)
        XCTAssertEqual(session.currentChallengeId, challenge.challengeId)

        XCTAssertTrue(session.advance())
        XCTAssertEqual(session.state, .executing)

        XCTAssertTrue(session.advance())
        XCTAssertEqual(session.state, .submitted)

        XCTAssertTrue(session.transition(to: .verified))
        XCTAssertEqual(session.state, .verified)

        XCTAssertTrue(session.advance())
        XCTAssertEqual(session.state, .closed)
    }

    func testInvalidTransitionFailsClosedWithoutMutatingState() {
        let session = ChallengeSession()

        XCTAssertFalse(session.transition(to: .verified))
        XCTAssertEqual(session.state, .idle)
        XCTAssertNil(session.currentChallengeId)
    }

    func testMarkSubmittedRejectsReplay() {
        let session = ChallengeSession()

        XCTAssertTrue(session.markSubmitted("challenge-dup"))
        XCTAssertTrue(session.hasSubmitted("challenge-dup"))
        XCTAssertFalse(session.markSubmitted("challenge-dup"))
    }
}
