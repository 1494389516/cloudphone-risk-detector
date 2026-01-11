import XCTest
@testable import CloudPhoneRiskKit

final class BehaviorCouplingTests: XCTestCase {
    func test_correlation_basic() {
        // 10 actions over 10 seconds, motion energy increasing with actions.
        let start: TimeInterval = 1000
        let actions = (0..<10).map { start + TimeInterval($0) + 0.1 }
        let motion = (0..<200).map { i in
            let t = start + Double(i) * 0.05
            let energy = floor((t - start)) // step per second
            return MotionSample(timestamp: t, energy: energy)
        }
        let corr = BehaviorCoupling.touchMotionCorrelation(actionTimestamps: actions, motion: motion)
        XCTAssertNotNil(corr)
        XCTAssertTrue((corr ?? 0) > 0.5)
    }
}

