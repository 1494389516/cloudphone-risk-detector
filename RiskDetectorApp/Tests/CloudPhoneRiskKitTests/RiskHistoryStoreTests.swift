import XCTest
@testable import CloudPhoneRiskKit

final class RiskHistoryStoreTests: XCTestCase {
    func test_patternCounts() throws {
        let suite = "CloudPhoneRiskKitTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let store = RiskHistoryStore(defaults: defaults)

        let now = Date().timeIntervalSince1970
        for i in 0..<10 {
            store.append(RiskHistoryEvent(t: now - Double(i) * 60, score: 10, isHighRisk: false, summary: "x"))
        }
        let p = store.pattern(now: now)
        XCTAssertEqual(p.events24h, 10)
        XCTAssertTrue(p.uniqueHours24h >= 1)
        XCTAssertNotNil(p.averageIntervalSeconds24h)
    }
}

