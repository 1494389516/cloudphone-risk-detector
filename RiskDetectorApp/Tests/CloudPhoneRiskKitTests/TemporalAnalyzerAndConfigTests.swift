import XCTest
@testable import CloudPhoneRiskKit

// MARK: - TimeWindow Tests

final class TimeWindowTests: XCTestCase {

    func testLastHourWindowContainsRecentTimestamp() {
        let now = Date().timeIntervalSince1970
        let window = TimeWindow.last1Hour
        XCTAssertTrue(window.contains(now - 100), "1 小时内的时间戳应在窗口内")
        XCTAssertFalse(window.contains(now - 7200), "2 小时前的时间戳不应在窗口内")
    }

    func testExplicitWindowBounds() {
        let now = Date().timeIntervalSince1970
        let window = TimeWindow(duration: 3600, startTime: now - 3600, endTime: now)
        XCTAssertTrue(window.contains(now - 1800))
        XCTAssertFalse(window.contains(now + 1))
    }

    func testPresetWindowDurations() {
        XCTAssertEqual(TimeWindow.last1Hour.duration, 3600)
        XCTAssertEqual(TimeWindow.last6Hours.duration, 21600)
        XCTAssertEqual(TimeWindow.last24Hours.duration, 86400)
        XCTAssertEqual(TimeWindow.last7Days.duration, 604800)
        XCTAssertEqual(TimeWindow.last30Days.duration, 2592000)
    }

    func testGetActualRangeEndIsNow() {
        let window = TimeWindow.last1Hour
        let range = window.getActualRange()
        let now = Date().timeIntervalSince1970
        XCTAssertEqual(range.end, now, accuracy: 1.0, "end 应近似为当前时间")
        XCTAssertEqual(range.start, range.end - 3600, accuracy: 1.0)
    }
}

// MARK: - TemporalRiskHistoryEvent / [TemporalRiskHistoryEvent] Tests

final class TemporalRiskHistoryEventTests: XCTestCase {

    private func makeEvent(
        timestamp: TimeInterval,
        score: Double,
        isHighRisk: Bool = false
    ) -> TemporalRiskHistoryEvent {
        TemporalRiskHistoryEvent(
            timestamp: timestamp,
            score: score,
            isHighRisk: isHighRisk,
            summary: isHighRisk ? "high_risk" : "low_risk"
        )
    }

    // MARK: calculateIntervals

    func testCalculateIntervalsEmptyReturnsEmpty() {
        let events: [TemporalRiskHistoryEvent] = []
        XCTAssertTrue(events.calculateIntervals().isEmpty)
    }

    func testCalculateIntervalsSingleEventReturnsEmpty() {
        let events = [makeEvent(timestamp: 1000, score: 30)]
        XCTAssertTrue(events.calculateIntervals().isEmpty)
    }

    func testCalculateIntervalsCorrectDeltas() {
        let events = [
            makeEvent(timestamp: 1000, score: 20),
            makeEvent(timestamp: 1300, score: 25),
            makeEvent(timestamp: 1900, score: 30)
        ]
        let intervals = events.calculateIntervals()
        XCTAssertEqual(intervals.count, 2)
        XCTAssertEqual(intervals[0], 300.0, accuracy: 0.001)
        XCTAssertEqual(intervals[1], 600.0, accuracy: 0.001)
    }

    func testCalculateIntervalsUnorderedInputSortedFirst() {
        // Events added out-of-order — should still calculate correct chronological intervals
        let events = [
            makeEvent(timestamp: 1900, score: 30),
            makeEvent(timestamp: 1000, score: 20),
            makeEvent(timestamp: 1300, score: 25)
        ]
        let intervals = events.calculateIntervals()
        XCTAssertEqual(intervals.count, 2)
        XCTAssertEqual(intervals[0], 300.0, accuracy: 0.001)
        XCTAssertEqual(intervals[1], 600.0, accuracy: 0.001)
    }

    // MARK: averageInterval

    func testAverageIntervalNilForSingleEvent() {
        let events = [makeEvent(timestamp: 1000, score: 30)]
        XCTAssertNil(events.averageInterval())
    }

    func testAverageIntervalNilForEmptyEvents() {
        let events: [TemporalRiskHistoryEvent] = []
        XCTAssertNil(events.averageInterval())
    }

    func testAverageIntervalCorrectValue() {
        let events = [
            makeEvent(timestamp: 0, score: 10),
            makeEvent(timestamp: 100, score: 20),
            makeEvent(timestamp: 300, score: 30)
        ]
        // Intervals: [100, 200] → avg = 150
        let avg = events.averageInterval()
        XCTAssertNotNil(avg)
        XCTAssertEqual(avg!, 150.0, accuracy: 0.001)
    }

    // MARK: sortedByTime

    func testSortedByTimeAscending() {
        let events = [
            makeEvent(timestamp: 300, score: 30),
            makeEvent(timestamp: 100, score: 10),
            makeEvent(timestamp: 200, score: 20)
        ]
        let sorted = events.sortedByTime()
        XCTAssertEqual(sorted[0].timestamp, 100)
        XCTAssertEqual(sorted[1].timestamp, 200)
        XCTAssertEqual(sorted[2].timestamp, 300)
    }

    // MARK: filtered(by:)

    func testFilteredByWindowKeepsInWindow() {
        let now = Date().timeIntervalSince1970
        let events = [
            makeEvent(timestamp: now - 500, score: 20),
            makeEvent(timestamp: now - 200, score: 25),
            makeEvent(timestamp: now - 10000, score: 80, isHighRisk: true)
        ]
        let filtered = events.filtered(by: .last1Hour)
        XCTAssertEqual(filtered.count, 2, "超出 1 小时的事件应被过滤")
    }

    // MARK: Codable round-trip

    func testTemporalRiskHistoryEventCodableRoundtrip() throws {
        let event = TemporalRiskHistoryEvent(
            timestamp: 1741800000,
            score: 72.5,
            isHighRisk: true,
            summary: "high_risk",
            scenario: .payment,
            action: .block,
            extras: ["source": "jailbreak"]
        )
        let data = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(TemporalRiskHistoryEvent.self, from: data)
        XCTAssertEqual(decoded.timestamp, event.timestamp, accuracy: 0.001)
        XCTAssertEqual(decoded.score, event.score, accuracy: 0.001)
        XCTAssertEqual(decoded.isHighRisk, event.isHighRisk)
        XCTAssertEqual(decoded.summary, event.summary)
        XCTAssertEqual(decoded.scenario, event.scenario)
        XCTAssertEqual(decoded.action, event.action)
        XCTAssertEqual(decoded.extras["source"], "jailbreak")
    }
}

// MARK: - ProviderConfig Tests

final class ProviderConfigTests: XCTestCase {

    private func makeConfig(
        effectiveDaysAgo: Double = 1,
        expireDaysFromNow: Double = 30
    ) -> ProviderConfig {
        let now = Date()
        return ProviderConfig(
            version: "1.0.0",
            effectiveTime: now.addingTimeInterval(-effectiveDaysAgo * 86400),
            expireTime: now.addingTimeInterval(expireDaysFromNow * 86400),
            detectors: ProviderDetectorConfigs(),
            policies: PolicyConfigs(),
            scenarios: ScenarioConfigs(),
            signature: "test_sig"
        )
    }

    func testEffectiveConfigIsEffectiveAndNotExpired() {
        let config = makeConfig()
        XCTAssertTrue(config.isEffective)
        XCTAssertFalse(config.isExpired)
    }

    func testExpiredConfigIsNotEffective() {
        let config = makeConfig(expireDaysFromNow: -1)
        XCTAssertFalse(config.isEffective, "已过期配置不应为 effective")
        XCTAssertTrue(config.isExpired)
    }

    func testFutureEffectiveTimeConfigIsNotYetEffective() {
        let config = makeConfig(effectiveDaysAgo: -1, expireDaysFromNow: 30) // effective in 1 day
        XCTAssertFalse(config.isEffective, "尚未生效的配置不应为 effective")
        XCTAssertFalse(config.isExpired)
    }

    func testCodableRoundtrip() throws {
        let config = makeConfig()
        let data = try JSONEncoder().encode(config)
        let decoded = try JSONDecoder().decode(ProviderConfig.self, from: data)
        XCTAssertEqual(decoded.version, config.version)
        XCTAssertEqual(decoded.signature, config.signature)
    }
}
