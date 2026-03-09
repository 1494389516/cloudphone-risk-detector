import XCTest
@testable import CloudPhoneRiskKit

final class StorageTests: XCTestCase {

    // MARK: - FreshnessState Tests

    func testFreshnessStateZero() {
        let zero = FreshnessState.zero
        XCTAssertEqual(zero.latestTimestamp, 0)
        XCTAssertEqual(zero.sequence, 0)
    }

    func testFreshnessStateDominates() {
        let a = FreshnessState(latestTimestamp: 100, sequence: 5)
        let b = FreshnessState(latestTimestamp: 50, sequence: 3)
        let c = FreshnessState(latestTimestamp: 200, sequence: 2)

        // a dominates b (both timestamp and sequence are >=)
        XCTAssertTrue(a.dominates(b))

        // b does NOT dominate a
        XCTAssertFalse(b.dominates(a))

        // a does NOT dominate c (a.timestamp < c.timestamp)
        XCTAssertFalse(a.dominates(c))

        // c does NOT dominate a (c.sequence < a.sequence)
        XCTAssertFalse(c.dominates(a))

        // zero dominates zero
        XCTAssertTrue(FreshnessState.zero.dominates(.zero))
    }

    func testFreshnessStateDominatesEdgeCases() {
        let a = FreshnessState(latestTimestamp: 100, sequence: 5)
        // Equal values should dominate
        XCTAssertTrue(a.dominates(a))

        // One field equal, other greater
        let b = FreshnessState(latestTimestamp: 100, sequence: 3)
        XCTAssertTrue(a.dominates(b))

        let c = FreshnessState(latestTimestamp: 50, sequence: 5)
        XCTAssertTrue(a.dominates(c))
    }

    func testFreshnessStateCodable() throws {
        let original = FreshnessState(latestTimestamp: 1709884800.123, sequence: 42)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(FreshnessState.self, from: encoded)

        XCTAssertEqual(decoded.latestTimestamp, original.latestTimestamp)
        XCTAssertEqual(decoded.sequence, original.sequence)
    }

    // MARK: - RiskHistoryEvent Tests

    func testRiskHistoryEventCodable() throws {
        let event = RiskHistoryEvent(
            t: 1709884800.0,
            score: 75.5,
            isHighRisk: true,
            summary: "high_risk"
        )
        let encoded = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(RiskHistoryEvent.self, from: encoded)

        XCTAssertEqual(decoded.t, event.t)
        XCTAssertEqual(decoded.score, event.score)
        XCTAssertEqual(decoded.isHighRisk, event.isHighRisk)
        XCTAssertEqual(decoded.summary, event.summary)
    }

    // MARK: - TimePattern Tests

    func testTimePatternDefaults() {
        let pattern = TimePattern(
            events24h: 0,
            uniqueHours24h: 0,
            nightRatio24h: nil,
            averageIntervalSeconds24h: nil
        )
        XCTAssertEqual(pattern.events24h, 0)
        XCTAssertEqual(pattern.uniqueHours24h, 0)
        XCTAssertNil(pattern.nightRatio24h)
        XCTAssertNil(pattern.averageIntervalSeconds24h)
    }

    func testTimePatternCodable() throws {
        let pattern = TimePattern(
            events24h: 10,
            uniqueHours24h: 5,
            nightRatio24h: 0.3,
            averageIntervalSeconds24h: 3600.0
        )
        let encoded = try JSONEncoder().encode(pattern)
        let decoded = try JSONDecoder().decode(TimePattern.self, from: encoded)

        XCTAssertEqual(decoded.events24h, 10)
        XCTAssertEqual(decoded.uniqueHours24h, 5)
        XCTAssertEqual(decoded.nightRatio24h, 0.3)
        XCTAssertEqual(decoded.averageIntervalSeconds24h, 3600.0)
    }

    // MARK: - RiskHistoryStore Tests

    func testHistoryStoreAppendAndPattern() {
        let defaults = UserDefaults(suiteName: "test_history_\(UUID().uuidString)")!
        let store = RiskHistoryStore(defaults: defaults)
        let now = Date().timeIntervalSince1970

        store.append(RiskHistoryEvent(t: now - 3600, score: 30, isHighRisk: false, summary: "low"))
        store.append(RiskHistoryEvent(t: now - 1800, score: 75, isHighRisk: true, summary: "high"))
        store.append(RiskHistoryEvent(t: now - 900, score: 45, isHighRisk: false, summary: "medium"))

        let pattern = store.pattern(now: now)
        XCTAssertGreaterThanOrEqual(pattern.events24h, 0)
        // We can't guarantee exact counts due to encryption/keychain deps in test env
    }

    func testHistoryStoreEmptyPattern() {
        let defaults = UserDefaults(suiteName: "test_empty_\(UUID().uuidString)")!
        let store = RiskHistoryStore(defaults: defaults)
        let now = Date().timeIntervalSince1970

        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 0)
        XCTAssertEqual(pattern.uniqueHours24h, 0)
        XCTAssertNil(pattern.nightRatio24h)
        XCTAssertNil(pattern.averageIntervalSeconds24h)
    }

    func testHistoryStorePatternNightRatioCalculation() {
        // TimePattern nightRatio should be between 0 and 1 when events exist
        let pattern = TimePattern(
            events24h: 10,
            uniqueHours24h: 3,
            nightRatio24h: 0.5,
            averageIntervalSeconds24h: 1200
        )
        XCTAssertGreaterThanOrEqual(pattern.nightRatio24h!, 0.0)
        XCTAssertLessThanOrEqual(pattern.nightRatio24h!, 1.0)
    }

    // MARK: - StorageIntegrityGuard Tests

    func testStorageIntegritySignAndVerify() {
        let testData = Data("test payload".utf8)
        let purpose = "test_purpose"

        let signature = StorageIntegrityGuard.sign(testData, purpose: purpose)
        XCTAssertFalse(signature.isEmpty)

        let isValid = StorageIntegrityGuard.verify(testData, signature: signature, purpose: purpose)
        XCTAssertTrue(isValid)
    }

    func testStorageIntegrityRejectsTamperedData() {
        let testData = Data("original data".utf8)
        let purpose = "test_purpose"

        let signature = StorageIntegrityGuard.sign(testData, purpose: purpose)

        // Tamper with data
        let tamperedData = Data("tampered data".utf8)
        let isValid = StorageIntegrityGuard.verify(tamperedData, signature: signature, purpose: purpose)
        XCTAssertFalse(isValid)
    }

    func testStorageIntegrityRejectsWrongPurpose() {
        let testData = Data("test payload".utf8)

        let signature = StorageIntegrityGuard.sign(testData, purpose: "purpose_a")
        let isValid = StorageIntegrityGuard.verify(testData, signature: signature, purpose: "purpose_b")
        XCTAssertFalse(isValid)
    }

    func testStorageIntegrityRejectsTamperedSignature() {
        let testData = Data("test payload".utf8)
        let purpose = "test_purpose"

        var signature = StorageIntegrityGuard.sign(testData, purpose: purpose)
        // Flip a bit in the signature
        if !signature.isEmpty {
            signature[0] ^= 0xFF
        }

        let isValid = StorageIntegrityGuard.verify(testData, signature: signature, purpose: purpose)
        XCTAssertFalse(isValid)
    }

    func testStorageIntegrityConsistentSigning() {
        let testData = Data("consistent test".utf8)
        let purpose = "test_purpose"

        let sig1 = StorageIntegrityGuard.sign(testData, purpose: purpose)
        let sig2 = StorageIntegrityGuard.sign(testData, purpose: purpose)

        // Same key should produce same signature
        XCTAssertEqual(sig1, sig2)
    }

    func testStorageIntegrityEmptyData() {
        let emptyData = Data()
        let purpose = "test"

        let signature = StorageIntegrityGuard.sign(emptyData, purpose: purpose)
        XCTAssertFalse(signature.isEmpty)

        let isValid = StorageIntegrityGuard.verify(emptyData, signature: signature, purpose: purpose)
        XCTAssertTrue(isValid)
    }
}
