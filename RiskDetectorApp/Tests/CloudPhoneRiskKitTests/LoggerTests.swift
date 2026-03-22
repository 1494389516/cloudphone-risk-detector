import XCTest
@testable import CloudPhoneRiskKit

final class LoggerTests: XCTestCase {

    // MARK: - Test Destination

    /// In-memory log destination for testing
    final class InMemoryLogDestination: LogDestination, @unchecked Sendable {
        private let lock = UnfairLock()
        private var _entries: [LogEntry] = []

        var entries: [LogEntry] {
            lock.withLock { _entries }
        }

        var count: Int {
            lock.withLock { _entries.count }
        }

        func write(_ entry: LogEntry) {
            lock.withLock { _entries.append(entry) }
        }

        func reset() {
            lock.withLock { _entries.removeAll() }
        }
    }

    private var destination: InMemoryLogDestination!

    override func setUp() {
        super.setUp()
        destination = InMemoryLogDestination()
        Logger.addDestination(destination)
        Logger.isEnabled = true
        Logger.releaseLoggingEnabled = true
        Logger.minimumLevel = .debug
    }

    override func tearDown() {
        Logger.removeAllDestinations()
        Logger.clearAuditTrail()
        destination = nil
        super.tearDown()
    }

    // MARK: - Log Level Tests

    func testLogLevelOrdering() {
        XCTAssertLessThan(LogLevel.debug, LogLevel.info)
        XCTAssertLessThan(LogLevel.info, LogLevel.warn)
        XCTAssertLessThan(LogLevel.warn, LogLevel.error)
        XCTAssertLessThan(LogLevel.error, LogLevel.critical)
    }

    func testLogLevelLabels() {
        XCTAssertEqual(LogLevel.debug.label, "DEBUG")
        XCTAssertEqual(LogLevel.info.label, "INFO")
        XCTAssertEqual(LogLevel.warn.label, "WARN")
        XCTAssertEqual(LogLevel.error.label, "ERROR")
        XCTAssertEqual(LogLevel.critical.label, "CRITICAL")
    }

    // MARK: - Destination Tests

    func testCustomDestinationReceivesLogs() {
        Logger.info("test message")

        // Custom destination should receive the log
        XCTAssertGreaterThan(destination.count, 0)
        let entry = destination.entries.last!
        XCTAssertEqual(entry.level, .info)
        XCTAssertEqual(entry.message, "test message")
    }

    func testMetadataPassedToDestination() {
        Logger.warn("alert", metadata: ["key": "value", "code": "42"])

        let entry = destination.entries.last!
        XCTAssertEqual(entry.metadata["key"], "value")
        XCTAssertEqual(entry.metadata["code"], "42")
    }

    func testMinimumLevelFiltering() {
        Logger.minimumLevel = .warn

        Logger.debug("should be filtered")
        Logger.info("should be filtered")
        let countBefore = destination.count

        Logger.warn("should pass")
        XCTAssertEqual(destination.count, countBefore + 1)

        Logger.error("should pass")
        XCTAssertEqual(destination.count, countBefore + 2)
    }

    func testRemoveAllDestinations() {
        Logger.removeAllDestinations()
        Logger.info("after removal")

        XCTAssertEqual(destination.count, 0, "No logs should reach removed destination")
    }

    // MARK: - Audit Trail Tests

    func testAuditAddsEntry() {
        Logger.clearAuditTrail()
        Logger.audit(action: "evaluate", details: ["score": "75", "scenario": "payment"])

        let trail = Logger.auditSnapshot()
        XCTAssertEqual(trail.count, 1)
        XCTAssertEqual(trail[0].action, "evaluate")
        XCTAssertEqual(trail[0].details["score"], "75")
        XCTAssertEqual(trail[0].details["scenario"], "payment")
    }

    func testAuditTrailRingBuffer() {
        Logger.clearAuditTrail()

        // Add more than maxAuditEntries (200)
        for i in 0..<250 {
            Logger.audit(action: "event_\(i)")
        }

        let trail = Logger.auditSnapshot()
        XCTAssertLessThanOrEqual(trail.count, 200)
        // Should have the most recent entries
        XCTAssertEqual(trail.last?.action, "event_249")
    }

    func testClearAuditTrail() {
        Logger.audit(action: "test")
        Logger.clearAuditTrail()

        let trail = Logger.auditSnapshot()
        XCTAssertTrue(trail.isEmpty)
    }

    // MARK: - Measure

    func testMeasureReturnsValue() {
        let result = Logger.measure("test_op") { 42 }
        XCTAssertEqual(result, 42)
    }

    func testMeasureThrowingClosure() {
        struct TestError: Error {}

        XCTAssertThrowsError(try Logger.measure("failing_op") {
            throw TestError()
        })
    }

    // MARK: - Thread Safety

    func testConcurrentLogging() {
        let iterations = 200
        let expectation = XCTestExpectation(description: "concurrent logging")
        expectation.expectedFulfillmentCount = iterations

        for i in 0..<iterations {
            DispatchQueue.global().async {
                Logger.info("concurrent_\(i)")
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 10.0)
        XCTAssertEqual(destination.count, iterations)
    }

    func testConcurrentAuditTrail() {
        Logger.clearAuditTrail()
        let iterations = 100
        let expectation = XCTestExpectation(description: "concurrent audit")
        expectation.expectedFulfillmentCount = iterations

        for i in 0..<iterations {
            DispatchQueue.global().async {
                Logger.audit(action: "concurrent_\(i)")
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 10.0)
        let trail = Logger.auditSnapshot()
        XCTAssertEqual(trail.count, iterations)
    }
}
