import XCTest
@testable import CloudPhoneRiskKit

final class EvaluateAsyncTests: XCTestCase {
    func test_evaluateAsyncCallsBackOnMainThread() {
        let exp = expectation(description: "evaluateAsync completion")
        CPRiskKit.shared.evaluateAsync { report in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertFalse(report.jsonString().isEmpty)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2.0)
    }
}

