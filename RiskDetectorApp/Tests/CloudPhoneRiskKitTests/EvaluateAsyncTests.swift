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

    func test_evaluateWithScenarioCallsBackOnMainThread() {
        let exp = expectation(description: "evaluate(scenario:) completion")
        CPRiskKit.shared.evaluate(scenario: .payment) { report in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertFalse(report.summary.isEmpty)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 2.0)
    }

    func test_updateRemoteConfigFailsWithoutEndpoint() {
        let exp = expectation(description: "updateRemoteConfig completion")
        let kit = CPRiskKit.shared
        kit.clearRemoteConfigEndpoint()

        kit.updateRemoteConfig { success in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertFalse(success)
            exp.fulfill()
        }

        wait(for: [exp], timeout: 2.0)
    }

    func test_featureTogglesDisableTemporalAndAntiTamperProviders() {
        let config = CPRiskConfig()
        config.enableTemporalAnalysis = false
        config.enableAntiTamper = false

        _ = CPRiskKit.shared.evaluate(config: config, scenario: .default)
        let ids = Set(CPRiskKit.registeredProviderIDs())

        XCTAssertFalse(ids.contains("time_pattern"))
        XCTAssertFalse(ids.contains("anti_tampering"))
    }

    func test_featureTogglesEnableTemporalAndAntiTamperProviders() {
        let config = CPRiskConfig()
        config.enableTemporalAnalysis = true
        config.enableAntiTamper = true

        _ = CPRiskKit.shared.evaluate(config: config, scenario: .default)
        let ids = Set(CPRiskKit.registeredProviderIDs())

        XCTAssertTrue(ids.contains("time_pattern"))
        XCTAssertTrue(ids.contains("anti_tampering"))
    }

    func test_temporalDisabledStillKeepsLocalTimePatternPayload() throws {
        let config = CPRiskConfig()
        config.enableTemporalAnalysis = false

        _ = CPRiskKit.shared.evaluate(config: config, scenario: .default)
        let report = CPRiskKit.shared.evaluate(config: config, scenario: .default)

        let object = try JSONSerialization.jsonObject(with: report.jsonData(), options: []) as? [String: Any]
        let local = object?["local"] as? [String: Any]

        XCTAssertNotNil(local?["timePattern"])
    }

    @available(iOS 13.0, macOS 10.15, *)
    func test_asyncAwaitScenarioEvaluateReturnsReport() async {
        let report = await CPRiskKit.shared.evaluateAsync(config: .default, scenario: .payment)
        XCTAssertFalse(report.summary.isEmpty)
        XCTAssertFalse(report.jsonString().isEmpty)
    }

    @available(iOS 13.0, macOS 10.15, *)
    func test_updateRemoteConfigAsyncThrowsWithoutEndpoint() async {
        let kit = CPRiskKit.shared
        kit.clearRemoteConfigEndpoint()

        do {
            try await kit.updateRemoteConfigAsync()
            XCTFail("expected updateRemoteConfigAsync to throw when endpoint not configured")
        } catch {
            XCTAssertNotNil(error as? ConfigError)
        }
    }
}
