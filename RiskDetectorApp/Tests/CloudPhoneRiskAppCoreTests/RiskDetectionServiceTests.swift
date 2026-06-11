import XCTest
@testable import CloudPhoneRiskAppCore
@testable import CloudPhoneRiskKit

/// RiskDetectionService 单元测试：编排、配置加载、报告生成流程。
final class RiskDetectionServiceTests: XCTestCase {

    private let service = RiskDetectionService.shared
    private var tempRoot: URL!

    override func setUp() {
        super.setUp()
        tempRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("RiskDetectionServiceTests.\(UUID().uuidString)", isDirectory: true)
        RiskReportStorage.testBaseDirectoryOverride = tempRoot
        service.clearExternalServerSignals()
    }

    override func tearDown() {
        service.clearExternalServerSignals()
        RiskReportStorage.testBaseDirectoryOverride = nil
        try? FileManager.default.removeItem(at: tempRoot)
        tempRoot = nil
        super.tearDown()
    }

    // MARK: - evaluate

    func testEvaluate_ReturnsReport() {
        let report = service.evaluate(config: .default)
        XCTAssertFalse(report.deviceID.isEmpty)
        XCTAssertGreaterThanOrEqual(report.score, 0)
        XCTAssertLessThanOrEqual(report.score, 100)
        XCTAssertFalse(report.summary.isEmpty)
    }

    func testEvaluate_WithCustomConfig() {
        var config = RiskAppConfig.default
        config.enableBehaviorDetect = false
        config.enableNetworkSignals = false
        config.threshold = 80

        let report = service.evaluate(config: config)
        XCTAssertGreaterThanOrEqual(report.score, 0)
    }

    // MARK: - evaluateAsync

    func testEvaluateAsync_CompletesOnMainThread() {
        let exp = expectation(description: "evaluateAsync")
        service.evaluateAsync(config: .default) { report in
            XCTAssertTrue(Thread.isMainThread, "completion 应回到主线程")
            XCTAssertFalse(report.deviceID.isEmpty)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
    }

    // MARK: - runAsync

    func testRunAsync_ReturnsDtoAndJson() {
        let exp = expectation(description: "runAsync")
        service.runAsync(config: .default, save: false) { result in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertEqual(result.dto.deviceID, result.dto.deviceID)
            XCTAssertFalse(result.json.isEmpty)
            XCTAssertTrue(result.json.contains("{"))
            XCTAssertNil(result.savedPath, "save=false 时 savedPath 应为 nil")
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
    }

    func testRunAsync_WithSaveOnMacOS() {
#if os(macOS)
        let exp = expectation(description: "runAsync save")
        service.runAsync(config: .default, save: true) { result in
            XCTAssertNotNil(result.savedPath)
            if let path = result.savedPath {
                XCTAssertTrue(path.contains("reports"))
                XCTAssertTrue(path.hasSuffix(".json"))
            }
            exp.fulfill()
        }
        wait(for: [exp], timeout: 5)
#endif
    }

    // MARK: - setRemoteConfigJSON

    func testSetRemoteConfigJSON_ValidJSON() {
        // 需使用完整 RemoteConfig 结构，否则 JSON 解析失败
        let json = RemoteConfig.sampleJSON
        let ok = service.setRemoteConfigJSON(json)
        XCTAssertTrue(ok, "setRemoteConfigJSON 应接受有效的 RemoteConfig JSON")
    }

    func testSetRemoteConfigJSON_InvalidJSON() {
        let ok = service.setRemoteConfigJSON("not valid json")
        XCTAssertFalse(ok)
    }

    // MARK: - save (macOS)

    func testSave_ReturnsPathOnMacOS() {
#if os(macOS)
        let context = TestFixtures.makeRiskContext()
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)

        let path = service.save(report: cprReport, config: .default)
        XCTAssertNotNil(path)
        if let p = path {
            XCTAssertTrue(FileManager.default.fileExists(atPath: p))
            _ = RiskReportStorage.delete(atPath: p)
        }
#endif
    }

    // MARK: - loadSavedReportJSON

    func testLoadSavedReportJSON_NonExistentReturnsNil() {
        let json = service.loadSavedReportJSON(atPath: "/nonexistent/path.json")
        XCTAssertNil(json)
    }

    // MARK: - Provider management

    func testRegisteredProviderIDs_ReturnsArray() {
        let ids = service.registeredProviderIDs()
        XCTAssertTrue(ids.allSatisfy { !$0.isEmpty }, "每个 provider ID 不得为空")
        // 启动后应有若干内置 provider
        XCTAssertFalse(ids.isEmpty, "registeredProviderIDs 应返回非空数组")
    }

    // MARK: - Orchestration flow

    func testFullFlow_EvaluateToDtoToSave() {
#if os(macOS)
        let report = service.evaluate(config: .default)
        let dto = RiskReportMapper.dto(from: report)
        XCTAssertEqual(dto.deviceID, report.deviceID)
        XCTAssertEqual(dto.score, report.score)

        let path = service.save(report: report, config: .default)
        XCTAssertNotNil(path)
        if let p = path {
            let loaded = service.loadSavedReportJSON(atPath: p)
            XCTAssertNotNil(loaded)
            XCTAssertFalse(loaded?.isEmpty ?? true)
            _ = RiskReportStorage.delete(atPath: p)
        }
#endif
    }
}
