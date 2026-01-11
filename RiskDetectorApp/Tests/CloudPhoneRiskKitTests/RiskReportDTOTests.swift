import XCTest
@testable import CloudPhoneRiskAppCore
@testable import CloudPhoneRiskKit

final class RiskReportDTOTests: XCTestCase {
    func test_dtoFromCPRiskReportContainsStructuredNetwork() {
        let report = CPRiskKit.shared.evaluate()
        let dto = RiskReportMapper.dto(from: report)

        XCTAssertFalse(dto.deviceID.isEmpty)
        XCTAssertTrue(["ifaddrs_prefix", "unavailable_simulator"].contains(dto.network.vpn.method))
        XCTAssertEqual(dto.network.vpn.confidence, .weak)
        XCTAssertTrue(["CFNetworkCopySystemProxySettings", "unavailable_simulator"].contains(dto.network.proxy.method))
        XCTAssertEqual(dto.network.proxy.confidence, .weak)
        XCTAssertEqual(dto.network.interfaceType.method, "NWPathMonitor")
    }

    func test_dtoContainsCloudPhoneLocalSignals() {
        let report = CPRiskKit.shared.evaluate()
        let dto = RiskReportMapper.dto(from: report)

        XCTAssertNotNil(dto.local?.cloudPhone)

        let ids = Set(dto.softSignals.map(\.id))
        XCTAssertTrue(ids.contains("cloud_behavior"))
        XCTAssertTrue(ids.contains("time_pattern"))
        XCTAssertTrue(ids.contains("simulator"))
    }

    func test_metaIsWrittenAndRead() throws {
        let report = CPRiskKit.shared.evaluate()
        let dto = RiskReportMapper.dto(from: report)

        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("CloudPhoneRiskAppCoreTests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let reportURL = dir.appendingPathComponent("risk-test.json")
        try report.jsonData(prettyPrinted: true).write(to: reportURL, options: [.atomic])

        RiskReportSummaryIO.writeMeta(for: dto, reportPath: reportURL.path)
        let meta = RiskReportSummaryIO.readMeta(reportPath: reportURL.path)

        XCTAssertEqual(meta?.score, dto.score)
        XCTAssertEqual(meta?.jailbreakIsJailbroken, dto.jailbreak.isJailbroken)
    }
}
