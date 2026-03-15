import XCTest
@testable import CloudPhoneRiskAppCore
@testable import CloudPhoneRiskKit

/// RiskReportMapper 单元测试：映射 CPRiskReport/JSON 到 RiskReportDTO，含边界情况。
final class RiskReportMapperTests: XCTestCase {

    // MARK: - dto(from: CPRiskReport)

    func testDtoFromReport_BasicMapping() {
        let context = TestFixtures.makeRiskContext(isJailbroken: false)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)

        let dto = RiskReportMapper.dto(from: cprReport)

        XCTAssertEqual(dto.deviceID, context.deviceID)
        XCTAssertEqual(dto.score, report.score)
        XCTAssertEqual(dto.isHighRisk, report.isHighRisk)
        XCTAssertEqual(dto.summary, report.summary)
        XCTAssertEqual(dto.jailbreak.isJailbroken, context.jailbreak.isJailbroken)
        XCTAssertEqual(dto.jailbreak.confidence, context.jailbreak.confidence)
        XCTAssertFalse(dto.hardSignals.isEmpty, "至少应有 jailbreak 硬信号")
        XCTAssertFalse(dto.softSignals.isEmpty, "至少应有 VPN/proxy/cloud 软信号")
    }

    func testDtoFromReport_JailbrokenMapsCorrectly() {
        let context = TestFixtures.makeRiskContext(
            isJailbroken: true,
            jailbreakConfidence: 0.9,
            vpnActive: true
        )
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)

        let dto = RiskReportMapper.dto(from: cprReport)

        XCTAssertTrue(dto.jailbreak.isJailbroken)
        XCTAssertEqual(dto.jailbreak.confidence, 0.9)
        let jailbreakHard = dto.hardSignals.first { $0.id == "jailbreak" }
        XCTAssertNotNil(jailbreakHard)
        XCTAssertTrue(jailbreakHard?.detected ?? false)
    }

    // MARK: - dto(from: jsonData)

    func testDtoFromJSONData_MinimalValidPayload() {
        let json = """
        {
          "generatedAt": "2024-01-15T10:00:00.000Z",
          "deviceID": "test-device-123",
          "score": 25.0,
          "isHighRisk": false,
          "summary": "low_risk",
          "network": {
            "interfaceType": {"value": "wifi", "method": "NWPathMonitor"},
            "isExpensive": false,
            "isConstrained": false,
            "vpn": {"detected": false, "method": "ifaddrs", "confidence": "weak"},
            "proxy": {"detected": false, "method": "CFNetwork", "confidence": "weak"}
          },
          "behavior": {
            "touch": {"sampleCount": 0, "tapCount": 0, "swipeCount": 0},
            "motion": {"sampleCount": 0},
            "touchMotionCorrelation": null,
            "actionCount": 0
          },
          "jailbreak": {
            "isJailbroken": false,
            "confidence": 0,
            "detectedMethods": [],
            "details": ""
          },
          "signals": []
        }
        """
        guard let data = json.data(using: .utf8) else {
            XCTFail("JSON data encoding failed")
            return
        }

        let dto = RiskReportMapper.dto(from: data)

        XCTAssertNotNil(dto)
        XCTAssertEqual(dto?.deviceID, "test-device-123")
        XCTAssertEqual(dto?.score, 25.0)
        XCTAssertEqual(dto?.isHighRisk, false)
        XCTAssertEqual(dto?.summary, "low_risk")
        XCTAssertEqual(dto?.jailbreak.isJailbroken, false)
        XCTAssertEqual(dto?.signals.count, 0)
    }

    func testDtoFromJSONData_EmptyDataReturnsNil() {
        let data = Data()
        let dto = RiskReportMapper.dto(from: data)
        XCTAssertNil(dto)
    }

    func testDtoFromJSONData_InvalidJSONReturnsNil() {
        let data = Data("not valid json {{{".utf8)
        let dto = RiskReportMapper.dto(from: data)
        XCTAssertNil(dto)
    }

    func testDtoFromJSONData_MissingRequiredFieldsReturnsNil() {
        let json = """
        {"deviceID": "x"}
        """
        let data = Data(json.utf8)
        let dto = RiskReportMapper.dto(from: data)
        XCTAssertNil(dto)
    }

    func testDtoFromJSONData_WithServerSignals() {
        let json = """
        {
          "generatedAt": "2024-01-15T10:00:00.000Z",
          "deviceID": "test-device",
          "score": 60,
          "isHighRisk": true,
          "summary": "high_risk",
          "network": {
            "interfaceType": {"value": "wifi", "method": "NWPathMonitor"},
            "isExpensive": false,
            "isConstrained": false,
            "vpn": {"detected": false, "method": "ifaddrs", "confidence": "weak"},
            "proxy": {"detected": false, "method": "CFNetwork", "confidence": "weak"}
          },
          "behavior": {
            "touch": {"sampleCount": 0, "tapCount": 0, "swipeCount": 0},
            "motion": {"sampleCount": 0},
            "touchMotionCorrelation": null,
            "actionCount": 0
          },
          "jailbreak": {
            "isJailbroken": false,
            "confidence": 0,
            "detectedMethods": [],
            "details": ""
          },
          "signals": [],
          "server": {
            "isDatacenter": true,
            "publicIP": "1.2.3.4",
            "ipDeviceAgg": 100,
            "ipAccountAgg": 50,
            "riskTags": ["cloud_phone"]
          }
        }
        """
        guard let data = json.data(using: .utf8) else {
            XCTFail("JSON data encoding failed")
            return
        }

        let dto = RiskReportMapper.dto(from: data)

        XCTAssertNotNil(dto)
        XCTAssertEqual(dto?.server?.isDatacenter, true)
        XCTAssertEqual(dto?.server?.publicIP, "1.2.3.4")
        XCTAssertEqual(dto?.server?.ipDeviceAgg, 100)
        XCTAssertEqual(dto?.server?.ipAccountAgg, 50)
        XCTAssertEqual(dto?.server?.riskTags, ["cloud_phone"])

        let cloudDatacenter = dto?.softSignals.first { $0.id == "cloud_datacenter" }
        XCTAssertNotNil(cloudDatacenter)
        XCTAssertTrue(cloudDatacenter?.detected ?? false)
    }

    func testDtoFromReport_RoundtripViaJSON() {
        let context = TestFixtures.makeRiskContext()
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)

        let jsonData = cprReport.jsonData(prettyPrinted: false)
        let dtoFromJSON = RiskReportMapper.dto(from: jsonData)
        let dtoFromReport = RiskReportMapper.dto(from: cprReport)

        XCTAssertNotNil(dtoFromJSON)
        XCTAssertEqual(dtoFromReport.deviceID, dtoFromJSON?.deviceID)
        XCTAssertEqual(dtoFromReport.score, dtoFromJSON?.score)
        XCTAssertEqual(dtoFromReport.isHighRisk, dtoFromJSON?.isHighRisk)
    }
}
