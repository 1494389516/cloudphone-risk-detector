import XCTest
@testable import CloudPhoneRiskKit

final class ExternalServerSignalsTests: XCTestCase {
    func test_externalServerSignalsEmbeddedInJSONAndSignals() throws {
        CPRiskKit.setExternalServerSignals(
            publicIP: "1.2.3.4",
            asn: "AS4134",
            asOrg: "CHINANET",
            isDatacenter: 1,
            ipDeviceAgg: 120,
            ipAccountAgg: 500,
            geoCountry: "CN",
            geoRegion: "GD",
            riskTags: ["dc_ip", "ip_shared"]
        )
        defer { CPRiskKit.clearExternalServerSignals() }

        let report = CPRiskKit.shared.evaluate()

        XCTAssertTrue(report.signals.contains(where: { $0.id == "datacenter_ip" }))

        let obj = try JSONSerialization.jsonObject(with: report.jsonData(), options: []) as? [String: Any]
        let server = obj?["server"] as? [String: Any]
        XCTAssertEqual(server?["publicIP"] as? String, "1.2.3.4")
        XCTAssertEqual(server?["asn"] as? String, "AS4134")
        XCTAssertEqual(server?["geoCountry"] as? String, "CN")
    }
}

