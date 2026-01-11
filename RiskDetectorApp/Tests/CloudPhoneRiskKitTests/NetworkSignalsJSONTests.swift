import XCTest
@testable import CloudPhoneRiskKit

final class NetworkSignalsJSONTests: XCTestCase {
    func test_networkSignalsAreStructured() throws {
        let report = CPRiskKit.shared.evaluate()
        let obj = try JSONSerialization.jsonObject(with: report.jsonData(), options: []) as? [String: Any]
        let network = obj?["network"] as? [String: Any]

        let vpn = network?["vpn"] as? [String: Any]
        XCTAssertNotNil(vpn?["detected"])
        XCTAssertEqual(vpn?["method"] as? String, "ifaddrs_prefix")
        XCTAssertEqual(vpn?["confidence"] as? String, "weak")

        let proxy = network?["proxy"] as? [String: Any]
        XCTAssertNotNil(proxy?["detected"])
        XCTAssertEqual(proxy?["method"] as? String, "CFNetworkCopySystemProxySettings")
        XCTAssertEqual(proxy?["confidence"] as? String, "weak")

        let iface = network?["interfaceType"] as? [String: Any]
        XCTAssertNotNil(iface?["value"])
        XCTAssertEqual(iface?["method"] as? String, "NWPathMonitor")
    }
}

