import XCTest
@testable import CloudPhoneRiskKit

final class WhitelistRulesTests: XCTestCase {
    func testContainsIPWithExactMatch() {
        let rules = WhitelistRules(ipWhitelist: ["10.0.0.7"])
        XCTAssertTrue(rules.contains(ip: "10.0.0.7"))
        XCTAssertFalse(rules.contains(ip: "10.0.0.8"))
    }

    func testContainsIPWithIPv4CIDRMatch() {
        let rules = WhitelistRules(ipWhitelist: ["192.168.10.0/24"])
        XCTAssertTrue(rules.contains(ip: "192.168.10.42"))
        XCTAssertFalse(rules.contains(ip: "192.168.11.42"))
    }

    func testContainsIPWithIPv6CIDRMatch() {
        let rules = WhitelistRules(ipWhitelist: ["2001:db8::/32"])
        XCTAssertTrue(rules.contains(ip: "2001:db8::1"))
        XCTAssertFalse(rules.contains(ip: "2001:db9::1"))
    }

    func testContainsIPWithInvalidCIDRDoesNotCrashOrMatch() {
        let rules = WhitelistRules(ipWhitelist: ["not-a-cidr", "10.0.0.0/99"])
        XCTAssertFalse(rules.contains(ip: "10.0.0.7"))
    }
}
