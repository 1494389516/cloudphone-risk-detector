import XCTest
@testable import CloudPhoneRiskKit

final class WhitelistRulesTests: XCTestCase {

    // MARK: - IP Whitelist: Exact Match

    func testContainsIPWithExactMatch() {
        let rules = WhitelistRules(ipWhitelist: ["10.0.0.7"])
        XCTAssertTrue(rules.contains(ip: "10.0.0.7"))
        XCTAssertFalse(rules.contains(ip: "10.0.0.8"))
    }

    func testContainsIPWithMultipleExactEntries() {
        let rules = WhitelistRules(ipWhitelist: ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        XCTAssertTrue(rules.contains(ip: "10.0.0.1"))
        XCTAssertTrue(rules.contains(ip: "10.0.0.3"))
        XCTAssertFalse(rules.contains(ip: "10.0.0.4"))
    }

    func testContainsIPTrimsWhitespace() {
        let rules = WhitelistRules(ipWhitelist: ["10.0.0.7"])
        XCTAssertTrue(rules.contains(ip: " 10.0.0.7 "))
    }

    func testContainsIPEmptyStringReturnsFalse() {
        let rules = WhitelistRules(ipWhitelist: ["10.0.0.7"])
        XCTAssertFalse(rules.contains(ip: ""))
        XCTAssertFalse(rules.contains(ip: "   "))
    }

    // MARK: - IP Whitelist: IPv4 CIDR

    func testContainsIPWithIPv4CIDRMatch() {
        let rules = WhitelistRules(ipWhitelist: ["192.168.10.0/24"])
        XCTAssertTrue(rules.contains(ip: "192.168.10.42"))
        XCTAssertFalse(rules.contains(ip: "192.168.11.42"))
    }

    func testContainsIPWithIPv4CIDR16() {
        let rules = WhitelistRules(ipWhitelist: ["172.16.0.0/16"])
        XCTAssertTrue(rules.contains(ip: "172.16.0.1"))
        XCTAssertTrue(rules.contains(ip: "172.16.255.254"))
        XCTAssertFalse(rules.contains(ip: "172.17.0.1"))
    }

    func testContainsIPWithIPv4CIDR32() {
        let rules = WhitelistRules(ipWhitelist: ["10.0.0.1/32"])
        XCTAssertTrue(rules.contains(ip: "10.0.0.1"))
        XCTAssertFalse(rules.contains(ip: "10.0.0.2"))
    }

    // MARK: - IP Whitelist: IPv6

    func testContainsIPWithIPv6CIDRMatch() {
        let rules = WhitelistRules(ipWhitelist: ["2001:db8::/32"])
        XCTAssertTrue(rules.contains(ip: "2001:db8::1"))
        XCTAssertFalse(rules.contains(ip: "2001:db9::1"))
    }

    func testContainsIPWithIPv6ExactMatch() {
        let rules = WhitelistRules(ipWhitelist: ["::1"])
        XCTAssertTrue(rules.contains(ip: "::1"))
    }

    // MARK: - IP Whitelist: Invalid

    func testContainsIPWithInvalidCIDRDoesNotCrashOrMatch() {
        let rules = WhitelistRules(ipWhitelist: ["not-a-cidr", "10.0.0.0/99"])
        XCTAssertFalse(rules.contains(ip: "10.0.0.7"))
    }

    func testContainsIPEmptyWhitelist() {
        let rules = WhitelistRules(ipWhitelist: [])
        XCTAssertFalse(rules.contains(ip: "1.2.3.4"))
    }

    // MARK: - Device ID Whitelist

    func testContainsDeviceIDExactMatch() {
        let rules = WhitelistRules(deviceIDs: ["device_A", "device_B"])
        XCTAssertTrue(rules.contains(deviceID: "device_A"))
        XCTAssertTrue(rules.contains(deviceID: "device_B"))
        XCTAssertFalse(rules.contains(deviceID: "device_C"))
    }

    func testContainsDeviceIDPrefixMatch() {
        let rules = WhitelistRules(deviceIDPrefixes: ["test-", "dev-"])
        XCTAssertTrue(rules.contains(deviceID: "test-12345"))
        XCTAssertTrue(rules.contains(deviceID: "dev-abc"))
        XCTAssertFalse(rules.contains(deviceID: "prod-12345"))
    }

    func testContainsDeviceIDNoMatchOnEmpty() {
        let rules = WhitelistRules()
        XCTAssertFalse(rules.contains(deviceID: "any-device"))
    }

    func testContainsDeviceIDExactOverPrefix() {
        // Both exact and prefix should work
        let rules = WhitelistRules(deviceIDs: ["exact-id"], deviceIDPrefixes: ["prefix-"])
        XCTAssertTrue(rules.contains(deviceID: "exact-id"))
        XCTAssertTrue(rules.contains(deviceID: "prefix-anything"))
        XCTAssertFalse(rules.contains(deviceID: "other"))
    }

    // MARK: - Blacklist

    func testIsBlacklisted() {
        let rules = WhitelistRules(blacklistedDeviceIDs: ["bad_device_1", "bad_device_2"])
        XCTAssertTrue(rules.isBlacklisted(deviceID: "bad_device_1"))
        XCTAssertTrue(rules.isBlacklisted(deviceID: "bad_device_2"))
        XCTAssertFalse(rules.isBlacklisted(deviceID: "good_device"))
    }

    func testIsBlacklistedEmpty() {
        let rules = WhitelistRules()
        XCTAssertFalse(rules.isBlacklisted(deviceID: "any"))
    }

    // MARK: - Trusted Version

    func testIsTrustedExactVersion() {
        let rules = WhitelistRules(trustedVersions: ["17.0", "17.1", "16.7"])
        XCTAssertTrue(rules.isTrusted(version: "17.0"))
        XCTAssertTrue(rules.isTrusted(version: "16.7"))
        XCTAssertFalse(rules.isTrusted(version: "16.6"))
    }

    func testIsTrustedMinVersion() {
        let rules = WhitelistRules(minTrustedVersion: "16.0")
        XCTAssertTrue(rules.isTrusted(version: "16.0"))
        XCTAssertTrue(rules.isTrusted(version: "17.0"))
        XCTAssertTrue(rules.isTrusted(version: "16.5.1"))
        XCTAssertFalse(rules.isTrusted(version: "15.9"))
    }

    func testIsTrustedSemanticVersionComparison() {
        // Ensure 10.0 > 9.0 (not string comparison)
        let rules = WhitelistRules(minTrustedVersion: "10.0")
        XCTAssertTrue(rules.isTrusted(version: "10.0"))
        XCTAssertTrue(rules.isTrusted(version: "11.0"))
        XCTAssertFalse(rules.isTrusted(version: "9.0"))
        XCTAssertFalse(rules.isTrusted(version: "9.9.9"))
    }

    func testIsTrustedNoVersionConfigured() {
        let rules = WhitelistRules()
        XCTAssertFalse(rules.isTrusted(version: "17.0"))
    }

    func testIsTrustedExactVersionTakesPrecedence() {
        let rules = WhitelistRules(trustedVersions: ["15.0"], minTrustedVersion: "16.0")
        // 15.0 is in trustedVersions even though < minTrustedVersion
        XCTAssertTrue(rules.isTrusted(version: "15.0"))
        // 16.0 passes via minTrustedVersion
        XCTAssertTrue(rules.isTrusted(version: "16.0"))
    }

    // MARK: - Default Configuration

    func testDefaultRulesAllEmpty() {
        let rules = WhitelistRules.default
        XCTAssertTrue(rules.deviceIDs.isEmpty)
        XCTAssertTrue(rules.deviceIDPrefixes.isEmpty)
        XCTAssertTrue(rules.blacklistedDeviceIDs.isEmpty)
        XCTAssertTrue(rules.trustedVersions.isEmpty)
        XCTAssertNil(rules.minTrustedVersion)
        XCTAssertTrue(rules.ipWhitelist.isEmpty)
    }

    // MARK: - Codable

    func testWhitelistRulesCodableRoundTrip() throws {
        let rules = WhitelistRules(
            deviceIDs: ["d1"],
            deviceIDPrefixes: ["prefix-"],
            blacklistedDeviceIDs: ["bad1"],
            trustedVersions: ["17.0"],
            minTrustedVersion: "16.0",
            ipWhitelist: ["10.0.0.0/24"]
        )
        let data = try JSONEncoder().encode(rules)
        let decoded = try JSONDecoder().decode(WhitelistRules.self, from: data)

        XCTAssertEqual(decoded.deviceIDs, ["d1"])
        XCTAssertEqual(decoded.deviceIDPrefixes, ["prefix-"])
        XCTAssertEqual(decoded.blacklistedDeviceIDs, ["bad1"])
        XCTAssertEqual(decoded.trustedVersions, ["17.0"])
        XCTAssertEqual(decoded.minTrustedVersion, "16.0")
        XCTAssertEqual(decoded.ipWhitelist, ["10.0.0.0/24"])
    }

    func testWhitelistRulesUsesShortCodingKeys() throws {
        let rules = WhitelistRules(deviceIDs: ["d1"], ipWhitelist: ["1.2.3.4"])
        let data = try JSONEncoder().encode(rules)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(json["di"], "Should use short key 'di' for deviceIDs")
        XCTAssertNotNil(json["iw"], "Should use short key 'iw' for ipWhitelist")
        XCTAssertNil(json["deviceIDs"], "Should not use full key")
    }
}
