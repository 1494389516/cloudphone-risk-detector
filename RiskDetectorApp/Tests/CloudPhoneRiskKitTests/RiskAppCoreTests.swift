import XCTest
@testable import CloudPhoneRiskAppCore

final class RiskAppCoreTests: XCTestCase {
    func test_configStoreRoundTrip() throws {
        let defaults = UserDefaults(suiteName: "RiskAppCoreTests.\(UUID().uuidString)")!
        let store = RiskAppConfigStore(defaults: defaults)

        var cfg = RiskAppConfig.default
        cfg.threshold = 77
        cfg.jailbreakEnableHookDetect = false
        cfg.storeMaxFiles = 12

        try store.save(cfg)
        let loaded = store.load()

        XCTAssertEqual(loaded.threshold, 77)
        XCTAssertEqual(loaded.jailbreakEnableHookDetect, false)
        XCTAssertEqual(loaded.storeMaxFiles, 12)
    }
}

