import XCTest
@testable import CloudPhoneRiskKit

final class AppStoreSafeRuntimeTests: XCTestCase {

    func testEffectiveAntiDebugRuntimeModeLocalAppStoreAlwaysWins() {
        XCTAssertEqual(
            CPRiskKit.effectiveAntiDebugRuntimeMode(localMode: .appStoreSafe, remoteRequestsAppStoreSafeProfile: false),
            .appStoreSafe
        )
        XCTAssertEqual(
            CPRiskKit.effectiveAntiDebugRuntimeMode(localMode: .appStoreSafe, remoteRequestsAppStoreSafeProfile: true),
            .appStoreSafe
        )
    }

    func testEffectiveAntiDebugRuntimeModeRemoteMapsToAppStoreSafe() {
        XCTAssertEqual(
            CPRiskKit.effectiveAntiDebugRuntimeMode(localMode: .production, remoteRequestsAppStoreSafeProfile: true),
            .appStoreSafe
        )
        XCTAssertEqual(
            CPRiskKit.effectiveAntiDebugRuntimeMode(localMode: .relaxedDevelopmentQA, remoteRequestsAppStoreSafeProfile: true),
            .appStoreSafe
        )
    }

    func testEffectiveAntiDebugRuntimeModeRemoteIgnoredWhenFalse() {
        XCTAssertEqual(
            CPRiskKit.effectiveAntiDebugRuntimeMode(localMode: .production, remoteRequestsAppStoreSafeProfile: false),
            .production
        )
    }

    func testSecurityHardeningAppStoreSafeProfileJSONRoundtrip() {
        let sh = SecurityHardeningConfig(
            enableEnvelopeSignatureV2: true,
            enforcePayloadFieldMapping: false,
            enableChallengeBinding: true,
            killSwitchEnabled: false,
            enableAppStoreSafeProfile: true
        )
        let cfg = RemoteConfig(
            version: 99,
            timestamp: 1,
            environment: .production,
            description: nil,
            policy: .default,
            detector: .default,
            whitelist: .default,
            experiments: .default,
            advanced: nil,
            probeConfig: nil,
            payloadFieldMapping: nil,
            securityHardening: sh,
            textSegmentHashReference: nil
        )
        guard let json = cfg.toJSONString() else {
            XCTFail("encode")
            return
        }
        guard let decoded = RemoteConfig.from(jsonString: json) else {
            XCTFail("decode")
            return
        }
        XCTAssertEqual(decoded.securityHardening?.enableAppStoreSafeProfile, true)
    }
}
