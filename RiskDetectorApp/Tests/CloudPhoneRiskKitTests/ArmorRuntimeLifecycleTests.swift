import Foundation
import XCTest
@testable import CloudPhoneRiskKit

final class ArmorRuntimeLifecycleTests: XCTestCase {
    private let armorRootKeyDefaultsKey = "com.cloudphone.riskkit.armor.root_key_hex"

    override func setUp() {
        super.setUp()
        UserDefaults.standard.removeObject(forKey: armorRootKeyDefaultsKey)
        CPRiskKit.shared.stop()
    }

    override func tearDown() {
        CPRiskKit.shared.stop()
        UserDefaults.standard.removeObject(forKey: armorRootKeyDefaultsKey)
        super.tearDown()
    }

    func testEvaluateOnlyPathBootstrapsArmorRuntimeAndEmitsObservableSignal() {
        let report = CPRiskKit.shared.evaluate()
        let snapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        XCTAssertEqual(snapshot.trigger, "evaluate")
        XCTAssertEqual(snapshot.attemptCount, 1)
        XCTAssertNotEqual(snapshot.status, "inactive")
        XCTAssertTrue(
            report.signals.contains { signal in
                signal.id == "armor_runtime_unavailable" || signal.id == "armor_runtime_init_failed"
            },
            "evaluate-only path should surface armor runtime degradation instead of silent success"
        )

        if ProcessInfo.processInfo.environment["CPRISKKIT_ARMOR_ROOT_KEY_HEX"] == nil {
            XCTAssertTrue(snapshot.debugFallbackUsed, "debug builds should fall back to the test root key")
        }
    }

    func testStartIsIdempotentUntilStopResetsArmorRuntimeState() {
        CPRiskKit.shared.start()
        let firstSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        CPRiskKit.shared.start()
        let secondSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        XCTAssertEqual(firstSnapshot.trigger, "start")
        XCTAssertEqual(firstSnapshot.attemptCount, 1)
        XCTAssertEqual(secondSnapshot.attemptCount, 1, "repeated start() must not initialize armor twice")
        XCTAssertNotEqual(secondSnapshot.status, "inactive")

        CPRiskKit.shared.stop()
        let stoppedSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        XCTAssertEqual(stoppedSnapshot.status, "inactive")
        XCTAssertEqual(stoppedSnapshot.attemptCount, 0)
    }
}
