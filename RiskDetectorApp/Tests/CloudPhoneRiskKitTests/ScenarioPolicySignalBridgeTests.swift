import XCTest
@testable import CloudPhoneRiskKit

final class ScenarioPolicySignalBridgeTests: XCTestCase {

    func testDeviceTamperScoreBridgeDerivesFromAntiTamperDrivers() {
        let derived = ScenarioPolicySignalBridge.deviceTamperSignal(
            from: [
                RiskSignal(
                    id: SignalID.antiDebugRuntimeConsensus,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 41,
                    evidence: ["driver": "watchdog"],
                    state: .tampered,
                    layer: 3,
                    weightHint: 60
                ),
                RiskSignal(
                    id: SignalID.signingChainConsensus,
                    category: "integrity",
                    score: 32,
                    evidence: ["driver": "signing"],
                    state: .soft(confidence: 0.82),
                    layer: 3,
                    weightHint: 54
                ),
            ]
        )

        XCTAssertEqual(derived?.id, SignalID.deviceTamperScore)
        XCTAssertNotNil(derived?.evidence["drivers"])
        if case .soft = derived?.state {
            XCTFail("expected tampered state when multiple anti-tamper drivers are present")
        }
        XCTAssertEqual(derived?.state, .tampered)
    }

    func testIDFVReinstallBridgeTriggersAfterRepeatedChanges() throws {
        let suiteName = "ScenarioPolicySignalBridgeTests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            throw XCTSkip("unable to create isolated defaults suite")
        }
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let baseSnapshot = makeSnapshot(idfv: "IDFV-A")
        XCTAssertNil(
            ScenarioPolicySignalBridge.idfvReinstallSignal(
                snapshot: baseSnapshot,
                defaults: defaults,
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
        )

        XCTAssertNil(
            ScenarioPolicySignalBridge.idfvReinstallSignal(
                snapshot: makeSnapshot(idfv: "IDFV-B"),
                defaults: defaults,
                now: Date(timeIntervalSince1970: 1_700_000_100)
            )
        )

        let signal = ScenarioPolicySignalBridge.idfvReinstallSignal(
            snapshot: makeSnapshot(idfv: "IDFV-C"),
            defaults: defaults,
            now: Date(timeIntervalSince1970: 1_700_000_200)
        )

        XCTAssertEqual(signal?.id, SignalID.idfvReinstallCount)
        XCTAssertEqual(signal?.evidence["reinstall_count_30d"], "2")
    }

    func testMCCMismatchBridgeMatchesLocaleRegionExpectation() {
        let snapshot = makeSnapshot(localeIdentifier: "zh_CN", mcc: "310")

        let signal = ScenarioPolicySignalBridge.mccMismatchSignal(snapshot: snapshot)

        XCTAssertEqual(signal?.id, SignalID.mccMismatch)
        XCTAssertEqual(signal?.evidence["region"], "CN")
        XCTAssertEqual(signal?.evidence["mcc"], "310")
    }

    func testDebugAndFridaPortBridgeAggregateToScenarioIDs() {
        let debugged = ScenarioPolicySignalBridge.debuggedSignal(
            from: [
                RiskSignal(
                    id: SignalID.debuggerDetected,
                    category: "debugger",
                    score: 20,
                    evidence: ["detector": "ptrace"],
                    state: .tampered,
                    layer: 2,
                    weightHint: 40
                ),
            ]
        )
        let fridaPort = ScenarioPolicySignalBridge.fridaPortSignal(
            from: [
                RiskSignal(
                    id: "frida_port_27042",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 30,
                    evidence: ["listening_port": "27042"],
                    state: .hard(detected: true),
                    layer: 2,
                    weightHint: 48
                ),
            ]
        )

        XCTAssertEqual(debugged?.id, SignalID.isDebugged)
        XCTAssertEqual(fridaPort?.id, SignalID.fridaPortOpen)
        XCTAssertEqual(fridaPort?.evidence["ports"], "27042")
    }

    func testDNSTunnelBridgeAggregatesAnomalousProtoSignals() {
        let signal = ScenarioPolicySignalBridge.dnsTunnelSignal(
            from: [
                RiskSignal(
                    id: "frida_anom_proto_53_dbus_wire",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 34,
                    evidence: ["detection_method": "frida:anom_proto:53:dbus_wire"],
                    state: .soft(confidence: 0.78),
                    layer: 2,
                    weightHint: 46
                ),
                RiskSignal(
                    id: "suspicious_local_listen_5353",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 4,
                    evidence: ["listening_port": "5353"],
                    state: .soft(confidence: 0.35),
                    layer: 1,
                    weightHint: 12
                ),
            ]
        )

        XCTAssertEqual(signal?.id, SignalID.dnsTunnelDetected)
        XCTAssertEqual(signal?.category, "network")
        XCTAssertEqual(signal?.evidence["driver_count"], "2")
        XCTAssertEqual(signal?.evidence["ports"], "53,5353")
    }

    func testDeriveSignalsCanSatisfyCR002Inputs() throws {
        let suiteName = "ScenarioPolicySignalBridgeTests.Combo.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            throw XCTSkip("unable to create isolated defaults suite")
        }
        defer { defaults.removePersistentDomain(forName: suiteName) }

        _ = ScenarioPolicySignalBridge.idfvReinstallSignal(
            snapshot: makeSnapshot(idfv: "IDFV-A", localeIdentifier: "zh_CN", mcc: "310"),
            defaults: defaults,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )
        _ = ScenarioPolicySignalBridge.idfvReinstallSignal(
            snapshot: makeSnapshot(idfv: "IDFV-B", localeIdentifier: "zh_CN", mcc: "310"),
            defaults: defaults,
            now: Date(timeIntervalSince1970: 1_700_000_100)
        )

        let derived = ScenarioPolicySignalBridge.deriveSignals(
            snapshot: makeSnapshot(idfv: "IDFV-C", localeIdentifier: "zh_CN", mcc: "310"),
            existingSignals: [
                RiskSignal(
                    id: SignalID.antiDebugRuntimeConsensus,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 41,
                    evidence: ["driver": "watchdog"],
                    state: .tampered,
                    layer: 3,
                    weightHint: 60
                ),
                RiskSignal(
                    id: SignalID.signingChainConsensus,
                    category: "integrity",
                    score: 32,
                    evidence: ["driver": "signing"],
                    state: .tampered,
                    layer: 3,
                    weightHint: 54
                ),
            ],
            defaults: defaults,
            now: Date(timeIntervalSince1970: 1_700_000_200)
        )

        let comboRule = ScenarioPolicy.general.comboRules.first { $0.name == "CR-002_device_tamper_idfv_mcc" }
        XCTAssertNotNil(comboRule)
        XCTAssertTrue(comboRule?.matches(signals: derived) == true)
    }

    private func makeSnapshot(
        idfv: String = "TEST-UUID-1234",
        localeIdentifier: String = "zh_CN",
        mcc: String? = nil
    ) -> RiskSnapshot {
        var device = TestFixtures.makeDeviceFingerprint()
        device.identifierForVendor = idfv
        device.localeIdentifier = localeIdentifier

        let network = TestFixtures.makeNetworkSignals(mcc: mcc)
        return RiskSnapshot(
            deviceID: "device-1",
            device: device,
            network: network,
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }
}
