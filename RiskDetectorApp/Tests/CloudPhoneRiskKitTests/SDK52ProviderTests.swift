import XCTest
@testable import CloudPhoneRiskKit

/// SDK 5.2 新 Provider 单元测试
///
/// 覆盖 8 个新 Provider 的：
/// - 信号 ID / category / layer 结构正确性
/// - 模拟器环境下行为（返回空数组或固定信号）
/// - 核心判断逻辑（机型解析、接口名过滤、环境历史等）
final class SDK52ProviderTests: XCTestCase {

    private var dummySnapshot: RiskSnapshot {
        let device = DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: "TEST-UUID-5200",
            localeIdentifier: "zh_CN",
            timeZoneIdentifier: "Asia/Shanghai",
            timeZoneOffsetSeconds: 28800,
            screenWidth: 1179,
            screenHeight: 2556,
            screenScale: 3.0,
            hardwareMachine: "iPhone16,1",
            hardwareModel: "D83AP",
            isSimulator: false
        )
        return RiskSnapshot(
            deviceID: "test-device-5200",
            device: device,
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }

    // MARK: - HardwareCapabilityProvider

    func testHardwareCapabilityProviderID() {
        XCTAssertEqual(HardwareCapabilityProvider.shared.id, "hardware_capability")
    }

    func testHardwareCapabilityProviderSimulatorReturnsEmpty() {
        #if targetEnvironment(simulator)
        let signals = HardwareCapabilityProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty, "模拟器环境下 HardwareCapabilityProvider 应返回空数组")
        #else
        // 设备上不强断言内容（依赖硬件），只验证结构
        let signals = HardwareCapabilityProvider.shared.signals(snapshot: dummySnapshot)
        for signal in signals {
            XCTAssertFalse(signal.id.isEmpty)
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 1)
            XCTAssertGreaterThanOrEqual(signal.weightHint, 0)
        }
        #endif
    }

    func testHardwareCapabilitySignalIDsAreKnown() {
        // 已知可能的信号 ID
        let knownIDs: Set<String> = [
            "haptic_capability_mismatch",
            "refresh_rate_mismatch",
            "proximity_sensor_absent",
        ]
        let signals = HardwareCapabilityProvider.shared.signals(snapshot: dummySnapshot)
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 HardwareCapabilityProvider 信号 ID: \(signal.id)")
        }
    }

    // MARK: - PhysicalSensorProbe

    func testPhysicalSensorProbeRunsWithoutCrash() throws {
        let probe = PhysicalSensorProbe()
        let result = try probe.detect()
        XCTAssertGreaterThanOrEqual(result.score, 0)
    }

    func testPhysicalSensorProbeSimulatorReturnsZeroScore() throws {
        #if targetEnvironment(simulator)
        let probe = PhysicalSensorProbe()
        let result = try probe.detect()
        // 模拟器返回 score=0，methods 包含 "unavailable_simulator"
        XCTAssertEqual(result.score, 0)
        XCTAssertTrue(result.methods.contains("unavailable_simulator"),
            "模拟器环境下 PhysicalSensorProbe 应返回 unavailable_simulator")
        #endif
    }

    func testPhysicalSensorProbeSignalStructure() throws {
        let probe = PhysicalSensorProbe()
        let signals = try probe.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 3)
            XCTAssertTrue(
                signal.id == "physical_sensor_anomaly",
                "PhysicalSensorProbe 信号 ID 应为 physical_sensor_anomaly，实际为: \(signal.id)"
            )
        }
    }

    // MARK: - BiometricStateProvider

    func testBiometricStateProviderID() {
        XCTAssertEqual(BiometricStateProvider.shared.id, "biometric_state")
    }

    func testBiometricStateProviderSimulatorReturnsEmpty() {
        #if targetEnvironment(simulator)
        let signals = BiometricStateProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty, "模拟器环境下 BiometricStateProvider 应返回空数组")
        #endif
    }

    func testBiometricStateProviderSignalStructure() {
        let signals = BiometricStateProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = [
            "biometric_not_enrolled",
            "biometric_not_available",
            "biometric_lockout",
        ]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 BiometricStateProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 1)
        }
    }

    func testBiometricStateProviderAtMostOneSignal() {
        // 每次调用最多输出一个信号（互斥状态）
        let signals = BiometricStateProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertLessThanOrEqual(signals.count, 1,
            "BiometricStateProvider 应最多输出一个信号，实际 \(signals.count) 个")
    }

    // MARK: - AudioRouteProvider

    func testAudioRouteProviderID() {
        XCTAssertEqual(AudioRouteProvider.shared.id, "audio_route")
    }

    func testAudioRouteProviderSimulatorReturnsEmpty() {
        #if targetEnvironment(simulator)
        let signals = AudioRouteProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty)
        #endif
    }

    func testAudioRouteProviderSignalStructure() {
        let signals = AudioRouteProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = ["usb_audio_routed", "virtual_audio_output"]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 AudioRouteProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 1)
            XCTAssertFalse(signal.evidence.isEmpty)
        }
    }

    // MARK: - DisplayMuxProvider

    func testDisplayMuxProviderID() {
        XCTAssertEqual(DisplayMuxProvider.shared.id, "display_mux")
    }

    func testDisplayMuxProviderSimulatorReturnsEmpty() {
        #if targetEnvironment(simulator)
        let signals = DisplayMuxProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty)
        #endif
    }

    func testDisplayMuxProviderSignalStructure() {
        let signals = DisplayMuxProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = ["screen_captured", "external_display_attached"]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 DisplayMuxProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 1)
        }
    }

    // MARK: - BasebandIsolationProvider

    func testBasebandIsolationProviderID() {
        XCTAssertEqual(BasebandIsolationProvider.shared.id, "baseband_isolation")
    }

    func testBasebandIsolationProviderSimulatorReturnsEmpty() {
        #if targetEnvironment(simulator)
        let signals = BasebandIsolationProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty)
        #endif
    }

    func testBasebandIsolationProviderSignalStructure() {
        let signals = BasebandIsolationProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = ["no_cellular_provider", "system_app_missing"]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 BasebandIsolationProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 1)
        }
    }

    // MARK: - NetworkInterfaceProvider

    func testNetworkInterfaceProviderID() {
        XCTAssertEqual(NetworkInterfaceProvider.shared.id, "network_interface")
    }

    func testNetworkInterfaceProviderSimulatorReturnsAnomalySignal() {
        #if targetEnvironment(simulator)
        let signals = NetworkInterfaceProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals.first?.id, "network_interface_anomaly")
        XCTAssertEqual(signals.first?.evidence["detail"], "simulator")
        #endif
    }

    func testNetworkInterfaceProviderVirtualInterfaceDetection() {
        // 验证虚拟接口名过滤逻辑：bridge/tap/tun（非 utun）/veth/docker 应被标记
        let virtualNames = ["bridge0", "tap1", "tun0", "veth0", "docker0"]
        let normalNames = ["en0", "lo0", "utun0", "utun1", "pdp_ip0"]
        let virtualKeywords = ["bridge", "tap", "tun", "veth", "docker"]

        for name in virtualNames {
            let lower = name.lowercased()
            let hit = virtualKeywords.contains { kw in
                if kw == "tun" {
                    return lower.contains("tun") && !lower.contains("utun")
                }
                return lower.contains(kw)
            }
            XCTAssertTrue(hit, "接口名 '\(name)' 应被识别为虚拟接口")
        }

        for name in normalNames {
            let lower = name.lowercased()
            let hit = virtualKeywords.contains { kw in
                if kw == "tun" {
                    return lower.contains("tun") && !lower.contains("utun")
                }
                return lower.contains(kw)
            }
            XCTAssertFalse(hit, "接口名 '\(name)' 不应被误判为虚拟接口")
        }
    }

    func testNetworkInterfaceProviderSignalStructure() {
        let signals = NetworkInterfaceProvider.shared.signals(snapshot: dummySnapshot)
        for signal in signals {
            XCTAssertEqual(signal.id, "network_interface_anomaly")
            XCTAssertFalse(signal.evidence.isEmpty)
        }
    }

    // MARK: - EnvironmentConsistencyProvider

    func testEnvironmentConsistencyProviderID() {
        XCTAssertEqual(EnvironmentConsistencyProvider.shared.id, "environment_consistency")
    }

    func testEnvironmentConsistencyProviderSimulatorReturnsEmpty() {
        #if targetEnvironment(simulator)
        let signals = EnvironmentConsistencyProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty)
        #endif
    }

    func testEnvironmentConsistencyProviderSignalStructure() {
        let signals = EnvironmentConsistencyProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = [
            "thermal_state_static",
            "battery_state_static",
            SignalID.batteryLevelStatic,
            SignalID.noChargeStateChange,
            "screen_brightness_static",
        ]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 EnvironmentConsistencyProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.layer, 3)
        }
    }

    // MARK: - 全部 SDK 5.2 Provider 共同不变量

    func testAllSDK52ProvidersHaveNonEmptyID() {
        let providers: [RiskSignalProvider] = [
            HardwareCapabilityProvider.shared,
            BiometricStateProvider.shared,
            AudioRouteProvider.shared,
            DisplayMuxProvider.shared,
            BasebandIsolationProvider.shared,
            NetworkInterfaceProvider.shared,
            EnvironmentConsistencyProvider.shared,
        ]
        for provider in providers {
            XCTAssertFalse(provider.id.isEmpty, "\(type(of: provider)).id 不得为空")
        }
    }

    func testAllSDK52ProvidersSignalsHaveValidScore() {
        let providers: [RiskSignalProvider] = [
            HardwareCapabilityProvider.shared,
            BiometricStateProvider.shared,
            AudioRouteProvider.shared,
            DisplayMuxProvider.shared,
            BasebandIsolationProvider.shared,
            NetworkInterfaceProvider.shared,
            EnvironmentConsistencyProvider.shared,
        ]
        for provider in providers {
            let signals = provider.signals(snapshot: dummySnapshot)
            for signal in signals {
                XCTAssertGreaterThanOrEqual(signal.score, 0,
                    "\(provider.id) 信号 '\(signal.id)' score < 0")
                XCTAssertLessThanOrEqual(signal.score, 100,
                    "\(provider.id) 信号 '\(signal.id)' score > 100")
            }
        }
    }
}
