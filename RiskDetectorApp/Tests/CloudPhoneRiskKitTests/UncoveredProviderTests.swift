import XCTest
@testable import CloudPhoneRiskKit

/// 未在 SDK52ProviderTests 中覆盖的 Provider 单元测试
///
/// 覆盖：DeviceHardwareProvider、DeviceAgeProvider、ExternalServerAggregateProvider、
/// MountPointProvider、LayeredConsistencyProvider、DRMCapabilityProvider
///
/// 风格与 SDK52ProviderTests 一致：ID、模拟器行为、信号结构、已知 ID 集合
final class UncoveredProviderTests: XCTestCase {

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
            hardwareMachine: "iPhone15,3",
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

    private var simulatorSnapshot: RiskSnapshot {
        let device = DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: "TEST-UUID-SIM",
            localeIdentifier: "zh_CN",
            timeZoneIdentifier: "Asia/Shanghai",
            timeZoneOffsetSeconds: 28800,
            screenWidth: 1179,
            screenHeight: 2556,
            screenScale: 3.0,
            hardwareMachine: "arm64",
            hardwareModel: "Virtual",
            isSimulator: true
        )
        return RiskSnapshot(
            deviceID: "test-simulator",
            device: device,
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }

    // MARK: - DeviceHardwareProvider

    func testDeviceHardwareProviderID() {
        XCTAssertEqual(DeviceHardwareProvider.shared.id, "device_hardware")
    }

    func testDeviceHardwareProviderSimulatorReturnsSimulatorSignal() {
        let signals = DeviceHardwareProvider.shared.signals(snapshot: simulatorSnapshot)
        let simulatorSignal = signals.first { $0.id == "simulator" }
        let policySimulatorSignal = signals.first { $0.id == SignalID.isSimulator }
        XCTAssertNotNil(simulatorSignal, "模拟器环境下应包含 simulator 信号")
        XCTAssertNotNil(policySimulatorSignal, "模拟器环境下应包含 is_simulator 策略桥接信号")
        XCTAssertEqual(simulatorSignal?.category, "device")
    }

    func testDeviceHardwareProviderRealDeviceReturnsHwMachine() {
        let signals = DeviceHardwareProvider.shared.signals(snapshot: dummySnapshot)
        let hwMachine = signals.first { $0.id == "hw_machine" }
        XCTAssertNotNil(hwMachine)
        XCTAssertEqual(hwMachine?.evidence["machine"], "iPhone15,3")
    }

    func testDeviceHardwareProviderInvalidKernelBuildReturnsAnomalySignal() {
        let snapshot = RiskSnapshot(
            deviceID: "test-kernel-build",
            device: TestFixtures.makeDeviceFingerprint(kernelBuild: "RELEASE_ARM64_T8101"),
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )

        let signals = DeviceHardwareProvider.shared.signals(snapshot: snapshot)
        let anomaly = signals.first { $0.id == SignalID.kernelBuildAnomaly }

        XCTAssertNotNil(anomaly)
        XCTAssertEqual(anomaly?.evidence["reason"], "kernel_build_format_invalid")
    }

    // MARK: - DeviceAgeProvider

    func testDeviceAgeProviderID() {
        XCTAssertEqual(DeviceAgeProvider.shared.id, "device_age")
    }

    func testDeviceAgeProviderOldModelReturnsSignal() {
        let device = DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: "TEST",
            localeIdentifier: "zh_CN",
            timeZoneIdentifier: "Asia/Shanghai",
            timeZoneOffsetSeconds: 28800,
            screenWidth: 1179,
            screenHeight: 2556,
            screenScale: 3.0,
            hardwareMachine: "iPhone10,6",
            hardwareModel: "D22AP",
            isSimulator: false
        )
        let snapshot = RiskSnapshot(
            deviceID: "test-old",
            device: device,
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
        let signals = DeviceAgeProvider.shared.signals(snapshot: snapshot)
        XCTAssertFalse(signals.isEmpty)
        XCTAssertEqual(signals.first?.id, "old_device_model")
        XCTAssertEqual(signals.first?.evidence["family"], "10")
    }

    func testDeviceAgeProviderNewModelReturnsEmpty() {
        let signals = DeviceAgeProvider.shared.signals(snapshot: dummySnapshot)
        let oldModel = signals.first { $0.id == "old_device_model" }
        XCTAssertNil(oldModel)
    }

    // MARK: - ExternalServerAggregateProvider

    func testExternalServerAggregateProviderID() {
        XCTAssertEqual(ExternalServerAggregateProvider.shared.id, "server_aggregate")
    }

    func testExternalServerAggregateProviderEmptyReturnsEmpty() {
        ExternalServerAggregateProvider.shared.set(nil)
        ExternalServerAggregateProvider.shared.clearGraphFeatures()
        let signals = ExternalServerAggregateProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertTrue(signals.isEmpty)
    }

    func testExternalServerAggregateProviderWithServerSignals() {
        let serverSignals = ServerSignals(
            publicIP: "1.2.3.4",
            isDatacenter: true,
            ipDeviceAgg: 100,
            ipAccountAgg: 50,
            riskTags: ["cloud_phone"]
        )
        ExternalServerAggregateProvider.shared.set(serverSignals)
        defer { ExternalServerAggregateProvider.shared.set(nil) }

        let signals = ExternalServerAggregateProvider.shared.signals(snapshot: dummySnapshot)
        XCTAssertFalse(signals.isEmpty)
        let datacenter = signals.first { $0.id == SignalID.datacenterIP }
        XCTAssertNotNil(datacenter)
        XCTAssertEqual(datacenter?.score, 20)
    }

    // MARK: - MountPointProvider

    func testMountPointProviderID() {
        XCTAssertEqual(MountPointProvider.shared.id, "mount_point")
    }

    func testMountPointProviderSimulatorReturnsMountUnavailable() {
        #if targetEnvironment(simulator)
        let signals = MountPointProvider.shared.signals(snapshot: simulatorSnapshot)
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals.first?.id, "mount_unavailable")
        XCTAssertEqual(signals.first?.evidence["detail"], "simulator")
        #endif
    }

    func testMountPointProviderSignalStructure() {
        let signals = MountPointProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = [
            "mount_unavailable",
            "mount_virtual_fs",
            "mount_missing_required",
            "mount_count_anomaly",
        ]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 MountPointProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.category, "device")
        }
    }

    // MARK: - LayeredConsistencyProvider

    func testLayeredConsistencyProviderID() {
        XCTAssertEqual(LayeredConsistencyProvider.shared.id, "layered_consistency")
    }

    func testLayeredConsistencyProviderSignalStructure() {
        let signals = LayeredConsistencyProvider.shared.signals(snapshot: dummySnapshot)
        for signal in signals {
            XCTAssertFalse(signal.id.isEmpty)
            if let layer = signal.layer {
                XCTAssertGreaterThanOrEqual(layer, 1, "layer 应为正数")
                XCTAssertLessThanOrEqual(layer, 4)
            }
            XCTAssertGreaterThanOrEqual(signal.score, 0)
        }
    }

    // MARK: - DRMCapabilityProvider

    func testDRMCapabilityProviderID() {
        XCTAssertEqual(DRMCapabilityProvider.shared.id, "drm_capability")
    }

    func testDRMCapabilityProviderSignalStructure() {
        let signals = DRMCapabilityProvider.shared.signals(snapshot: dummySnapshot)
        let knownIDs: Set<String> = [
            "drm_capability",
            "drm_device_mismatch",
        ]
        for signal in signals {
            XCTAssertTrue(knownIDs.contains(signal.id),
                "未预期的 DRMCapabilityProvider 信号 ID: \(signal.id)")
            XCTAssertEqual(signal.category, "device")
        }
    }

    // MARK: - 共同不变量

    func testAllUncoveredProvidersHaveNonEmptyID() {
        let providers: [RiskSignalProvider] = [
            DeviceHardwareProvider.shared,
            DeviceAgeProvider.shared,
            ExternalServerAggregateProvider.shared,
            MountPointProvider.shared,
            LayeredConsistencyProvider.shared,
            DRMCapabilityProvider.shared,
        ]
        for provider in providers {
            XCTAssertFalse(provider.id.isEmpty, "\(type(of: provider)).id 不得为空")
        }
    }
}
