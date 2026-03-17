import CryptoKit
import CRiskCore
import Foundation
import XCTest
@testable import CloudPhoneRiskKit

/// 壳与 SDK 的集成测试：验证 armor runtime material、v2a 签名版本、
/// 以及壳初始化失败或 decoy 回退时的风险信号注入行为。
final class ArmorIntegrationTests: XCTestCase {

    // MARK: - Setup / Teardown

    override func setUp() {
        super.setUp()
        CPRiskKit.shared.stop()
    }

    override func tearDown() {
        CPRiskKit.shared.stop()
        super.tearDown()
    }

    // MARK: - Test 1: Runtime Material Always Returns Bytes

    /// 验证 `cprisk_get_runtime_material()` 返回值的行为。
    /// 在测试环境中壳未加固时通常走 decoy 路径；但返回值与成功路径一致（rc == 0），
    /// 防止攻击者通过返回值区分。函数必须可调用且写入 32 字节。
    func testArmorRuntimeMaterialReturnsValidBuffer() {
        var material = [UInt8](repeating: 0, count: 32)
        let rc = cprisk_get_runtime_material(&material)

        let materialData = Data(material)
        XCTAssertEqual(materialData.count, 32, "material must always be 32 bytes")
        XCTAssertFalse(materialData.allSatisfy({ $0 == 0 }),
                       "material must not be all zeros (even decoy material is non-zero)")
        // Decoy path returns 0 (same as success) to prevent oracle attacks
        XCTAssertEqual(rc, 0, "cprisk_get_runtime_material must return 0 on both success and decoy paths")
    }

    /// 验证初始化后 runtime material 的可获取性。
    /// 在测试环境中壳未加固，init 会失败，但不应崩溃。
    func testArmorInitProtectionDoesNotCrash() {
        let rootKey = Data(repeating: 0x42, count: 32)
        let rc = rootKey.withUnsafeBytes { rawBuffer -> Int32 in
            guard let ptr = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return Int32(cprisk_init_protection(ptr, rootKey.count))
        }

        // In test environment, armor may be absent or incomplete; init must fail gracefully.
        // Valid codes: 0 (success) or reserved failure range -2..-7.
        XCTAssertTrue(
            rc == 0 || (rc >= -7 && rc <= -2),
            "cprisk_init_protection must return valid code (0 or -2..-7), got \(rc)"
        )

        if rc != 0 {
            var material = [UInt8](repeating: 0, count: 32)
            let materialRc = cprisk_get_runtime_material(&material)
            XCTAssertEqual(materialRc, 0,
                           "get_runtime_material returns 0 on decoy path (constant-time, no oracle)")
        }

        cprisk_cleanup_protection()
    }

    // MARK: - Test 2: v2a Signature Version Emitted

    /// 验证 `buildSecureReportEnvelope()` 在 DEBUG 模式下的签名版本逻辑。
    /// Release 默认 "v2a"；DEBUG 下受 `enableEnvelopeSignatureV2` 控制。
    func testV2aSignatureVersionEmitted() throws {
        CPRiskKit.shared.start()
        let snapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        guard snapshot.status == "active" else {
            throw XCTSkip("当前测试二进制未提供可用 armor runtime，跳过 v2a active-path 断言（需 Release 加固构建或设置 CPRISKKIT_ARMOR_ROOT_KEY_HEX）")
        }

        let report = CPRiskKit.shared.evaluate()
        XCTAssertFalse(report.reportID.isEmpty, "report must have a valid reportID")

        let envelope = try CPRiskKit.shared.buildSecureReportEnvelope(
            report: report,
            sessionToken: "test-session-token-\(UUID().uuidString)",
            signingKey: "test-signing-key-for-v2a-verification"
        )

        #if DEBUG
        // DEBUG 模式下，enableEnvelopeSignatureV2 默认为 true → "v2a"
        // 如果 remoteConfig 覆写了 enableEnvelopeSignatureV2=false 则为 "v1"
        XCTAssertTrue(
            envelope.sigVer == "v2a" || envelope.sigVer == "v1",
            "DEBUG sigVer must be 'v2a' or 'v1', got '\(envelope.sigVer)'"
        )
        #else
        XCTAssertEqual(envelope.sigVer, "v2a",
                       "Release build must always emit v2a signature version")
        #endif

        XCTAssertFalse(envelope.signature.isEmpty, "signature must not be empty")
        XCTAssertFalse(envelope.nonce.isEmpty, "nonce must not be empty")
        XCTAssertGreaterThan(envelope.ts, 0, "timestamp must be positive")
    }

    /// 验证 effectiveSigningKey 确实由 armor material 混入。
    /// active runtime 下，签名密钥必须由 `cprisk_get_runtime_material()` 返回的 32 字节参与 HMAC 派生。
    func testEffectiveSigningKeyDerivedFromArmorMaterial() throws {
        CPRiskKit.shared.start()
        let snapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        guard snapshot.status == "active" else {
            throw XCTSkip("当前测试二进制未提供可用 armor runtime，跳过 active-path 派生密钥断言（需 Release 加固构建或设置 CPRISKKIT_ARMOR_ROOT_KEY_HEX）")
        }

        let report = CPRiskKit.shared.evaluate()
        let baseKey = "test-base-signing-key"

        let envelope = try CPRiskKit.shared.buildSecureReportEnvelope(
            report: report,
            sessionToken: "test-session",
            signingKey: baseKey
        )

        // Reconstruct the expected effective key using the bytes returned by runtime
        var material = [UInt8](repeating: 0, count: 32)
        _ = cprisk_get_runtime_material(&material)
        let materialData = Data(material)

        guard let keyData = baseKey.data(using: .utf8) else {
            XCTFail("baseKey must be UTF-8 encodable")
            return
        }
        let derived = HMAC<SHA256>.authenticationCode(
            for: keyData,
            using: SymmetricKey(data: materialData)
        )
        let expectedEffectiveKey = Data(derived).map { String(format: "%02x", $0) }.joined()

        let verified = envelope.verifySignature(expectedEffectiveKey)
        XCTAssertTrue(verified,
                      "envelope signature must verify against HMAC(armorMaterial, baseKey)")

        // 验证 validateSecureReportEnvelope 使用 baseKey 能正确验签 v2a 信封
        let validationResult = CPRiskKit.shared.validateSecureReportEnvelope(
            envelope,
            signingKey: baseKey,
            enableReplayProtection: false
        )
        if case .failure(let err) = validationResult {
            XCTFail("validateSecureReportEnvelope with baseKey must succeed for v2a envelope: \(err)")
        }
    }

    // MARK: - Test 3: Armor Failure Injects Risk Signal

    /// 验证壳初始化失败时，SDK 会在 evaluate() 的信号列表中注入 armor 风险信号。
    func testArmorFailureInjectsRiskSignal() {
        let report = CPRiskKit.shared.evaluate()
        let snapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        let armorSignals = report.signals.filter {
            $0.id == "armor_runtime_unavailable" || $0.id == "armor_runtime_init_failed"
        }

        if snapshot.status == "active" {
            XCTAssertTrue(armorSignals.isEmpty,
                          "active armor runtime should not inject degradation signal")
        } else {
            XCTAssertFalse(armorSignals.isEmpty,
                           "non-active armor runtime must inject a risk signal")

            let signal = armorSignals[0]
            XCTAssertEqual(signal.category, "anti_tamper",
                           "armor signal category must be 'anti_tamper'")
            XCTAssertGreaterThan(signal.score, 0,
                                "armor signal score must be positive")
            XCTAssertTrue(signal.evidenceJSON.contains("reason"),
                          "armor signal evidenceJSON must include 'reason' key")
            XCTAssertTrue(signal.evidenceJSON.contains("trigger"),
                          "armor signal evidenceJSON must include 'trigger' key")
        }
    }

    /// 验证 armor runtime 状态信号中包含诊断字段。
    func testArmorSignalContainsDiagnosticFields() {
        CPRiskKit.shared.start()
        let snapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        XCTAssertFalse(snapshot.status.isEmpty, "status must not be empty")
        XCTAssertFalse(snapshot.reason.isEmpty, "reason must not be empty")
        XCTAssertFalse(snapshot.trigger.isEmpty, "trigger must not be empty")
        XCTAssertFalse(snapshot.rootKeySource.isEmpty, "rootKeySource must not be empty")
        XCTAssertGreaterThan(snapshot.attemptCount, 0, "at least one init attempt after start()")
    }

    /// 验证连续 evaluate() 调用中 armor 信号一致性：
    /// 状态不会在两次调用间莫名切换。
    func testArmorSignalConsistencyAcrossEvaluations() {
        let report1 = CPRiskKit.shared.evaluate()
        let report2 = CPRiskKit.shared.evaluate()

        let armorIDs1 = Set(report1.signals
            .filter { $0.id.hasPrefix("armor_runtime") }
            .map(\.id))
        let armorIDs2 = Set(report2.signals
            .filter { $0.id.hasPrefix("armor_runtime") }
            .map(\.id))

        XCTAssertEqual(armorIDs1, armorIDs2,
                       "armor runtime signal IDs must be consistent across evaluations without stop/restart")
    }

    /// 验证 stop() 后重新 start()，armor 信号重新初始化。
    func testArmorRuntimeReInitAfterStopStart() {
        CPRiskKit.shared.start()
        let snapshot1 = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        XCTAssertGreaterThan(snapshot1.attemptCount, 0)

        CPRiskKit.shared.stop()
        let stoppedSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        XCTAssertEqual(stoppedSnapshot.status, "inactive")

        CPRiskKit.shared.start()
        let snapshot2 = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        XCTAssertGreaterThan(snapshot2.attemptCount, 0)
        XCTAssertNotEqual(snapshot2.status, "inactive")
    }
}
