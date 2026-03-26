import XCTest
@testable import CloudPhoneRiskKit

final class ProtectionStabilityStoreTests: XCTestCase {

    private func makeStore() -> ProtectionStabilityStore {
        let fs = SecureFileStore(subdirectory: "ProtectionStabilityStoreTests.\(UUID().uuidString)")
        let cache = ConfigCache.inMemoryCache()
        return ProtectionStabilityStore(fileStore: fs, configCache: cache)
    }

    private func makePersistentCache() -> ConfigCache {
        let cache = ConfigCache.instance(withNamespace: "ProtectionStabilityStoreTests.\(UUID().uuidString)")
        cache.clear()
        return cache
    }

    private func sampleRemoteConfig(version: Int) -> RemoteConfig {
        RemoteConfig(
            version: version,
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
            securityHardening: nil,
            textSegmentHashReference: nil
        )
    }

    // MARK: - 1. 编解码 / 持久化

    func testStorePersistenceRoundTrip() {
        let fs = SecureFileStore(subdirectory: "ProtectionStabilityStoreTests.persist.\(UUID().uuidString)")
        let cache = makePersistentCache()
        let store1 = ProtectionStabilityStore(fileStore: fs, configCache: cache)
        store1.resetForTesting()

        _ = store1.beginSession(
            remoteConfigVersion: 7,
            antiDebugMode: .production,
            safeProfileAlreadyActive: false
        )
        store1.markPhase(.armorRuntimeInit)
        store1.markStartupCompleted(remoteConfigVersion: 7)

        let store2 = ProtectionStabilityStore(fileStore: fs, configCache: cache)
        let snap = store2.currentSnapshot()
        XCTAssertEqual(snap.lastHealthyStartupAt != nil, true)
        XCTAssertEqual(snap.currentPhase, .startupCompleted)
        XCTAssertEqual(snap.lastFailedConfigVersion, nil)
    }

    // MARK: - 2. 上次 session 未完成 -> 异常终止

    func testPreviousSessionIncompleteDetectedAsAbnormal() {
        let store = makeStore()
        store.resetForTesting()

        _ = store.beginSession(
            remoteConfigVersion: 42,
            antiDebugMode: .relaxedDevelopmentQA,
            safeProfileAlreadyActive: false
        )
        store.markPhase(.armorRuntimeInit)
        // 故意不调用 markStartupCompleted，模拟崩溃

        let bootstrap = store.beginSession(
            remoteConfigVersion: 42,
            antiDebugMode: .production,
            safeProfileAlreadyActive: false
        )

        XCTAssertNotNil(bootstrap.attribution)
        XCTAssertEqual(bootstrap.attribution?.remoteConfigVersion, 42)
        XCTAssertEqual(bootstrap.attribution?.phase, .armorRuntimeInit)
    }

    // MARK: - 3. 同版本连续两次启动前崩溃 -> 回滚到已验证旧版本

    func testSameVersionRepeatedFailureRollsBackToVerifiedOlderConfig() {
        let fs = SecureFileStore(subdirectory: "ProtectionStabilityStoreTests.rollback.\(UUID().uuidString)")
        let cache = makePersistentCache()
        cache.save(sampleRemoteConfig(version: 10), verifiedByServer: true)
        cache.save(sampleRemoteConfig(version: 20), verifiedByServer: true)

        let store = ProtectionStabilityStore(fileStore: fs, configCache: cache)
        store.resetForTesting()

        // 第一次异常（v20）
        _ = store.beginSession(remoteConfigVersion: 20, antiDebugMode: .production, safeProfileAlreadyActive: false)
        store.markPhase(.antiDebugPrepare)

        // 第二次异常（同版本）
        var bootstrap = store.beginSession(remoteConfigVersion: 20, antiDebugMode: .production, safeProfileAlreadyActive: false)
        XCTAssertNil(bootstrap.rolledBackToVersion)

        // 第三次启动：同版本计数>=2 -> 触发回滚
        bootstrap = store.beginSession(remoteConfigVersion: 20, antiDebugMode: .production, safeProfileAlreadyActive: false)
        XCTAssertTrue(bootstrap.didRollbackRemoteConfig)
        XCTAssertEqual(bootstrap.rolledBackToVersion, 10)

        let rolled = cache.load()?.config.version
        XCTAssertEqual(rolled, 10)
    }

    // MARK: - 4. 无可回滚版本 -> 本地 safe profile + kill switch

    func testNoRollbackCandidateEntersLocalDegradedMode() {
        let fs = SecureFileStore(subdirectory: "ProtectionStabilityStoreTests.degraded.\(UUID().uuidString)")
        let cache = makePersistentCache()
        cache.save(sampleRemoteConfig(version: 5), verifiedByServer: true)
        // 仅 v5，无法找到 <5 的候选

        let store = ProtectionStabilityStore(fileStore: fs, configCache: cache)
        store.resetForTesting()

        _ = store.beginSession(remoteConfigVersion: 5, antiDebugMode: .production, safeProfileAlreadyActive: false)
        _ = store.beginSession(remoteConfigVersion: 5, antiDebugMode: .production, safeProfileAlreadyActive: false)
        let bootstrap = store.beginSession(remoteConfigVersion: 5, antiDebugMode: .production, safeProfileAlreadyActive: false)

        XCTAssertFalse(bootstrap.didRollbackRemoteConfig)
        XCTAssertTrue(bootstrap.didEnterLocalSafeProfile)
        XCTAssertTrue(bootstrap.didActivateLocalStabilityKillSwitch)

        XCTAssertTrue(store.isLocalSafeProfileActive())
        XCTAssertTrue(store.isLocalStabilityKillSwitchEnabled())
    }

    // MARK: - 5. 防震荡：进入 safe profile 后不会仅因成功次数立即恢复（需更高版本）

    func testSafeProfileDoesNotClearUntilHigherVersionAfterEnoughSuccesses() {
        let store = makeStore()
        store.resetForTesting()

        _ = store.beginSession(remoteConfigVersion: 5, antiDebugMode: .production, safeProfileAlreadyActive: false)
        _ = store.beginSession(remoteConfigVersion: 5, antiDebugMode: .production, safeProfileAlreadyActive: false)
        _ = store.beginSession(remoteConfigVersion: 5, antiDebugMode: .production, safeProfileAlreadyActive: false)

        XCTAssertTrue(store.isLocalSafeProfileActive())

        store.markStartupCompleted(remoteConfigVersion: 5)
        store.markStartupCompleted(remoteConfigVersion: 5)
        store.markStartupCompleted(remoteConfigVersion: 5)

        XCTAssertTrue(store.isLocalSafeProfileActive(), "仅成功次数达标但版本未升高，不应解除")

        store.markStartupCompleted(remoteConfigVersion: 6)

        XCTAssertFalse(store.isLocalSafeProfileActive())
        XCTAssertFalse(store.isLocalStabilityKillSwitchEnabled())
    }
}
