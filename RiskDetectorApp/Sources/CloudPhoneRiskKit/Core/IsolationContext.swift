// MARK: - IsolationContext — Multi-Instance Process Isolation
//
// 为 CPRiskKit 提供多实例隔离能力，支持 App Extension / Widget 等多进程场景下
// 各进程持有独立的评估状态、Keychain 命名空间和存储路径。
//
// 设计原则：
//   - 每个 IsolationContext 拥有独立的 keychain prefix、存储目录和评估状态
//   - 支持 App Group 共享容器，用于主 App 与 Extension 共享关键配置
//   - CPRiskKit.shared 作为默认 context 保持完全向后兼容
//   - 通过 CPRiskKit.scoped(identifier:group:) 获取进程作用域实例

import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - IsolationContext

/// 进程隔离上下文：封装单个 CPRiskKit 实例的全部运行时状态。
///
/// 每个 IsolationContext 维护独立的：
/// - Keychain 命名空间（`keychainPrefix`）
/// - 本地存储目录（`storagePath`）
/// - 评估状态缓存
/// - 远程配置引用
///
/// 多进程场景（App Extension、Widget、Keyboard Extension 等）应使用不同 identifier
/// 创建各自的 context，避免 Keychain 和存储路径冲突。
public final class IsolationContext: @unchecked Sendable {

    /// 上下文唯一标识符，用于区分不同进程/实例
    public let identifier: String

    /// App Group 标识（可选），用于跨进程共享配置
    public let appGroupIdentifier: String?

    /// Keychain 项的前缀，确保不同 context 的数据互不干扰
    public let keychainPrefix: String

    /// 独立的存储根路径
    public let storagePath: URL

    /// 评估状态（线程安全）
    internal let evaluationState: EvaluationState

    /// 上下文级别的配置快照
    internal var configSnapshot: ContextConfigSnapshot

    private let lock = NSLock()

    /// 创建隔离上下文
    ///
    /// - Parameters:
    ///   - identifier: 唯一标识符（推荐使用 reverse-DNS 风格，如 "com.app.keyboard-extension"）
    ///   - appGroupIdentifier: App Group ID（如 "group.com.company.app"），用于共享容器
    public init(identifier: String, appGroupIdentifier: String? = nil) {
        self.identifier = identifier
        self.appGroupIdentifier = appGroupIdentifier
        self.keychainPrefix = "com.cprisk.\(identifier)"
        self.evaluationState = EvaluationState()
        self.configSnapshot = ContextConfigSnapshot()

        if let groupId = appGroupIdentifier,
           let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) {
            self.storagePath = containerURL
                .appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
                .appendingPathComponent(identifier, isDirectory: true)
        } else {
            let cachesURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSTemporaryDirectory())
            self.storagePath = cachesURL
                .appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
                .appendingPathComponent(identifier, isDirectory: true)
        }

        ensureStorageDirectory()
    }

    // MARK: - Default Context

    /// 默认上下文（与 CPRiskKit.shared 绑定），保持向后兼容
    public static let `default` = IsolationContext(identifier: "default")

    // MARK: - Thread-Safe State Access

    /// 读取当前评估缓存的报告摘要（线程安全）
    public var lastEvaluationDigest: String? {
        lock.lock()
        defer { lock.unlock() }
        return evaluationState.lastDigest
    }

    /// 记录评估结果摘要
    internal func recordEvaluationDigest(_ digest: String) {
        lock.lock()
        defer { lock.unlock() }
        evaluationState.lastDigest = digest
    }

    /// 更新配置快照
    internal func updateConfig(_ snapshot: ContextConfigSnapshot) {
        lock.lock()
        defer { lock.unlock() }
        configSnapshot = snapshot
    }

    /// 读取配置快照
    internal func currentConfig() -> ContextConfigSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return configSnapshot
    }

    // MARK: - App Group Shared State

    /// 向 App Group 共享容器写入键值对（跨进程共享）
    ///
    /// 适用于将主 App 的配置或状态同步给 Extension / Widget。
    /// 仅在 `appGroupIdentifier` 非空时生效。
    public func setSharedValue(_ value: Any?, forKey key: String) {
        guard let groupId = appGroupIdentifier else { return }
        let defaults = UserDefaults(suiteName: groupId)
        let namespacedKey = "\(keychainPrefix).\(key)"
        defaults?.set(value, forKey: namespacedKey)
    }

    /// 从 App Group 共享容器读取键值对
    public func sharedValue(forKey key: String) -> Any? {
        guard let groupId = appGroupIdentifier else { return nil }
        let defaults = UserDefaults(suiteName: groupId)
        let namespacedKey = "\(keychainPrefix).\(key)"
        return defaults?.object(forKey: namespacedKey)
    }

    /// 移除 App Group 共享容器中的键值对
    public func removeSharedValue(forKey key: String) {
        guard let groupId = appGroupIdentifier else { return }
        let defaults = UserDefaults(suiteName: groupId)
        let namespacedKey = "\(keychainPrefix).\(key)"
        defaults?.removeObject(forKey: namespacedKey)
    }

    // MARK: - Keychain Namespacing

    /// 生成带命名空间的 Keychain service 名
    ///
    /// 不同 context 使用不同的 service 名，确保 Keychain 数据隔离。
    public func keychainService(for component: String) -> String {
        "\(keychainPrefix).\(component)"
    }

    /// 生成带命名空间的 Keychain account 名
    public func keychainAccount(for key: String) -> String {
        "\(keychainPrefix).account.\(key)"
    }

    // MARK: - Storage Paths

    /// 返回 context 内的子路径（自动创建目录）
    public func storagePath(for component: String) -> URL {
        let path = storagePath.appendingPathComponent(component, isDirectory: true)
        try? FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        return path
    }

    /// 返回 context 内的文件路径
    public func storageFile(named filename: String, in component: String? = nil) -> URL {
        if let component {
            return storagePath(for: component).appendingPathComponent(filename)
        }
        return storagePath.appendingPathComponent(filename)
    }

    // MARK: - Lifecycle

    /// 重置评估状态（用于注销场景或测试）
    public func resetEvaluationState() {
        lock.lock()
        defer { lock.unlock() }
        evaluationState.reset()
    }

    /// 清除当前 context 的所有本地存储（包含缓存、历史评估数据等）
    ///
    /// 注意：此操作不可逆，不影响 Keychain 数据和 App Group 共享数据。
    public func clearLocalStorage() {
        try? FileManager.default.removeItem(at: storagePath)
        ensureStorageDirectory()
    }

    // MARK: - Private

    private func ensureStorageDirectory() {
        try? FileManager.default.createDirectory(at: storagePath, withIntermediateDirectories: true)
    }
}

// MARK: - EvaluationState

extension IsolationContext {

    /// 评估状态：维护单个 context 内的评估运行时数据
    internal final class EvaluationState {
        var lastDigest: String?
        var previousSignalIds: Set<String> = []
        var previousSignalsDigest: String?
        var cachedReport: AnyObject?
        var cachedKey: String?
        var lastEvaluationEpoch: TimeInterval = 0
        var evaluationCount: UInt64 = 0

        func reset() {
            lastDigest = nil
            previousSignalIds = []
            previousSignalsDigest = nil
            cachedReport = nil
            cachedKey = nil
            lastEvaluationEpoch = 0
            evaluationCount = 0
        }
    }
}

// MARK: - ContextConfigSnapshot

extension IsolationContext {

    /// 上下文级配置快照：记录从 CPRiskConfig 提取的配置状态
    internal struct ContextConfigSnapshot {
        var enableBehaviorDetect: Bool = true
        var enableNetworkSignals: Bool = true
        var enableAntiTamper: Bool = true
        var enableRemoteConfig: Bool = true
        var threshold: Double = 55.0
        var boundAccountId: String?
        var boundSceneTag: String?
        var sessionId: String?
    }
}

// MARK: - IsolationContext Registry

extension IsolationContext {

    /// 全局 context 注册表（线程安全）
    ///
    /// 维护所有已创建的 IsolationContext 实例引用，支持按 identifier 查找。
    /// `CPRiskKit.scoped(identifier:group:)` 使用此注册表确保相同 identifier 只创建一个实例。
    internal static let registry = ContextRegistry()

    internal final class ContextRegistry: @unchecked Sendable {
        private var contexts: [String: IsolationContext] = [:]
        private let lock = NSLock()

        func getOrCreate(identifier: String, appGroupIdentifier: String?) -> IsolationContext {
            lock.lock()
            defer { lock.unlock() }

            if let existing = contexts[identifier] {
                return existing
            }

            let context = IsolationContext(identifier: identifier, appGroupIdentifier: appGroupIdentifier)
            contexts[identifier] = context
            return context
        }

        func get(identifier: String) -> IsolationContext? {
            lock.lock()
            defer { lock.unlock() }
            return contexts[identifier]
        }

        func remove(identifier: String) {
            lock.lock()
            defer { lock.unlock() }
            contexts.removeValue(forKey: identifier)
        }

        func allIdentifiers() -> [String] {
            lock.lock()
            defer { lock.unlock() }
            return Array(contexts.keys)
        }

        /// 仅用于测试
        func removeAll() {
            lock.lock()
            defer { lock.unlock() }
            contexts.removeAll()
        }
    }
}

// MARK: - CPRiskKit Scoped Factory

extension CPRiskKit {

    /// 返回指定标识符的进程作用域 IsolationContext。
    ///
    /// 相同 identifier 返回相同实例（singleton per identifier）。
    /// 适用于 App Extension / Widget / Keyboard Extension 等多进程场景。
    ///
    /// ```swift
    /// // 在 Keyboard Extension 中
    /// let context = CPRiskKit.scoped(
    ///     identifier: "keyboard-extension",
    ///     group: "group.com.company.app"
    /// )
    /// // context.keychainPrefix → "com.cprisk.keyboard-extension"
    /// // context.storagePath → <shared-container>/CloudPhoneRiskKit/keyboard-extension/
    /// ```
    ///
    /// - Parameters:
    ///   - identifier: 上下文唯一标识符
    ///   - group: App Group ID（可选），用于跨进程共享状态
    /// - Returns: 与 identifier 绑定的 IsolationContext 实例
    public static func scoped(identifier: String, group: String? = nil) -> IsolationContext {
        IsolationContext.registry.getOrCreate(identifier: identifier, appGroupIdentifier: group)
    }

    /// 返回默认的 IsolationContext（与 CPRiskKit.shared 绑定）
    ///
    /// 等价于 `IsolationContext.default`，用于不需要多实例隔离的普通场景。
    public static var defaultContext: IsolationContext {
        IsolationContext.default
    }

    /// 列出所有已注册的 context 标识符（调试/诊断用）
    public static var registeredContextIdentifiers: [String] {
        IsolationContext.registry.allIdentifiers()
    }
}
