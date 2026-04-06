import Foundation

/// 检测器注册中心
///
/// 管理 SDK 2.0 中新增的检测器，提供统一的注册和调用接口
///
/// ## 架构说明
/// - 使用注册模式，支持动态添加/移除检测器
/// - 与现有 JailbreakEngine 兼容，可以通过配置启用新检测器
/// - 支持检测器分组管理（越狱检测、反篡改检测、行为检测等）
public final class DetectorRegistry {
    
    // MARK: - Singleton
    
    public static let shared = DetectorRegistry()
    
    private init() {
        self.registry = DetectorRegistryBootstrap.makeDefaultRegistry()
        self.groupTypeOrder = DetectorRegistryBootstrap.makeOrderedGroups()
    }
    
    // MARK: - 检测器类型

    /// 检测器类型枚举
    public enum DetectorType: CaseIterable, Sendable {
        // 原有越狱检测器
        case file
        case dyld
        case env
        case sysctl
        case scheme
        case hook

        // 新增反篡改检测器
        case antiTampering
        case debugger
        case frida
        case fridaModule
        case dylibInjection
        case codeSignature
        case memoryIntegrity
        case runtimeIntegrity

        // 行为检测型检测器（不依赖工具特征签名）
        case functionIntegrityHash   // 函数前缀哈希基线校验（对抗 Dobby/Ellekit/任意 inline hook）
        case moduleWhitelist         // 模块白名单（对抗 IPA 重签注入/越狱 tweak 注入）
        case syscallCrossValidator   // libc 与直接 SVC 结果一致性（对抗越狱隐藏工具）

        public var rawValue: String {
            switch self {
            case .file: return "file"
            case .dyld: return "dyld"
            case .env: return "env"
            case .sysctl: return "sysctl"
            case .scheme: return "scheme"
            case .hook: return ObfuscatedConstants.keywordHook
            case .antiTampering: return ObfuscatedConstants.detectorIDAntiTampering
            case .debugger: return ObfuscatedConstants.detectorIDDebugger
            case .frida: return ObfuscatedConstants.keywordFrida
            case .fridaModule: return ObfuscatedConstants.detectorIDFridaModule
            case .dylibInjection: return "dylib_injection"
            case .codeSignature: return "code_signature"
            case .memoryIntegrity: return "memory_integrity"
            case .runtimeIntegrity: return "runtime_integrity"
            case .functionIntegrityHash: return "function_integrity_hash"
            case .moduleWhitelist: return "module_whitelist"
            case .syscallCrossValidator: return "syscall_cross_validator"
            }
        }

        public init?(rawValue: String) {
            guard let match = Self.allCases.first(where: { $0.rawValue == rawValue }) else {
                return nil
            }
            self = match
        }
    }

    /// 检测器分组
    public enum DetectorGroup: CaseIterable, Sendable {
        case jailbreak
        case antiTamper
        case integrity

        public var rawValue: String {
            switch self {
            case .jailbreak: return ObfuscatedConstants.detectorGroupJailbreak
            case .antiTamper: return ObfuscatedConstants.categoryAntiTamper
            case .integrity: return "integrity"
            }
        }

        public init?(rawValue: String) {
            guard let match = Self.allCases.first(where: { $0.rawValue == rawValue }) else {
                return nil
            }
            self = match
        }
    }

    private enum CFF {
        static let detectTypeLabel = "dr_dt_v1"
        static let detectGroupLabel = "dr_dg_v1"

        static let detectTypeConfig = CFFConfig.adaptive(
            functionSeed: 0xA37C_19E4_5B62_D08F,
            protectionTier: .light,
            dispatcherStyle: .functionPointerTable,
            codecStyle: .feistelSpn
        )

        static let detectGroupConfig = CFFConfig.adaptive(
            functionSeed: 0x5CE1_8A20_7F39_B4D1,
            protectionTier: .light,
            dispatcherStyle: .functionPointerTable,
            codecStyle: .feistelSpn
        )

        static func salt(for type: DetectorType) -> UInt32 {
            CFFRuntimeSalt.derive(
                functionSeed: detectTypeConfig.functionSeed,
                inputs: CFFRuntimeSaltInputs(
                    extraWords: [stableHash64(type.rawValue)],
                    strings: [detectTypeLabel, type.rawValue],
                    flags: [true]
                )
            )
        }

        static func salt(for group: DetectorGroup, detectorCount: Int) -> UInt32 {
            CFFRuntimeSalt.derive(
                functionSeed: detectGroupConfig.functionSeed,
                inputs: CFFRuntimeSaltInputs(
                    extraWords: [stableHash64(group.rawValue), UInt64(detectorCount)],
                    strings: [detectGroupLabel, group.rawValue],
                    flags: [detectorCount > 0]
                )
            )
        }

        private static func stableHash64(_ value: String) -> UInt64 {
            var hash: UInt64 = 0xCBF29CE484222325
            for byte in value.utf8 {
                hash ^= UInt64(byte)
                hash &*= 0x100000001B3
            }
            return hash
        }
    }

    // MARK: - 检测器元数据清单

    /// 检测器生命周期元数据，用于管理 iOS 版本兼容性、依赖关系和信号去重
    public struct DetectorManifest: Sendable {
        /// 支持的最低 iOS 版本（如 14.0）
        public let minOS: Double
        /// 支持的最高 iOS 版本（nil 表示无上限）
        public let maxOS: Double?
        /// 依赖的其他检测器（当前检测器需要依赖检测器先执行）
        public let dependsOn: Set<DetectorType>
        /// 与哪些检测器互斥（同时启用时仅保留优先级更高者）
        public let conflictsWith: Set<DetectorType>
        /// 信号重叠分组标识（同组检测器评分取 max 而非累加，防止重复计分）
        public let signalOverlapGroup: String?
        /// 检测器优先级（同组冲突时保留优先级最高者，默认 100）
        public let priority: Int

        public init(
            minOS: Double = 14.0,
            maxOS: Double? = nil,
            dependsOn: Set<DetectorType> = [],
            conflictsWith: Set<DetectorType> = [],
            signalOverlapGroup: String? = nil,
            priority: Int = 100
        ) {
            self.minOS = minOS
            self.maxOS = maxOS
            self.dependsOn = dependsOn
            self.conflictsWith = conflictsWith
            self.signalOverlapGroup = signalOverlapGroup
            self.priority = priority
        }
    }

    /// 内置检测器元数据注册表
    private static let manifests: [DetectorType: DetectorManifest] = [
        .file: DetectorManifest(signalOverlapGroup: ObfuscatedConstants.overlapGroupJailbreakFile),
        .dyld: DetectorManifest(signalOverlapGroup: "dyld"),
        .env: DetectorManifest(),
        .sysctl: DetectorManifest(),
        .scheme: DetectorManifest(),
        .hook: DetectorManifest(signalOverlapGroup: ObfuscatedConstants.overlapGroupHook),
        .antiTampering: DetectorManifest(
            dependsOn: [.debugger],
            signalOverlapGroup: ObfuscatedConstants.categoryAntiTamper
        ),
        .debugger: DetectorManifest(signalOverlapGroup: ObfuscatedConstants.categoryAntiTamper),
        .frida: DetectorManifest(
            signalOverlapGroup: ObfuscatedConstants.overlapGroupFrida,
            priority: 120
        ),
        .fridaModule: DetectorManifest(
            signalOverlapGroup: ObfuscatedConstants.overlapGroupFrida,
            priority: 125
        ),
        .dylibInjection: DetectorManifest(
            signalOverlapGroup: "dyld"
        ),
        .codeSignature: DetectorManifest(minOS: 14.0),
        .memoryIntegrity: DetectorManifest(
            minOS: 14.0,
            signalOverlapGroup: "memory"
        ),
        .runtimeIntegrity: DetectorManifest(
            minOS: 14.0,
            signalOverlapGroup: "runtime_integrity"
        ),
        // 行为检测型（不依赖工具特征签名）
        .functionIntegrityHash: DetectorManifest(
            minOS: 14.0,
            signalOverlapGroup: ObfuscatedConstants.overlapGroupFrida,
            priority: 110
        ),
        .moduleWhitelist: DetectorManifest(
            minOS: 14.0,
            dependsOn: [.dylibInjection],
            signalOverlapGroup: "dyld"
        ),
        .syscallCrossValidator: DetectorManifest(
            minOS: 14.0,
            signalOverlapGroup: "syscall_crosscheck",
            priority: 115
        ),
    ]
    
    // MARK: - 线程安全与封印

    private let lock = UnfairLock()

    /// 封印后拒绝一切 register/unregister 操作
    private var _isSealed = false
    public var isSealed: Bool {
        lock.withLock { _isSealed }
    }

    // MARK: - 注册表
    
    /// 检测器工厂类型
    public typealias DetectorFactory = () -> Detector
    
    /// 检测器注册表（由运行时 plan 构建，避免单一巨型字面量）
    private var registry: [DetectorType: DetectorFactory]
    
    /// 分组内检测顺序（稳定、可复现；不依赖 `Set` 迭代顺序）
    private let groupTypeOrder: [DetectorGroup: [DetectorType]]
    
    // MARK: - 公开 API
    
    /// 注册自定义检测器
    /// - Parameters:
    ///   - type: 检测器类型
    ///   - factory: 检测器工厂闭包
    public func register(type: DetectorType, factory: @escaping DetectorFactory) {
        lock.withLock {
            guard !_isSealed else {
                Logger.log("DetectorRegistry.register rejected (sealed): \(type.rawValue)")
                return
            }
            registry[type] = factory
            Logger.log("DetectorRegistry.register: \(type.rawValue)")
        }
    }
    
    /// 注销检测器
    /// - Parameter type: 检测器类型
    public func unregister(type: DetectorType) {
        lock.withLock {
            guard !_isSealed else {
                Logger.log("DetectorRegistry.unregister rejected (sealed): \(type.rawValue)")
                return
            }
            registry.removeValue(forKey: type)
            Logger.log("DetectorRegistry.unregister: \(type.rawValue)")
        }
    }

    /// 封印注册表，调用后拒绝一切 register/unregister 操作
    public func seal() {
        lock.withLock {
            _isSealed = true
            Logger.log("DetectorRegistry.sealed")
        }
    }
    
    /// 创建检测器实例
    /// - Parameter type: 检测器类型
    /// - Returns: 检测器实例，如果类型未注册则返回 nil
    public func createDetector(type: DetectorType) -> Detector? {
        lock.withLock {
            guard let factory = registry[type] else {
                Logger.log("DetectorRegistry.createDetector: \(type.rawValue) not found")
                return nil
            }
            return factory()
        }
    }
    
    /// 执行指定类型的检测
    /// - Parameter type: 检测器类型
    /// - Returns: 检测结果
    public func detect(type: DetectorType) -> DetectorResult {
        let cffConfig = CFF.detectTypeConfig
        let salt = CFF.salt(for: type)
        let entryState: UInt32 = 0x31
        let createState: UInt32 = 0x32
        let executeState: UInt32 = 0x33
        let connectorState: UInt32 = 0x34
        let settleState: UInt32 = 0x35
        let finishState: UInt32 = 0x36

        let anomalyResult = DetectorResult(score: 80, methods: ["detector_anomaly_\(type.rawValue)"])
        let cffKey = CFFStateCodec.deriveSeed(function: CFF.detectTypeLabel, config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<DetectorResult>()
        var detector: Detector?
        var result: DetectorResult = .empty
        var loopBudget = 20
        var encodedState = encodeState(entryState)

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(result)
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain
                || (dispatchPlan.usesSecondaryDispatcher && CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt))

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(createState)
                } else if decodedState == createState {
                    detector = createDetector(type: type)
                    if detector == nil {
                        sink.store(.empty)
                    } else {
                        let nextState = CFFOpaquePredicates.parityFence(decodedState &+ 1, salt: salt) ? connectorState : executeState
                        encodedState = encodeState(nextState)
                    }
                } else if decodedState == connectorState {
                    encodedState = encodeState(executeState)
                } else if decodedState == executeState {
                    do {
                        result = try detector?.detect() ?? .empty
                    } catch {
                        Logger.log("detector_exec_failed:\(type.rawValue):\(error)")
                        result = anomalyResult
                    }
                    encodedState = encodeState(finishState)
                } else if decodedState == finishState {
                    sink.store(result)
                } else if decodedState == settleState {
                    encodedState = encodeState(executeState)
                } else {
                    sink.store(result)
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(createState)
                case createState:
                    detector = createDetector(type: type)
                    guard detector != nil else {
                        sink.store(.empty)
                        continue
                    }
                    encodedState = encodeState(connectorState)
                case connectorState:
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? executeState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(executeState)
                case executeState:
                    do {
                        result = try detector?.detect() ?? .empty
                    } catch {
                        Logger.log("detector_exec_failed:\(type.rawValue):\(error)")
                        result = anomalyResult
                    }
                    encodedState = encodeState(finishState)
                case finishState:
                    sink.store(result)
                default:
                    sink.store(result)
                }
            }
        }

        return sink.resolve(or: result)
    }
    
    /// 执行指定分组的所有检测
    /// - Parameter group: 检测器分组
    /// - Returns: 分组检测结果
    public func detect(group: DetectorGroup) -> GroupDetectionResult {
        guard let orderedTypes = groupTypeOrder[group], !orderedTypes.isEmpty else {
            return GroupDetectionResult(score: 0, methods: [], details: "group_not_found")
        }
        let cffConfig = CFF.detectGroupConfig
        let salt = CFF.salt(for: group, detectorCount: orderedTypes.count)
        let entryState: UInt32 = 0x41
        let iterateState: UInt32 = 0x42
        let executeState: UInt32 = 0x43
        let connectorState: UInt32 = 0x44
        let settleState: UInt32 = 0x45
        let finishState: UInt32 = 0x46

        var totalScore: Double = 0
        var allMethods: [String] = []
        var typeIndex = 0
        var currentType: DetectorType?
        var loopBudget = max(24, orderedTypes.count * 5 + 10)
        let cffKey = CFFStateCodec.deriveSeed(function: CFF.detectGroupLabel, config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<GroupDetectionResult>()
        var encodedState = encodeState(entryState)

        func finalizeResult() -> GroupDetectionResult {
            GroupDetectionResult(
                score: totalScore,
                methods: Array(Set(allMethods)).sorted(),
                details: "\(group.rawValue)_group"
            )
        }

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(finalizeResult())
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain || (dispatchPlan.branchSelector == 3)

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == iterateState {
                    guard typeIndex < orderedTypes.count else {
                        encodedState = encodeState(finishState)
                        continue
                    }
                    currentType = orderedTypes[typeIndex]
                    encodedState = encodeState(executeState)
                } else if decodedState == executeState {
                    if let currentType {
                        let result = detect(type: currentType)
                        totalScore += result.score
                        allMethods.append(contentsOf: result.methods)
                    }
                    currentType = nil
                    typeIndex += 1
                    encodedState = encodeState(connectorState)
                } else if decodedState == connectorState {
                    let nextState = CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt) ? iterateState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == finishState {
                    sink.store(finalizeResult())
                } else {
                    sink.store(finalizeResult())
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(iterateState)
                case iterateState:
                    guard typeIndex < orderedTypes.count else {
                        encodedState = encodeState(finishState)
                        continue
                    }
                    currentType = orderedTypes[typeIndex]
                    encodedState = encodeState(executeState)
                case executeState:
                    if let currentType {
                        let result = detect(type: currentType)
                        totalScore += result.score
                        allMethods.append(contentsOf: result.methods)
                    }
                    currentType = nil
                    typeIndex += 1
                    encodedState = encodeState(connectorState)
                case connectorState:
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? iterateState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(iterateState)
                case finishState:
                    sink.store(finalizeResult())
                default:
                    sink.store(finalizeResult())
                }
            }
        }

        return sink.resolve(or: finalizeResult())
    }
    
    /// 执行所有启用的检测
    /// - Parameter enabledTypes: 启用的检测器类型集合
    /// - Returns: 综合检测结果
    ///
    /// 同一 `signalOverlapGroup` 内的检测器评分取最高值（而非累加），防止重复计分。
    public func detectAll(enabledTypes: Set<DetectorType> = Set(DetectorType.allCases)) -> ComprehensiveDetectionResult {
        var groupResults: [DetectorGroup: GroupDetectionResult] = [:]
        var totalScore: Double = 0
        var allMethods: [String] = []

        for group in DetectorGroup.allCases {
            let groupTypes = types(in: group).intersection(enabledTypes)

            // 收集原始结果
            var rawResults: [(DetectorType, DetectorResult)] = []
            for detectorType in groupTypes {
                let result = detect(type: detectorType)
                rawResults.append((detectorType, result))
            }

            // 信号重叠去重：同组取 max score
            let deduped = deduplicateByOverlapGroup(rawResults)

            var groupScore: Double = 0
            var groupMethods: [String] = []
            for (_, result) in deduped {
                groupScore += result.score
                groupMethods.append(contentsOf: result.methods)
            }

            let groupResult = GroupDetectionResult(
                score: groupScore,
                methods: Array(Set(groupMethods)).sorted(),
                details: "\(group.rawValue)_group"
            )
            groupResults[group] = groupResult
            totalScore += groupScore
            allMethods.append(contentsOf: groupMethods)
        }

        return ComprehensiveDetectionResult(
            totalScore: totalScore,
            groupResults: groupResults,
            allMethods: Array(Set(allMethods)).sorted(),
            summary: generateSummary(totalScore: totalScore, methods: allMethods)
        )
    }
    
    /// 获取检测器类型所属分组
    /// - Parameter type: 检测器类型
    /// - Returns: 检测器分组
    public func group(for type: DetectorType) -> DetectorGroup? {
        for (group, types) in groupTypeOrder {
            if types.contains(type) {
                return group
            }
        }
        return nil
    }
    
    /// 获取指定分组中的所有检测器类型
    /// - Parameter group: 检测器分组
    /// - Returns: 检测器类型集合
    public func types(in group: DetectorGroup) -> Set<DetectorType> {
        Set(groupTypeOrder[group] ?? [])
    }
    
    // MARK: - Manifest 查询

    /// 获取检测器的元数据清单
    public func manifest(for type: DetectorType) -> DetectorManifest {
        Self.manifests[type] ?? DetectorManifest()
    }

    /// 判断检测器在当前 iOS 版本上是否可用
    public func isAvailable(_ type: DetectorType, osVersion: Double) -> Bool {
        let m = manifest(for: type)
        if osVersion < m.minOS { return false }
        if let maxOS = m.maxOS, osVersion > maxOS { return false }
        return true
    }

    /// 获取指定检测器的未满足依赖
    public func unsatisfiedDependencies(for type: DetectorType, enabledTypes: Set<DetectorType>) -> Set<DetectorType> {
        let m = manifest(for: type)
        return m.dependsOn.subtracting(enabledTypes)
    }

    /// 对分组检测结果进行信号重叠去重（同 signalOverlapGroup 内取 max score）
    public func deduplicateByOverlapGroup(_ results: [(DetectorType, DetectorResult)]) -> [(DetectorType, DetectorResult)] {
        var groupBest: [String: (DetectorType, DetectorResult)] = [:]
        var ungrouped: [(DetectorType, DetectorResult)] = []

        for (type, result) in results {
            let m = manifest(for: type)
            if let group = m.signalOverlapGroup {
                if let existing = groupBest[group] {
                    if result.score > existing.1.score ||
                       (result.score == existing.1.score && m.priority > manifest(for: existing.0).priority) {
                        groupBest[group] = (type, result)
                    }
                } else {
                    groupBest[group] = (type, result)
                }
            } else {
                ungrouped.append((type, result))
            }
        }
        return ungrouped + groupBest.values.map { $0 }
    }

    // MARK: - 辅助方法

    private func generateSummary(totalScore: Double, methods: [String]) -> String {
        let methodCount = methods.count
        return """
        total_score=\(totalScore)
        methods_hit=\(methodCount)
        methods=\(methods.prefix(10).joined(separator: ","))
        """
    }
}

// MARK: - 运行时工厂 Plan（降低静态字面量可扫性）

private enum DetectorRegistryBootstrap {
    /// 与 token 混合后再排序，使源码中的行序与运行时注册序解耦
    static let planMix: UInt64 = 0xD37E_C70E_9E41_D6C1

    private struct FactoryToken {
        let token: UInt64
        let type: DetectorRegistry.DetectorType
        let factory: DetectorRegistry.DetectorFactory
    }

    private static let factoryPlan: [FactoryToken] = [
        FactoryToken(token: 0x4B21F9A2C0D18E71, type: .file, factory: { FileDetector() }),
        FactoryToken(token: 0x2E88D403F19A56B4, type: .dyld, factory: { DyldDetector() }),
        FactoryToken(token: 0x7C3A9012E4D5F678, type: .env, factory: { EnvDetector() }),
        FactoryToken(token: 0x1F9C2B45A67890DE, type: .sysctl, factory: { SysctlDetector() }),
        FactoryToken(token: 0x9A0E4F23C567B890, type: .scheme, factory: { SchemeDetector() }),
        FactoryToken(token: 0x3D71E6A8B234C501, type: .hook, factory: { HookDetector() }),
        FactoryToken(token: 0x5E92C4F1A837D602, type: .antiTampering, factory: { AntiTamperingDetector() }),
        FactoryToken(token: 0x6F03D5E2B948E713, type: .debugger, factory: { DebuggerDetector() }),
        FactoryToken(token: 0x8014E6F3CA59F824, type: .frida, factory: { FridaDetector() }),
        FactoryToken(token: 0x9125F704DB6A0935, type: .fridaModule, factory: { FridaModuleDetector() }),
        FactoryToken(token: 0xA2360815EC7B1A46, type: .dylibInjection, factory: { DylibInjectionDetector() }),
        FactoryToken(token: 0xB3471926FD8C2B57, type: .codeSignature, factory: { CodeSignatureValidator() }),
        FactoryToken(token: 0xC4582A370E9D3C68, type: .memoryIntegrity, factory: { MemoryIntegrityChecker() }),
        FactoryToken(token: 0xD5693B481FAE4D79, type: .runtimeIntegrity, factory: { RuntimeIntegrityValidator() }),
        // 行为检测型
        FactoryToken(token: 0xE67A4C5920BF5E8A, type: .functionIntegrityHash, factory: { FunctionIntegrityHashDetector() }),
        FactoryToken(token: 0xF78B5D6A30C16F9B, type: .moduleWhitelist, factory: { ModuleWhitelistDetector() }),
        FactoryToken(token: 0x089C6E7B4D1270AC, type: .syscallCrossValidator, factory: { DirectSyscallCrossValidator() }),
    ]

    private static let groupMembership: [DetectorRegistry.DetectorGroup: Set<DetectorRegistry.DetectorType>] = [
        .jailbreak: [.file, .dyld, .env, .sysctl, .scheme, .hook],
        .antiTamper: [
            .antiTampering, .debugger, .frida, .fridaModule, .dylibInjection,
            // 行为检测型（不依赖工具特征签名）
            .functionIntegrityHash, .moduleWhitelist, .syscallCrossValidator,
        ],
        .integrity: [.codeSignature, .memoryIntegrity, .runtimeIntegrity],
    ]

    private static func groupSalt(_ group: DetectorRegistry.DetectorGroup) -> UInt64 {
        switch group {
        case .jailbreak: return 0x1110_AAAA_BBBB_CCC1
        case .antiTamper: return 0x2220_DDDD_EEEE_FFF2
        case .integrity: return 0x3330_7777_8888_9993
        }
    }

    private static func fnv1a64(_ text: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in text.utf8 {
            hash ^= UInt64(b)
            hash &*= 0x100000001b3
        }
        return hash
    }

    static func makeDefaultRegistry() -> [DetectorRegistry.DetectorType: DetectorRegistry.DetectorFactory] {
        let ordered = factoryPlan.sorted {
            ($0.token ^ planMix) < ($1.token ^ planMix)
        }
        var reg: [DetectorRegistry.DetectorType: DetectorRegistry.DetectorFactory] = [:]
        reg.reserveCapacity(ordered.count)
        for entry in ordered {
            reg[entry.type] = entry.factory
        }
        return reg
    }

    static func makeOrderedGroups() -> [DetectorRegistry.DetectorGroup: [DetectorRegistry.DetectorType]] {
        var out: [DetectorRegistry.DetectorGroup: [DetectorRegistry.DetectorType]] = [:]
        for (group, members) in groupMembership {
            let salt = groupSalt(group)
            let ordered = members.sorted { a, b in
                let ka = fnv1a64(a.rawValue) ^ salt
                let kb = fnv1a64(b.rawValue) ^ salt
                if ka != kb { return ka < kb }
                return a.rawValue < b.rawValue
            }
            out[group] = ordered
        }
        return out
    }
}

// MARK: - 检测结果类型

/// 分组检测结果
public struct GroupDetectionResult {
    public let score: Double
    public let methods: [String]
    public let details: String
}

/// 综合检测结果
public struct ComprehensiveDetectionResult {
    public let totalScore: Double
    public let groupResults: [DetectorRegistry.DetectorGroup: GroupDetectionResult]
    public let allMethods: [String]
    public let summary: String
    
    /// 是否检测到风险
    public var hasRisk: Bool {
        totalScore > 0
    }
    
    /// 获取指定分组的分数
    public func score(for group: DetectorRegistry.DetectorGroup) -> Double {
        groupResults[group]?.score ?? 0
    }
}

// MARK: - JailbreakConfig 扩展

extension JailbreakConfig {
    
    /// 从配置创建启用的检测器类型集合
    var enabledDetectorTypes: Set<DetectorRegistry.DetectorType> {
        var types: Set<DetectorRegistry.DetectorType> = []
        
        if enableFileDetect { types.insert(.file) }
        if enableDyldDetect { types.insert(.dyld) }
        if enableEnvDetect { types.insert(.env) }
        if enableSysctlDetect { types.insert(.sysctl) }
        if enableSchemeDetect { types.insert(.scheme) }
        if enableHookDetect { types.insert(.hook) }
        
        // 默认启用新增的反篡改检测器
        // 可以通过额外配置控制
        types.insert(.antiTampering)
        types.insert(.debugger)
        types.insert(.frida)
        types.insert(.fridaModule)
        types.insert(.dylibInjection)
        types.insert(.codeSignature)
        types.insert(.memoryIntegrity)
        types.insert(.runtimeIntegrity)
        // 行为检测型（不依赖工具特征签名，应对 Dobby/Ellekit/IPA重签注入等）
        types.insert(.functionIntegrityHash)
        types.insert(.moduleWhitelist)
        types.insert(.syscallCrossValidator)

        return types
    }
    
    /// 创建包含新检测器的配置
    public static func v2(
        threshold: Double = 30,
        enableJailbreak: Bool = true,
        enableAntiTamper: Bool = true,
        enableIntegrity: Bool = true
    ) -> JailbreakConfig {
        let config = JailbreakConfig(
            enableFileDetect: enableJailbreak,
            enableDyldDetect: enableJailbreak,
            enableEnvDetect: enableJailbreak,
            enableSysctlDetect: enableJailbreak,
            enableSchemeDetect: enableJailbreak,
            enableHookDetect: enableJailbreak,
            threshold: threshold
        )
        
        // 通过 extras 传递新检测器配置
        // 实际实现中可以扩展 config 结构
        
        return config
    }
}

// MARK: - JailbreakEngine 扩展

extension JailbreakEngine {
    
    /// 使用新检测器架构进行检测
    /// - Parameter config: 检测配置
    /// - Returns: 检测结果
    func detectV2(config: JailbreakConfig) -> DetectionResult {
        let enabledTypes = config.enabledDetectorTypes
        let result = DetectorRegistry.shared.detectAll(enabledTypes: enabledTypes)
        
        let isJailbroken = result.totalScore >= config.threshold
        
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: min(result.totalScore, 100),
            detectedMethods: result.allMethods,
            details: result.summary
        )
    }
}
