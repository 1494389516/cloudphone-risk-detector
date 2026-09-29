import Foundation

public protocol DecisionTreeNode: Sendable {
    func evaluate(context: EvaluationContext) -> DecisionResult
}

public struct EvaluationContext: Sendable {
    public let score: Double
    public let signals: [RiskSignal]
    public let scenario: RiskScenario
    public let riskContext: RiskContext
    public let policy: ScenarioPolicy
    public var metadata: [String: String]

    public init(
        score: Double,
        signals: [RiskSignal],
        scenario: RiskScenario,
        riskContext: RiskContext,
        policy: ScenarioPolicy,
        metadata: [String: String] = [:]
    ) {
        self.score = score
        self.signals = signals
        self.scenario = scenario
        self.riskContext = riskContext
        self.policy = policy
        self.metadata = metadata
    }

    public func hasSignal(_ id: String) -> Bool {
        signals.contains { $0.id == id }
    }

    public func hasSignal(category: String) -> Bool {
        signals.contains { $0.category == category }
    }

    public func signalScore(_ id: String) -> Double {
        signals.first { $0.id == id }?.score ?? 0
    }

    public func categoryScore(_ category: String) -> Double {
        signals.filter { $0.category == category }.reduce(0) { $0 + $1.score }
    }
}

public enum DecisionResult: Sendable {
    case next
    case terminate(action: RiskAction, reason: String)
    case branch(String)

    public var isTerminal: Bool {
        if case .terminate = self { return true }
        return false
    }
}

private enum DecisionTreeCFF {
    static func salt(context: EvaluationContext, token: String, extraWords: [UInt64] = []) -> UInt32 {
        let signalPrefix = context.signals.prefix(2).map(\.id).joined(separator: "|")
        return CFFRuntimeSalt.combine(
            words: [
                context.score.bitPattern,
                UInt64(context.signals.count),
                UInt64(context.metadata.count),
                UInt64(context.scenario.rawValue),
                context.policy.mediumThreshold.bitPattern,
                context.policy.highThreshold.bitPattern,
                context.policy.criticalThreshold.bitPattern,
            ] + extraWords,
            strings: [
                token,
                signalPrefix,
                context.metadata["challenge_state"] ?? "",
                context.metadata["trust_level"] ?? "",
            ],
            flags: [
                context.riskContext.jailbreak.isJailbroken,
                context.riskContext.network.isVPNActive,
                context.riskContext.network.proxyEnabled,
            ]
        )
    }
}

public enum ConditionExpression: Codable, Sendable {
    case scoreRange(min: Double, max: Double)
    case scoreGreaterThanOrEqual(Double)
    case scoreLessThan(Double)
    case signalExists(String)
    case signalScore(id: String, greaterThan: Double)
    case categoryScore(category: String, greaterThan: Double)
    case isJailbroken
    case isVPN
    case isProxy
    case custom(String)

    public func evaluate(context: EvaluationContext) -> Bool {
        let salt = DecisionTreeCFF.salt(context: context, token: "expr")
        let seed: UInt32 = 0x51C2A91D
        let entryState: UInt32 = 0x10
        let scoreRangeState: UInt32 = 0x11
        let scoreGreaterState: UInt32 = 0x12
        let scoreLessState: UInt32 = 0x13
        let signalExistsState: UInt32 = 0x14
        let signalScoreState: UInt32 = 0x15
        let categoryScoreState: UInt32 = 0x16
        let jailbrokenState: UInt32 = 0x17
        let vpnState: UInt32 = 0x18
        let proxyState: UInt32 = 0x19
        let customState: UInt32 = 0x1A

        var sink = CFFReturnSink<Bool>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

            if CFFDispatcher.prefersPrimaryBranch(encodedState: encodedState, salt: salt) {
                if decodedState == entryState {
                    let targetState: UInt32
                    switch self {
                    case .scoreRange:
                        targetState = scoreRangeState
                    case .scoreGreaterThanOrEqual:
                        targetState = scoreGreaterState
                    case .scoreLessThan:
                        targetState = scoreLessState
                    case .signalExists:
                        targetState = signalExistsState
                    case .signalScore:
                        targetState = signalScoreState
                    case .categoryScore:
                        targetState = categoryScoreState
                    case .isJailbroken:
                        targetState = jailbrokenState
                    case .isVPN:
                        targetState = vpnState
                    case .isProxy:
                        targetState = proxyState
                    case .custom:
                        targetState = customState
                    }
                    encodedState = CFFStateCodec.encode(targetState, seed: seed, salt: salt)
                } else if decodedState == scoreRangeState, case let .scoreRange(min, max) = self {
                    sink.store(context.score >= min && context.score < max)
                } else if decodedState == scoreGreaterState, case let .scoreGreaterThanOrEqual(value) = self {
                    sink.store(context.score >= value)
                } else if decodedState == scoreLessState, case let .scoreLessThan(value) = self {
                    sink.store(context.score < value)
                } else if decodedState == signalExistsState, case let .signalExists(id) = self {
                    sink.store(context.hasSignal(id))
                } else if decodedState == signalScoreState, case let .signalScore(id, gt) = self {
                    sink.store(context.signalScore(id) > gt)
                } else if decodedState == categoryScoreState, case let .categoryScore(category, gt) = self {
                    sink.store(context.categoryScore(category) > gt)
                } else if decodedState == jailbrokenState {
                    sink.store(context.riskContext.jailbreak.isJailbroken)
                } else if decodedState == vpnState {
                    sink.store(context.riskContext.network.isVPNActive)
                } else if decodedState == proxyState {
                    sink.store(context.riskContext.network.proxyEnabled)
                } else if decodedState == customState, case let .custom(id) = self {
                    sink.store(ConditionExpression.customEvaluatorRegistry.evaluate(id: id, context: context))
                } else {
                    sink.store(false)
                }
            } else {
                switch decodedState {
                case entryState:
                    let targetState: UInt32
                    switch self {
                    case .scoreRange:
                        targetState = scoreRangeState
                    case .scoreGreaterThanOrEqual:
                        targetState = scoreGreaterState
                    case .scoreLessThan:
                        targetState = scoreLessState
                    case .signalExists:
                        targetState = signalExistsState
                    case .signalScore:
                        targetState = signalScoreState
                    case .categoryScore:
                        targetState = categoryScoreState
                    case .isJailbroken:
                        targetState = jailbrokenState
                    case .isVPN:
                        targetState = vpnState
                    case .isProxy:
                        targetState = proxyState
                    case .custom:
                        targetState = customState
                    }
                    encodedState = CFFStateCodec.encode(targetState, seed: seed, salt: salt)
                case scoreRangeState where self.isScoreRange:
                    if case let .scoreRange(min, max) = self {
                        sink.store(context.score >= min && context.score < max)
                    }
                case scoreGreaterState where self.isScoreGreaterThanOrEqual:
                    if case let .scoreGreaterThanOrEqual(value) = self {
                        sink.store(context.score >= value)
                    }
                case scoreLessState where self.isScoreLessThan:
                    if case let .scoreLessThan(value) = self {
                        sink.store(context.score < value)
                    }
                case signalExistsState where self.isSignalExists:
                    if case let .signalExists(id) = self {
                        sink.store(context.hasSignal(id))
                    }
                case signalScoreState where self.isSignalScore:
                    if case let .signalScore(id, gt) = self {
                        sink.store(context.signalScore(id) > gt)
                    }
                case categoryScoreState where self.isCategoryScore:
                    if case let .categoryScore(category, gt) = self {
                        sink.store(context.categoryScore(category) > gt)
                    }
                case jailbrokenState where self.isJailbrokenExpression:
                    sink.store(context.riskContext.jailbreak.isJailbroken)
                case vpnState where self.isVPNExpression:
                    sink.store(context.riskContext.network.isVPNActive)
                case proxyState where self.isProxyExpression:
                    sink.store(context.riskContext.network.proxyEnabled)
                case customState where self.isCustom:
                    if case let .custom(id) = self {
                        sink.store(ConditionExpression.customEvaluatorRegistry.evaluate(id: id, context: context))
                    }
                default:
                    // Terminate on unexpected state to avoid infinite loop
                    // (resetting to entryState would re-enter the same handler)
                    sink.store(false)
                }
            }
        }

        return sink.resolve(or: false)
    }
}

// MARK: - Custom Condition Evaluator Registry

extension ConditionExpression {
    /// 注册自定义条件求值器。`.custom(id)` 在 evaluate 时会调用已注册的 evaluator。
    /// 若未注册或 evaluator 返回 false，则 `.custom(id)` 视为 false。
    /// 注册仅在 `seal()` 之前有效；`CPRiskKit.start()` 后注册表将被封印。
    ///
    /// 用法：
    /// ```swift
    /// ConditionExpression.registerCustomEvaluator(id: "my_check") { ctx in
    ///     ctx.score > 80 && ctx.hasSignal("vpn_active")
    /// }
    /// ```
    public static func registerCustomEvaluator(id: String, evaluator: @escaping (EvaluationContext) -> Bool) {
        customEvaluatorRegistry.register(id: id, evaluator: evaluator)
    }

    /// 移除已注册的自定义求值器。
    public static func unregisterCustomEvaluator(id: String) {
        customEvaluatorRegistry.unregister(id: id)
    }

    /// 封印自定义求值器注册表，之后拒绝一切 register/unregister。
    public static func sealCustomEvaluators() {
        customEvaluatorRegistry.seal()
    }

#if DEBUG
    /// 测试用：解除封印并清空注册表，允许测试中重新注册。
    public static func unsealCustomEvaluatorsForTesting() {
        customEvaluatorRegistry.unsealForTesting()
    }
#endif

    fileprivate static let customEvaluatorRegistry = CustomEvaluatorRegistry()
}

private final class CustomEvaluatorRegistry: @unchecked Sendable {
    private let lock = UnfairLock()
    private var evaluators: [String: (EvaluationContext) -> Bool] = [:]
    private var isSealed = false

    func register(id: String, evaluator: @escaping (EvaluationContext) -> Bool) {
        let rejected = lock.withLock { () -> Bool in
            if isSealed {
                return true
            }
            evaluators[id] = evaluator
            return false
        }
        if rejected {
            Logger.log("CustomEvaluatorRegistry.register rejected (sealed): \(id)")
        }
    }

    func unregister(id: String) {
        let rejected = lock.withLock { () -> Bool in
            if isSealed {
                return true
            }
            evaluators.removeValue(forKey: id)
            return false
        }
        if rejected {
            Logger.log("CustomEvaluatorRegistry.unregister rejected (sealed): \(id)")
        }
    }

    func seal() {
        lock.withLock {
            isSealed = true
        }
        Logger.log("CustomEvaluatorRegistry.sealed")
    }

#if DEBUG
    func unsealForTesting() {
        lock.withLock {
            isSealed = false
            evaluators.removeAll()
        }
    }
#endif

    func evaluate(id: String, context: EvaluationContext) -> Bool {
        let evaluatorCopy: ((EvaluationContext) -> Bool)? = lock.withLock {
            evaluators[id]
        }
        return evaluatorCopy?(context) ?? false
    }
}

public struct ConditionNode: Codable, Sendable {
    public let id: String
    public let condition: ConditionExpression
    public let trueBranch: DecisionTreeNodeType
    public let falseBranch: DecisionTreeNodeType?

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case condition = "c"
        case trueBranch = "tb"
        case falseBranch = "fb"
    }

    public init(
        id: String,
        condition: ConditionExpression,
        trueBranch: DecisionTreeNodeType,
        falseBranch: DecisionTreeNodeType? = nil
    ) {
        self.id = id
        self.condition = condition
        self.trueBranch = trueBranch
        self.falseBranch = falseBranch
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        let salt = DecisionTreeCFF.salt(
            context: context,
            token: "cond-node:\(id)",
            extraWords: [UInt64(id.utf8.reduce(0) { ($0 &* 131) &+ UInt64($1) })]
        )
        let seed: UInt32 = 0x3D9E41A7
        let entryState: UInt32 = 0x21
        let conditionState: UInt32 = 0x22
        let trueState: UInt32 = 0x23
        let falseState: UInt32 = 0x24
        let falseEvalState: UInt32 = 0x25

        var sink = CFFReturnSink<DecisionResult>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
        var conditionMatched = false

        while !sink.isResolved {
            switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
            case entryState:
                encodedState = CFFStateCodec.encode(conditionState, seed: seed, salt: salt)
            case conditionState:
                conditionMatched = condition.evaluate(context: context)
                encodedState = CFFStateCodec.encode(conditionMatched ? trueState : falseState, seed: seed, salt: salt)
            case trueState:
                sink.store(trueBranch.evaluate(context: context))
            case falseState:
                if falseBranch != nil {
                    encodedState = CFFStateCodec.encode(falseEvalState, seed: seed, salt: salt)
                } else {
                    sink.store(.next)
                }
            case falseEvalState:
                sink.store(falseBranch?.evaluate(context: context) ?? .next)
            default:
                sink.store(.next)
            }
        }

        return sink.resolve(or: .next)
    }
}

public struct ActionNode: Codable, Sendable {
    public let id: String
    public let action: RiskAction
    public let reason: String

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case action = "a"
        case reason = "r"
    }

    public init(id: String, action: RiskAction, reason: String) {
        self.id = id
        self.action = action
        self.reason = reason
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        .terminate(action: action, reason: reason)
    }
}

public struct ScoreActionThreshold: Codable, Sendable {
    public let threshold: Double
    public let action: RiskAction

    private enum CodingKeys: String, CodingKey {
        case threshold = "t"
        case action = "a"
    }

    public init(threshold: Double, action: RiskAction) {
        self.threshold = threshold
        self.action = action
    }
}

public struct ScoreActionNode: Codable, Sendable {
    public let id: String
    public let thresholds: [ScoreActionThreshold]
    public let defaultAction: RiskAction

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case thresholds = "th"
        case defaultAction = "da"
    }

    public init(id: String, thresholds: [(Double, RiskAction)], defaultAction: RiskAction) {
        self.id = id
        self.thresholds = thresholds
            .map { ScoreActionThreshold(threshold: $0.0, action: $0.1) }
            .sorted { $0.threshold < $1.threshold }
        self.defaultAction = defaultAction
    }

    public init(id: String, thresholds: [ScoreActionThreshold], defaultAction: RiskAction) {
        self.id = id
        self.thresholds = thresholds.sorted { $0.threshold < $1.threshold }
        self.defaultAction = defaultAction
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        let salt = DecisionTreeCFF.salt(
            context: context,
            token: "score-node:\(id)",
            extraWords: [UInt64(thresholds.count), UInt64(defaultAction.rawValue)]
        )
        let seed: UInt32 = 0x7B4E12CD
        let entryState: UInt32 = 0x31
        let scanState: UInt32 = 0x32
        let connectorState: UInt32 = 0x33
        let settleState: UInt32 = 0x34

        let invalidScoreResult = DecisionResult.terminate(action: .allow, reason: "Invalid non-finite score")
        var sink = CFFReturnSink<DecisionResult>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
        var index = 0

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: salt)

            if decodedState == entryState {
                if context.score.isFinite {
                    encodedState = CFFStateCodec.encode(scanState, seed: seed, salt: salt)
                } else {
                    sink.store(invalidScoreResult)
                }
            } else if decodedState == scanState {
                guard index < thresholds.count else {
                    sink.store(.terminate(action: defaultAction, reason: "Score \(context.score) meets highest threshold"))
                    continue
                }

                let item = thresholds[index]
                if context.score < item.threshold {
                    sink.store(.terminate(action: item.action, reason: "Score \(context.score) below threshold \(item.threshold)"))
                } else {
                    index += 1
                    encodedState = CFFStateCodec.encode(connectorState, seed: seed, salt: salt)
                }
            } else if decodedState == connectorState {
                let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? scanState : settleState
                encodedState = CFFStateCodec.encode(nextState, seed: seed, salt: salt)
            } else if decodedState == settleState {
                encodedState = CFFStateCodec.encode(scanState, seed: seed, salt: salt)
            } else {
                sink.store(invalidScoreResult)
            }
        }

        return sink.resolve(or: invalidScoreResult)
    }
}

public struct SequenceNode: Codable, Sendable {
    public let id: String
    public let children: [DecisionTreeNodeType]

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case children = "ch"
    }

    public init(id: String, children: [DecisionTreeNodeType]) {
        self.id = id
        self.children = children
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        for child in children {
            let result = child.evaluate(context: context)
            if case .next = result {
                continue
            }
            return result
        }
        return .next
    }
}

public struct ParallelNode: Codable, Sendable {
    public let id: String
    public let children: [DecisionTreeNodeType]

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case children = "ch"
    }

    public init(id: String, children: [DecisionTreeNodeType]) {
        self.id = id
        self.children = children
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        var actions: [RiskAction] = []
        var reasons: [String] = []
        for child in children {
            switch child.evaluate(context: context) {
            case .terminate(let action, let reason):
                actions.append(action)
                reasons.append(reason)
            case .next, .branch:
                break
            }
        }

        guard !actions.isEmpty else { return .next }
        let strictestAction = actions.max(by: { $0.severity < $1.severity }) ?? .allow
        return .terminate(action: strictestAction, reason: reasons.joined(separator: "; "))
    }
}

public indirect enum DecisionTreeNodeType: Codable, Sendable {
    case condition(ConditionNode)
    case action(ActionNode)
    case scoreAction(ScoreActionNode)
    case sequence(SequenceNode)
    case parallel(ParallelNode)

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        switch self {
        case .condition(let node): return node.evaluate(context: context)
        case .action(let node): return node.evaluate(context: context)
        case .scoreAction(let node): return node.evaluate(context: context)
        case .sequence(let node): return node.evaluate(context: context)
        case .parallel(let node): return node.evaluate(context: context)
        }
    }
}

public struct DecisionTree: Codable, Sendable {
    public let root: DecisionTreeNodeType
    public let name: String
    public let description: String?

    private enum CodingKeys: String, CodingKey {
        case root = "r"
        case name = "n"
        case description = "ds"
    }

    public init(name: String, root: DecisionTreeNodeType, description: String? = nil) {
        self.name = name
        self.root = root
        self.description = description
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        root.evaluate(context: context)
    }

    public func decide(context: EvaluationContext) -> RiskAction {
        let salt = DecisionTreeCFF.salt(context: context, token: "tree:\(name)")
        let evaluationSeed: UInt32 = 0x6F8C21B3
        let fallbackSeed: UInt32 = 0x29D44761
        let evaluateState: UInt32 = 0x41
        let terminalState: UInt32 = 0x42
        let fallbackPreludeState: UInt32 = 0x51
        let classifyState: UInt32 = 0x52
        let allowState: UInt32 = 0x53
        let challengeState: UInt32 = 0x54
        let stepUpState: UInt32 = 0x55
        let blockState: UInt32 = 0x56

        var sink = CFFReturnSink<RiskAction>()
        var evaluationResult: DecisionResult = .next
        var needsFallback = false
        var encodedState = CFFStateCodec.encode(evaluateState, seed: evaluationSeed, salt: salt)

        while !sink.isResolved && !needsFallback {
            let decodedState = CFFStateCodec.decode(encodedState, seed: evaluationSeed, salt: salt)

            if decodedState == evaluateState {
                evaluationResult = evaluate(context: context)
                encodedState = CFFStateCodec.encode(terminalState, seed: evaluationSeed, salt: salt)
            } else if decodedState == terminalState {
                switch evaluationResult {
                case .terminate(let action, _):
                    sink.store(action)
                case .next, .branch:
                    needsFallback = true
                }
            } else {
                sink.store(.block)
            }
        }

        if !sink.isResolved {
            var fallbackState = CFFStateCodec.encode(fallbackPreludeState, seed: fallbackSeed, salt: salt ^ 0x13579BDF)

            while !sink.isResolved {
                switch CFFStateCodec.decode(fallbackState, seed: fallbackSeed, salt: salt ^ 0x13579BDF) {
                case fallbackPreludeState:
                    if context.score.isFinite {
                        fallbackState = CFFStateCodec.encode(classifyState, seed: fallbackSeed, salt: salt ^ 0x13579BDF)
                    } else {
                        sink.store(.block)
                    }
                case classifyState:
                    let nextState: UInt32
                    if context.score >= context.policy.criticalThreshold {
                        nextState = blockState
                    } else if context.score >= context.policy.highThreshold {
                        nextState = stepUpState
                    } else if context.score >= context.policy.mediumThreshold {
                        nextState = challengeState
                    } else {
                        nextState = allowState
                    }
                    fallbackState = CFFStateCodec.encode(nextState, seed: fallbackSeed, salt: salt ^ 0x13579BDF)
                case allowState:
                    sink.store(.allow)
                case challengeState:
                    sink.store(.challenge)
                case stepUpState:
                    sink.store(.stepUpAuth)
                case blockState:
                    sink.store(.block)
                default:
                    sink.store(.block)
                }
            }
        }

        return sink.resolve(or: .block)
    }
}

private extension ConditionExpression {
    var isScoreRange: Bool {
        if case .scoreRange = self { return true }
        return false
    }

    var isScoreGreaterThanOrEqual: Bool {
        if case .scoreGreaterThanOrEqual = self { return true }
        return false
    }

    var isScoreLessThan: Bool {
        if case .scoreLessThan = self { return true }
        return false
    }

    var isSignalExists: Bool {
        if case .signalExists = self { return true }
        return false
    }

    var isSignalScore: Bool {
        if case .signalScore = self { return true }
        return false
    }

    var isCategoryScore: Bool {
        if case .categoryScore = self { return true }
        return false
    }

    var isCustom: Bool {
        if case .custom = self { return true }
        return false
    }

    var isJailbrokenExpression: Bool {
        if case .isJailbroken = self { return true }
        return false
    }

    var isVPNExpression: Bool {
        if case .isVPN = self { return true }
        return false
    }

    var isProxyExpression: Bool {
        if case .isProxy = self { return true }
        return false
    }
}

extension DecisionTree {
    public static let `default` = DecisionTree(
        name: "default_score_tree",
        root: .scoreAction(
            ScoreActionNode(
                id: "score_decision",
                thresholds: [
                    (30, .allow),
                    (55, .challenge),
                    (80, .stepUpAuth)
                ],
                defaultAction: .block
            )
        ),
        description: "默认基于分数的决策树"
    )

    public static let payment = DecisionTree(
        name: "payment_tree",
        root: .sequence(
            SequenceNode(
                id: "payment_sequence",
                children: [
                    .condition(
                        ConditionNode(
                            id: "check_jailbreak_vpn",
                            condition: .signalExists(ObfuscatedConstants.signalJailbreak),
                            trueBranch: .condition(
                                ConditionNode(
                                    id: "check_vpn",
                                    condition: .signalExists(ObfuscatedConstants.requiredSignalVpnActive),
                                    trueBranch: .action(ActionNode(id: "block_combo", action: .block, reason: "越狱设备使用VPN进行支付")),
                                    falseBranch: .action(ActionNode(id: "block_jailbreak_only", action: .block, reason: "越狱设备禁止支付"))
                                )
                            ),
                            falseBranch: .scoreAction(
                                ScoreActionNode(
                                    id: "payment_score_decision",
                                    thresholds: [
                                        (20, .allow),
                                        (45, .stepUpAuth)
                                    ],
                                    defaultAction: .block
                                )
                            )
                        )
                    )
                ]
            )
        ),
        description: "支付场景决策树，越狱设备直接拒绝"
    )

    public static let login = DecisionTree(
        name: "login_tree",
        root: .sequence(
            SequenceNode(
                id: "login_sequence",
                children: [
                    .condition(
                        ConditionNode(
                            id: "check_high_risk_behavior",
                            condition: .categoryScore(category: "behavior", greaterThan: 20),
                            trueBranch: .action(ActionNode(id: "challenge_behavior", action: .challenge, reason: "检测到高风险行为模式")),
                            falseBranch: .scoreAction(
                                ScoreActionNode(
                                    id: "login_score_decision",
                                    thresholds: [
                                        (35, .allow),
                                        (60, .challenge)
                                    ],
                                    defaultAction: .stepUpAuth
                                )
                            )
                        )
                    )
                ]
            )
        ),
        description: "登录场景决策树"
    )

    public static func tree(for scenario: RiskScenario) -> DecisionTree {
        switch scenario {
        case .default: return .default
        case .login: return .login
        case .register: return .default
        case .payment: return .payment
        case .accountChange: return .login
        case .sensitiveAction: return .payment
        case .apiAccess: return .default
        case .query: return .default
        }
    }
}
