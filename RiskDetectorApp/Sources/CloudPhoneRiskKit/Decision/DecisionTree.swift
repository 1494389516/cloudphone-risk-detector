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
        switch self {
        case .scoreRange(let min, let max):
            return context.score >= min && context.score < max
        case .scoreGreaterThanOrEqual(let value):
            return context.score >= value
        case .scoreLessThan(let value):
            return context.score < value
        case .signalExists(let id):
            return context.hasSignal(id)
        case .signalScore(let id, let gt):
            return context.signalScore(id) > gt
        case .categoryScore(let cat, let gt):
            return context.categoryScore(cat) > gt
        case .isJailbroken:
            return context.riskContext.jailbreak.isJailbroken
        case .isVPN:
            return context.riskContext.network.isVPNActive
        case .isProxy:
            return context.riskContext.network.proxyEnabled
        case .custom:
            return false
        }
    }
}

public struct ConditionNode: Codable, Sendable {
    public let id: String
    public let condition: ConditionExpression
    public let trueBranch: DecisionTreeNodeType
    public let falseBranch: DecisionTreeNodeType?

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
        if condition.evaluate(context: context) {
            return trueBranch.evaluate(context: context)
        }
        if let falseBranch {
            return falseBranch.evaluate(context: context)
        }
        return .next
    }
}

public struct ActionNode: Codable, Sendable {
    public let id: String
    public let action: RiskAction
    public let reason: String

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

    public init(threshold: Double, action: RiskAction) {
        self.threshold = threshold
        self.action = action
    }
}

public struct ScoreActionNode: Codable, Sendable {
    public let id: String
    public let thresholds: [ScoreActionThreshold]
    public let defaultAction: RiskAction

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
        for item in thresholds where context.score < item.threshold {
            return .terminate(action: item.action, reason: "Score \(context.score) below threshold \(item.threshold)")
        }
        return .terminate(action: defaultAction, reason: "Score \(context.score) meets highest threshold")
    }
}

public struct SequenceNode: Codable, Sendable {
    public let id: String
    public let children: [DecisionTreeNodeType]

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

    public init(name: String, root: DecisionTreeNodeType, description: String? = nil) {
        self.name = name
        self.root = root
        self.description = description
    }

    public func evaluate(context: EvaluationContext) -> DecisionResult {
        root.evaluate(context: context)
    }

    public func decide(context: EvaluationContext) -> RiskAction {
        switch evaluate(context: context) {
        case .next, .branch:
            return .allow
        case .terminate(let action, _):
            return action
        }
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
                            condition: .signalExists("jailbreak"),
                            trueBranch: .condition(
                                ConditionNode(
                                    id: "check_vpn",
                                    condition: .signalExists("vpn_active"),
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
