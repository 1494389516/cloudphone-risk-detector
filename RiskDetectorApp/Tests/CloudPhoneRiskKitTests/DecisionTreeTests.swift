import XCTest
@testable import CloudPhoneRiskKit

final class DecisionTreeTests: XCTestCase {

    private func makeEvalContext(
        score: Double,
        signals: [RiskSignal] = [],
        scenario: RiskScenario = .default,
        isJailbroken: Bool = false,
        vpnActive: Bool = false,
        proxyEnabled: Bool = false,
        policy: ScenarioPolicy = .general
    ) -> EvaluationContext {
        EvaluationContext(
            score: score,
            signals: signals,
            scenario: scenario,
            riskContext: TestFixtures.makeRiskContext(
                isJailbroken: isJailbroken,
                vpnActive: vpnActive,
                proxyEnabled: proxyEnabled
            ),
            policy: policy
        )
    }

    // MARK: - ConditionExpression

    func testScoreRangeCondition() {
        let cond = ConditionExpression.scoreRange(min: 30, max: 60)
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 20)))
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 30)))
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 45)))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 60)))
    }

    func testScoreGreaterThanOrEqual() {
        let cond = ConditionExpression.scoreGreaterThanOrEqual(50)
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 49.9)))
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 50)))
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 100)))
    }

    func testScoreLessThan() {
        let cond = ConditionExpression.scoreLessThan(30)
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 29)))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 30)))
    }

    func testSignalExistsCondition() {
        let signal = RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:])
        let cond = ConditionExpression.signalExists("vpn_active")
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 0, signals: [signal])))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 0, signals: [])))
    }

    func testIsJailbrokenCondition() {
        let cond = ConditionExpression.isJailbroken
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 0, isJailbroken: true)))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 0, isJailbroken: false)))
    }

    func testIsVPNCondition() {
        let cond = ConditionExpression.isVPN
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 0, vpnActive: true)))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 0, vpnActive: false)))
    }

    func testIsProxyCondition() {
        let cond = ConditionExpression.isProxy
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 0, proxyEnabled: true)))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 0, proxyEnabled: false)))
    }

    func testSignalScoreCondition() {
        let signal = RiskSignal(id: "test_signal", category: "test", score: 15, evidence: [:])
        let cond = ConditionExpression.signalScore(id: "test_signal", greaterThan: 10)
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 0, signals: [signal])))
        let condHigh = ConditionExpression.signalScore(id: "test_signal", greaterThan: 20)
        XCTAssertFalse(condHigh.evaluate(context: makeEvalContext(score: 0, signals: [signal])))
    }

    func testCategoryScoreCondition() {
        let signals = [
            RiskSignal(id: "a", category: "behavior", score: 8, evidence: [:]),
            RiskSignal(id: "b", category: "behavior", score: 12, evidence: [:]),
        ]
        let cond = ConditionExpression.categoryScore(category: "behavior", greaterThan: 15)
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 0, signals: signals)))
    }

    func testCustomConditionUnregisteredReturnsFalse() {
#if DEBUG
        ConditionExpression.unsealCustomEvaluatorsForTesting()
#endif
        ConditionExpression.unregisterCustomEvaluator(id: "unregistered_id")
        let cond = ConditionExpression.custom("unregistered_id")
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 100)))
    }

    func testCustomConditionWithRegisteredEvaluator() {
#if DEBUG
        ConditionExpression.unsealCustomEvaluatorsForTesting()
#endif
        let id = "high_score_and_vpn"
        ConditionExpression.registerCustomEvaluator(id: id) { ctx in
            ctx.score >= 80 && ctx.hasSignal("vpn_active")
        }
        defer { ConditionExpression.unregisterCustomEvaluator(id: id) }

        let cond = ConditionExpression.custom(id)
        let vpnSignal = RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:])

        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 50, signals: [vpnSignal])))
        XCTAssertFalse(cond.evaluate(context: makeEvalContext(score: 90, signals: [])))
        XCTAssertTrue(cond.evaluate(context: makeEvalContext(score: 90, signals: [vpnSignal])))
    }

    // MARK: - ActionNode

    func testActionNodeTerminates() {
        let node = ActionNode(id: "block_it", action: .block, reason: "test reason")
        let result = node.evaluate(context: makeEvalContext(score: 50))
        if case .terminate(let action, let reason) = result {
            XCTAssertEqual(action, .block)
            XCTAssertEqual(reason, "test reason")
        } else {
            XCTFail("Expected terminate result")
        }
    }

    // MARK: - ConditionNode

    func testConditionNodeTrueBranch() {
        let node = ConditionNode(
            id: "check_jb",
            condition: .isJailbroken,
            trueBranch: .action(ActionNode(id: "block", action: .block, reason: "jailbroken")),
            falseBranch: .action(ActionNode(id: "allow", action: .allow, reason: "clean"))
        )
        let result = node.evaluate(context: makeEvalContext(score: 0, isJailbroken: true))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .block)
        } else {
            XCTFail("Expected block")
        }
    }

    func testConditionNodeFalseBranch() {
        let node = ConditionNode(
            id: "check_jb",
            condition: .isJailbroken,
            trueBranch: .action(ActionNode(id: "block", action: .block, reason: "jailbroken")),
            falseBranch: .action(ActionNode(id: "allow", action: .allow, reason: "clean"))
        )
        let result = node.evaluate(context: makeEvalContext(score: 0, isJailbroken: false))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .allow)
        } else {
            XCTFail("Expected allow")
        }
    }

    func testConditionNodeNoFalseBranchReturnsNext() {
        let node = ConditionNode(
            id: "check_jb",
            condition: .isJailbroken,
            trueBranch: .action(ActionNode(id: "block", action: .block, reason: "jailbroken"))
        )
        let result = node.evaluate(context: makeEvalContext(score: 0, isJailbroken: false))
        if case .next = result {} else {
            XCTFail("Expected .next when condition is false and no false branch")
        }
    }

    // MARK: - ScoreActionNode

    func testScoreActionNodeLowScore() {
        let node = ScoreActionNode(
            id: "score_check",
            thresholds: [(30, .allow), (55, .challenge), (80, .stepUpAuth)],
            defaultAction: .block
        )
        let result = node.evaluate(context: makeEvalContext(score: 10))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .allow)
        } else {
            XCTFail("Expected allow for low score")
        }
    }

    func testScoreActionNodeMidScore() {
        let node = ScoreActionNode(
            id: "score_check",
            thresholds: [(30, .allow), (55, .challenge), (80, .stepUpAuth)],
            defaultAction: .block
        )
        let result = node.evaluate(context: makeEvalContext(score: 40))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .challenge)
        } else {
            XCTFail("Expected challenge for mid score")
        }
    }

    func testScoreActionNodeHighScore() {
        let node = ScoreActionNode(
            id: "score_check",
            thresholds: [(30, .allow), (55, .challenge), (80, .stepUpAuth)],
            defaultAction: .block
        )
        let result = node.evaluate(context: makeEvalContext(score: 90))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .block)
        } else {
            XCTFail("Expected block for high score")
        }
    }

    // MARK: - SequenceNode

    func testSequenceNodeStopsAtFirstTerminate() {
        let seq = SequenceNode(id: "seq", children: [
            .condition(ConditionNode(
                id: "c1", condition: .scoreLessThan(20),
                trueBranch: .action(ActionNode(id: "a1", action: .allow, reason: "low"))
            )),
            .action(ActionNode(id: "a2", action: .block, reason: "fallback")),
        ])
        let result = seq.evaluate(context: makeEvalContext(score: 10))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .allow)
        } else {
            XCTFail("Expected allow (first match)")
        }
    }

    func testSequenceNodeContinuesToNext() {
        let seq = SequenceNode(id: "seq", children: [
            .condition(ConditionNode(
                id: "c1", condition: .scoreLessThan(20),
                trueBranch: .action(ActionNode(id: "a1", action: .allow, reason: "low"))
            )),
            .action(ActionNode(id: "a2", action: .block, reason: "fallback")),
        ])
        let result = seq.evaluate(context: makeEvalContext(score: 50))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .block)
        } else {
            XCTFail("Expected block (fallback)")
        }
    }

    // MARK: - ParallelNode

    func testParallelNodePicksStrictestAction() {
        let par = ParallelNode(id: "par", children: [
            .action(ActionNode(id: "a1", action: .allow, reason: "ok")),
            .action(ActionNode(id: "a2", action: .challenge, reason: "suspect")),
            .action(ActionNode(id: "a3", action: .block, reason: "bad")),
        ])
        let result = par.evaluate(context: makeEvalContext(score: 50))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .block)
        } else {
            XCTFail("Expected strictest action (block)")
        }
    }

    func testParallelNodeReturnsNextIfAllNext() {
        let par = ParallelNode(id: "par", children: [
            .condition(ConditionNode(
                id: "c1", condition: .isJailbroken,
                trueBranch: .action(ActionNode(id: "a1", action: .block, reason: "jb"))
            )),
        ])
        let result = par.evaluate(context: makeEvalContext(score: 0, isJailbroken: false))
        if case .next = result {} else {
            XCTFail("Expected .next")
        }
    }

    // MARK: - DecisionTree

    func testDecisionTreeDecideWithFallbackScoring() {
        let tree = DecisionTree(
            name: "empty_tree",
            root: .condition(ConditionNode(
                id: "always_false", condition: .custom("never"),
                trueBranch: .action(ActionNode(id: "never", action: .block, reason: "never"))
            ))
        )
        let policy = ScenarioPolicy(mediumThreshold: 30, highThreshold: 55, criticalThreshold: 80)

        let ctx1 = makeEvalContext(score: 10, policy: policy)
        XCTAssertEqual(tree.decide(context: ctx1), .allow)

        let ctx2 = makeEvalContext(score: 40, policy: policy)
        XCTAssertEqual(tree.decide(context: ctx2), .challenge)

        let ctx3 = makeEvalContext(score: 60, policy: policy)
        XCTAssertEqual(tree.decide(context: ctx3), .stepUpAuth)

        let ctx4 = makeEvalContext(score: 85, policy: policy)
        XCTAssertEqual(tree.decide(context: ctx4), .block)
    }

    func testDefaultTreePreset() {
        let tree = DecisionTree.default
        XCTAssertEqual(tree.name, "default_score_tree")
    }

    func testTreeForScenarioMapping() {
        XCTAssertEqual(DecisionTree.tree(for: .default).name, "default_score_tree")
        XCTAssertEqual(DecisionTree.tree(for: .login).name, "login_tree")
        XCTAssertEqual(DecisionTree.tree(for: .payment).name, "payment_tree")
        XCTAssertEqual(DecisionTree.tree(for: .register).name, "default_score_tree")
        XCTAssertEqual(DecisionTree.tree(for: .query).name, "default_score_tree")
    }

    // MARK: - EvaluationContext Helpers

    func testHasSignalById() {
        let ctx = makeEvalContext(score: 0, signals: [
            RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]),
        ])
        XCTAssertTrue(ctx.hasSignal("vpn_active"))
        XCTAssertFalse(ctx.hasSignal("nonexistent"))
    }

    func testHasSignalByCategory() {
        let ctx = makeEvalContext(score: 0, signals: [
            RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]),
        ])
        XCTAssertTrue(ctx.hasSignal(category: "network"))
        XCTAssertFalse(ctx.hasSignal(category: "jailbreak"))
    }

    func testSignalScoreRetrieval() {
        let ctx = makeEvalContext(score: 0, signals: [
            RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]),
        ])
        XCTAssertEqual(ctx.signalScore("vpn_active"), 10)
        XCTAssertEqual(ctx.signalScore("nonexistent"), 0)
    }

    func testCategoryScoreAggregation() {
        let ctx = makeEvalContext(score: 0, signals: [
            RiskSignal(id: "a", category: "behavior", score: 5, evidence: [:]),
            RiskSignal(id: "b", category: "behavior", score: 8, evidence: [:]),
            RiskSignal(id: "c", category: "network", score: 10, evidence: [:]),
        ])
        XCTAssertEqual(ctx.categoryScore("behavior"), 13)
        XCTAssertEqual(ctx.categoryScore("network"), 10)
        XCTAssertEqual(ctx.categoryScore("other"), 0)
    }

    // MARK: - Codable

    func testDecisionTreeCodable() throws {
        let tree = DecisionTree.default
        let data = try JSONEncoder().encode(tree)
        let decoded = try JSONDecoder().decode(DecisionTree.self, from: data)
        XCTAssertEqual(decoded.name, tree.name)
    }
}
