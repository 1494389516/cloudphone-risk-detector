import XCTest
@testable import CloudPhoneRiskKit

/// DecisionTree 边界情况补充测试
final class DecisionTreeEdgeCaseTests: XCTestCase {

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

    // MARK: - 嵌套条件节点

    func testDeeplyNestedConditionNodes() {
        // 3 层嵌套条件
        let tree = DecisionTree(
            name: "nested_tree",
            root: .condition(ConditionNode(
                id: "level1",
                condition: .scoreGreaterThanOrEqual(10),
                trueBranch: .condition(ConditionNode(
                    id: "level2",
                    condition: .scoreGreaterThanOrEqual(50),
                    trueBranch: .condition(ConditionNode(
                        id: "level3",
                        condition: .isJailbroken,
                        trueBranch: .action(ActionNode(id: "block", action: .block, reason: "deep_jb")),
                        falseBranch: .action(ActionNode(id: "step_up", action: .stepUpAuth, reason: "deep_high"))
                    )),
                    falseBranch: .action(ActionNode(id: "challenge", action: .challenge, reason: "deep_medium"))
                )),
                falseBranch: .action(ActionNode(id: "allow", action: .allow, reason: "deep_low"))
            ))
        )

        // score < 10 → allow
        let ctx1 = makeEvalContext(score: 5)
        if case .terminate(let action, _) = tree.evaluate(context: ctx1) {
            XCTAssertEqual(action, .allow)
        } else { XCTFail("Expected allow") }

        // 10 <= score < 50 → challenge
        let ctx2 = makeEvalContext(score: 30)
        if case .terminate(let action, _) = tree.evaluate(context: ctx2) {
            XCTAssertEqual(action, .challenge)
        } else { XCTFail("Expected challenge") }

        // score >= 50, not jailbroken → stepUpAuth
        let ctx3 = makeEvalContext(score: 70, isJailbroken: false)
        if case .terminate(let action, _) = tree.evaluate(context: ctx3) {
            XCTAssertEqual(action, .stepUpAuth)
        } else { XCTFail("Expected stepUpAuth") }

        // score >= 50, jailbroken → block
        let ctx4 = makeEvalContext(score: 70, isJailbroken: true)
        if case .terminate(let action, _) = tree.evaluate(context: ctx4) {
            XCTAssertEqual(action, .block)
        } else { XCTFail("Expected block") }
    }

    // MARK: - ParallelNode 边界情况

    func testParallelNodeEmptyChildren() {
        let par = ParallelNode(id: "empty_par", children: [])
        let result = par.evaluate(context: makeEvalContext(score: 50))
        if case .next = result {} else {
            XCTFail("Empty parallel node should return .next")
        }
    }

    func testParallelNodeAllSameAction() {
        let par = ParallelNode(id: "all_challenge", children: [
            .action(ActionNode(id: "a1", action: .challenge, reason: "r1")),
            .action(ActionNode(id: "a2", action: .challenge, reason: "r2")),
            .action(ActionNode(id: "a3", action: .challenge, reason: "r3")),
        ])
        let result = par.evaluate(context: makeEvalContext(score: 50))
        if case .terminate(let action, let reason) = result {
            XCTAssertEqual(action, .challenge)
            XCTAssertTrue(reason.contains(";"), "Should join multiple reasons")
        } else { XCTFail("Expected challenge") }
    }

    func testParallelNodeMixedNextAndTerminate() {
        let par = ParallelNode(id: "mixed", children: [
            .condition(ConditionNode(
                id: "false_cond", condition: .isJailbroken,
                trueBranch: .action(ActionNode(id: "block", action: .block, reason: "jb"))
                // no false branch → returns .next
            )),
            .action(ActionNode(id: "challenge", action: .challenge, reason: "always")),
        ])
        let result = par.evaluate(context: makeEvalContext(score: 50, isJailbroken: false))
        if case .terminate(let action, _) = result {
            XCTAssertEqual(action, .challenge, "Should pick the only terminal action")
        } else { XCTFail("Expected challenge") }
    }

    // MARK: - SequenceNode 边界情况

    func testSequenceNodeEmptyChildren() {
        let seq = SequenceNode(id: "empty_seq", children: [])
        let result = seq.evaluate(context: makeEvalContext(score: 50))
        if case .next = result {} else {
            XCTFail("Empty sequence should return .next")
        }
    }

    func testSequenceNodeAllNext() {
        let seq = SequenceNode(id: "all_next", children: [
            .condition(ConditionNode(
                id: "c1", condition: .isJailbroken,
                trueBranch: .action(ActionNode(id: "a1", action: .block, reason: "jb"))
            )),
            .condition(ConditionNode(
                id: "c2", condition: .isVPN,
                trueBranch: .action(ActionNode(id: "a2", action: .challenge, reason: "vpn"))
            )),
        ])
        let result = seq.evaluate(context: makeEvalContext(score: 50, isJailbroken: false, vpnActive: false))
        if case .next = result {} else {
            XCTFail("All conditions false with no false branches should return .next")
        }
    }

    // MARK: - ScoreActionNode 边界情况

    func testScoreActionNodeExactThresholdBoundary() {
        let node = ScoreActionNode(
            id: "boundary",
            thresholds: [(30, .allow), (55, .challenge), (80, .stepUpAuth)],
            defaultAction: .block
        )
        // Exactly at threshold 30 → should go to next tier (challenge)
        let result30 = node.evaluate(context: makeEvalContext(score: 30))
        if case .terminate(let action, _) = result30 {
            XCTAssertEqual(action, .challenge, "Score exactly at threshold should move to next action")
        } else { XCTFail("Expected challenge") }

        // Score at 0 → below first threshold → allow
        let result0 = node.evaluate(context: makeEvalContext(score: 0))
        if case .terminate(let action, _) = result0 {
            XCTAssertEqual(action, .allow)
        } else { XCTFail("Expected allow") }
    }

    func testScoreActionNodeNaNReturnsAllow() {
        let node = ScoreActionNode(
            id: "nan_test",
            thresholds: [(30, .allow), (80, .block)],
            defaultAction: .block
        )
        let result = node.evaluate(context: makeEvalContext(score: Double.nan))
        if case .terminate(let action, _) = result {
            // ScoreActionNode 的 isFinite guard 返回 .allow
            XCTAssertEqual(action, .allow,
                "ScoreActionNode should return allow for NaN (invalid non-finite score)")
        } else { XCTFail("Expected terminate") }
    }

    func testScoreActionNodeSingleThreshold() {
        let node = ScoreActionNode(
            id: "single",
            thresholds: [(50, .allow)],
            defaultAction: .block
        )
        let resultLow = node.evaluate(context: makeEvalContext(score: 30))
        if case .terminate(let action, _) = resultLow {
            XCTAssertEqual(action, .allow)
        } else { XCTFail("Expected allow") }

        let resultHigh = node.evaluate(context: makeEvalContext(score: 60))
        if case .terminate(let action, _) = resultHigh {
            XCTAssertEqual(action, .block)
        } else { XCTFail("Expected block") }
    }

    // MARK: - DecisionTree.decide 场景策略

    func testDecidePaymentTreeJailbrokenVPN() {
        let tree = DecisionTree.payment
        let policy = ScenarioPolicy(mediumThreshold: 20, highThreshold: 45, criticalThreshold: 70)
        let ctx = makeEvalContext(
            score: 90,
            signals: [
                RiskSignal(id: "jailbreak", category: "jailbreak", score: 60, evidence: [:]),
                RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]),
            ],
            isJailbroken: true,
            vpnActive: true,
            policy: policy
        )
        XCTAssertEqual(tree.decide(context: ctx), .block,
            "Jailbroken + VPN in payment should block")
    }

    func testDecidePaymentTreeCleanDevice() {
        let tree = DecisionTree.payment
        let policy = ScenarioPolicy(mediumThreshold: 20, highThreshold: 45, criticalThreshold: 70)
        let ctx = makeEvalContext(score: 10, isJailbroken: false, policy: policy)
        XCTAssertEqual(tree.decide(context: ctx), .allow,
            "Clean device with low score should allow in payment")
    }

    func testDecideLoginTreeHighBehaviorScore() {
        let tree = DecisionTree.login
        let policy = ScenarioPolicy(mediumThreshold: 35, highThreshold: 60, criticalThreshold: 85)
        let ctx = makeEvalContext(
            score: 15,
            signals: [
                RiskSignal(id: "touch_spread_low", category: "behavior", score: 12, evidence: [:]),
                RiskSignal(id: "touch_interval_regular", category: "behavior", score: 10, evidence: [:]),
            ],
            policy: policy
        )
        XCTAssertEqual(tree.decide(context: ctx), .challenge,
            "High behavior score in login should trigger challenge")
    }

    // MARK: - Codable 完整性

    func testPaymentTreeCodableRoundtrip() throws {
        let tree = DecisionTree.payment
        let data = try JSONEncoder().encode(tree)
        let decoded = try JSONDecoder().decode(DecisionTree.self, from: data)
        XCTAssertEqual(decoded.name, tree.name)
        XCTAssertEqual(decoded.description, tree.description)

        // 验证解码后的树行为一致
        let policy = ScenarioPolicy(mediumThreshold: 20, highThreshold: 45, criticalThreshold: 70)
        let ctx = makeEvalContext(score: 10, isJailbroken: false, policy: policy)
        XCTAssertEqual(decoded.decide(context: ctx), tree.decide(context: ctx))
    }

    func testLoginTreeCodableRoundtrip() throws {
        let tree = DecisionTree.login
        let data = try JSONEncoder().encode(tree)
        let decoded = try JSONDecoder().decode(DecisionTree.self, from: data)
        XCTAssertEqual(decoded.name, tree.name)
    }
}
