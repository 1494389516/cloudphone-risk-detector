import Foundation

// MARK: - Actor-based Risk Evaluation State
//
// 提供线程安全的状态隔离，替代 NSLock 手动管理。
// 新代码路径可通过此 actor 与 SDK 交互，保证状态访问不会出现数据竞争。
//
// 使用示例：
//   let result = await RiskEvaluationActor.shared.evaluate(config: .default, scenario: .payment)

/// Actor-based 风险评估状态容器 — 提供编译期线程安全保证。
///
/// 与 `CPRiskKit` 的 NSLock 方案共存，新增的 async/await 调用路径优先走此 actor。
/// 内部代理到 `CPRiskKit.shared` 的同步方法，actor 隔离保证同一时间只有一个评估任务修改状态。
@available(iOS 13.0, macOS 10.15, *)
public actor RiskEvaluationActor {

    public static let shared = RiskEvaluationActor()

    // MARK: - 评估状态

    /// 上一次评估结果缓存
    private var lastVerdict: CPRiskReport?

    /// 上一次评估时间
    private var lastEvaluationTime: Date?

    /// 连续评估次数（用于限流）
    private var consecutiveEvaluations: Int = 0

    /// 限流冷却期（秒）
    private let rateLimitCooldown: TimeInterval = 0.5

    // MARK: - 评估入口

    /// 执行风险评估（actor-isolated，编译期线程安全）
    public func evaluate(
        config: CPRiskConfig = .default,
        scenario: RiskScenario = .default
    ) -> CPRiskReport {
        // 限流检查：连续快速调用超过阈值时返回缓存结果
        if let lastTime = lastEvaluationTime,
           Date().timeIntervalSince(lastTime) < rateLimitCooldown {
            consecutiveEvaluations += 1
            if consecutiveEvaluations > 10 {
                Logger.warn("RiskEvaluationActor: rate limited — \(consecutiveEvaluations) rapid evaluations")
                if let cached = lastVerdict {
                    return cached
                }
            }
        } else {
            consecutiveEvaluations = 0
        }

        lastEvaluationTime = Date()

        // 代理到 CPRiskKit 的同步方法（CPRiskKit 内部有自己的锁保护）
        let report = CPRiskKit.shared.evaluate(config: config, scenario: scenario)
        lastVerdict = report
        return report
    }

    /// 获取上一次评估结果（如果有）
    public func lastResult() -> CPRiskReport? {
        lastVerdict
    }

    /// 重置评估状态
    public func reset() {
        lastVerdict = nil
        lastEvaluationTime = nil
        consecutiveEvaluations = 0
    }
}
