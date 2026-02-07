import Foundation

// MARK: - Risk Types (Unified with Architecture Protocol)
//
// This file defines the unified risk types that align with the architecture's
// DecisionEngine protocol while preserving enhanced functionality.

// MARK: - Risk Scenario
/// 风险评估场景
/// 定义不同的业务场景，每个场景可以有不同的策略配置
@objc public enum RiskScenario: Int, Sendable, Codable, CaseIterable {
    /// 登录场景
    case login = 0
    /// 支付场景
    case payment = 1
    /// 注册场景
    case register = 2
    /// 查询场景
    case query = 3
    /// 默认场景
    case `default` = 4
    /// 账户变更场景
    case accountChange = 5
    /// 敏感操作场景
    case sensitiveAction = 6
    /// API 访问场景
    case apiAccess = 7

    /// 场景显示名称
    public var displayName: String {
        switch self {
        case .login: return "登录"
        case .payment: return "支付"
        case .register: return "注册"
        case .query: return "查询"
        case .default: return "默认"
        case .accountChange: return "账户变更"
        case .sensitiveAction: return "敏感操作"
        case .apiAccess: return "API访问"
        }
    }

    /// 场景唯一标识
    public var identifier: String {
        switch self {
        case .login: return "login"
        case .payment: return "payment"
        case .register: return "register"
        case .query: return "query"
        case .default: return "default"
        case .accountChange: return "account_change"
        case .sensitiveAction: return "sensitive_action"
        case .apiAccess: return "api_access"
        }
    }

    /// String 值（向后兼容）
    public var rawStringValue: String {
        return identifier
    }
}

// MARK: - Internal Risk Level (4-level for fine-grained control)
/// 内部风险等级（4级，更精细控制）
/// 对外API映射为协议定义的3级
public enum InternalRiskLevel: String, Codable, Sendable {
    /// 低风险：正常用户，允许通过
    case low = "low"
    /// 中风险：需要额外验证或监控
    case medium = "medium"
    /// 高风险：需要强验证或限制操作
    case high = "high"
    /// 严重风险：直接拒绝
    case critical = "critical"

    /// 数值表示，便于比较和排序
    public var numericValue: Int {
        switch self {
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    /// 从分数计算风险等级
    public static func from(score: Double) -> InternalRiskLevel {
        switch score {
        case 0..<30: return .low
        case 30..<55: return .medium
        case 55..<80: return .high
        default: return .critical
        }
    }

    /// 映射到公开API的3级风险等级
    public func toPublicRiskLevel() -> PublicRiskLevel {
        switch self {
        case .low: return .low
        case .medium: return .medium
        case .high, .critical: return .high  // 合并 high 和 critical
        }
    }
}

// MARK: - Public Risk Level (3-level per protocol)
/// 公开风险等级（3级，符合协议定义）
@objc public enum PublicRiskLevel: Int, Sendable, Codable, CaseIterable {
    /// 低风险 - 可以直接通过
    case low = 0
    /// 中风险 - 需要额外验证或挑战
    case medium = 1
    /// 高风险 - 应该拒绝
    case high = 2

    /// 显示名称
    public var displayName: String {
        switch self {
        case .low: return "低风险"
        case .medium: return "中风险"
        case .high: return "高风险"
        }
    }

    /// 颜色值（用于 UI 显示）
    public var colorValue: Int {
        switch self {
        case .low: return 0x4CAF50    // Green
        case .medium: return 0xFF9800  // Orange
        case .high: return 0xF44336    // Red
        }
    }
}

// MARK: - Risk Action
/// 风险处理动作
/// 定义针对不同风险级别的处理建议
@objc public enum RiskAction: Int, Sendable, Codable, CaseIterable {
    /// 允许 - 直接放行
    case allow = 0
    /// 挑战 - 需要额外验证（如验证码、人脸识别）
    case challenge = 1
    /// 升级认证 - 需要更强的验证（如短信、生物识别）
    case stepUpAuth = 2
    /// 拒绝 - 直接阻止请求
    case block = 3

    /// 显示名称
    public var displayName: String {
        switch self {
        case .allow: return "允许"
        case .challenge: return "挑战"
        case .stepUpAuth: return "升级认证"
        case .block: return "拒绝"
        }
    }

    /// 动作的严格程度，用于比较
    public var severity: Int {
        switch self {
        case .allow: return 0
        case .challenge: return 1
        case .stepUpAuth: return 2
        case .block: return 3
        }
    }

    /// 映射到公开API的3种动作
    public func toPublicRiskAction() -> PublicRiskAction {
        switch self {
        case .allow: return .allow
        case .challenge, .stepUpAuth: return .challenge  // 合并 challenge 和 stepUpAuth
        case .block: return .block
        }
    }
}

// MARK: - Public Risk Action (3-type per protocol)
/// 公开风险动作（3种，符合协议定义）
@objc public enum PublicRiskAction: Int, Sendable, Codable, CaseIterable {
    /// 允许 - 直接放行
    case allow = 0
    /// 挑战 - 需要额外验证（如验证码、人脸识别）
    case challenge = 1
    /// 拒绝 - 直接阻止请求
    case block = 2

    /// 显示名称
    public var displayName: String {
        switch self {
        case .allow: return "允许"
        case .challenge: return "挑战"
        case .block: return "拒绝"
        }
    }
}

// MARK: - Type Aliases for Backward Compatibility
/// 类型别名，保持向后兼容
public typealias DetectionScenario = RiskScenario
public typealias RiskLevel = InternalRiskLevel
