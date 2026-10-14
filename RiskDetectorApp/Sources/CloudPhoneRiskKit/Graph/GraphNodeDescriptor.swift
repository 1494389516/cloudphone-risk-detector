import Foundation

// MARK: - 图节点描述符
///
/// 客户端声明的关联提示；SHA256 不是隐私保证，也不是可信设备实体。
/// 用于图风控联动：端侧生产特征 → 服务端图计算 → 反哺决策。
public struct GraphNodeDescriptor: Codable, Sendable {
    /// Legacy exact-match/churn hint; not hardware similarity or resolved device identity.
    public var hwProfileHash: String

    /// WiFi BSSID 哈希（如可获取，否则省略；iOS 沙箱限制下通常不可用）
    public var bssidHash: String?

    /// 应用安装列表哈希（如可获取，否则省略；iOS 隐私限制下通常不可用）
    public var appListHash: String?

    /// Installation correlation hint, separate from non-unique similarity attributes.
    public var installationKey: String?
    public var hardwareAttributes: [String: String]?

    private enum CodingKeys: String, CodingKey {
        case installationKey = "ik"
        case hardwareAttributes = "ha"
        case hwProfileHash = "hp"
        case bssidHash = "bh"
        case appListHash = "al"
    }

    public init(
        hwProfileHash: String,
        bssidHash: String? = nil,
        appListHash: String? = nil,
        installationKey: String? = nil,
        hardwareAttributes: [String: String]? = nil
    ) {
        self.installationKey = installationKey
        self.hardwareAttributes = hardwareAttributes
        self.hwProfileHash = hwProfileHash
        self.bssidHash = bssidHash
        self.appListHash = appListHash
    }
}
