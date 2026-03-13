import Foundation

// MARK: - 图节点描述符
///
/// 标准化为服务端可直接入图的格式，所有哈希为单向 SHA256，不可逆推原始值。
/// 用于图风控联动：端侧生产特征 → 服务端图计算 → 反哺决策。
public struct GraphNodeDescriptor: Codable, Sendable {
    /// 设备指纹哈希：SHA256(deviceID + hardwareMachine + model)
    public var hwProfileHash: String

    /// IP 哈希（从 context 或 ServerSignals 获取）
    public var ipHash: String?

    /// ASN（自治系统号，明文用于图边构建；服务端可再哈希）
    public var asn: String?

    /// 账号 ID 哈希（已有 bindAccount）
    public var accountIdHash: String?

    /// WiFi BSSID 哈希（如可获取，否则省略；iOS 沙箱限制下通常不可用）
    public var bssidHash: String?

    /// 应用安装列表哈希（如可获取，否则省略；iOS 隐私限制下通常不可用）
    public var appListHash: String?

    public init(
        hwProfileHash: String,
        ipHash: String? = nil,
        asn: String? = nil,
        accountIdHash: String? = nil,
        bssidHash: String? = nil,
        appListHash: String? = nil
    ) {
        self.hwProfileHash = hwProfileHash
        self.ipHash = ipHash
        self.asn = asn
        self.accountIdHash = accountIdHash
        self.bssidHash = bssidHash
        self.appListHash = appListHash
    }
}
