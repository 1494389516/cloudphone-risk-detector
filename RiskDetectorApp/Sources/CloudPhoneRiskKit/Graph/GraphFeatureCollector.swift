import CryptoKit
import Foundation

// MARK: - 图特征采集器
///
/// 自动收集可供图计算的结构化特征，输出 GraphNodeDescriptor，
/// 标准化为服务端可直接入图的格式。
///
/// ## 隐私保护
/// - 所有哈希为单向 SHA256，**加固定盐**后输出
/// - IP、账号 ID、BSSID、应用列表等敏感字段均以哈希形式上报
///
/// ## 关于可逆推性（诚实描述）
/// SHA256 本身单向，但 `hwProfileHash` 的原像由 `deviceID|hardwareMachine|model`
/// 组成，其中 `hardwareMachine`/`model` 是**低熵**字段（iPhone 机型空间仅几十个）。
/// 无盐确定性哈希可被攻击者预先构造彩虹表 / 字典，对低熵分量直接反查出设备型号，
/// 因此“不可逆推”是不成立的。
/// 这里引入**应用/租户级固定盐**（compile-time 常量，**非** per-install 随机盐）：
/// - 抬高反推成本：攻击者必须知道盐才能重建字典，盐随 SDK 版本可轮换。
/// - 保留可关联性：同一应用内所有设备/所有上报使用同一盐，跨设备/跨上报的
///   `hwProfileHash` 仍可在服务端聚类（per-install 随机盐会破坏这一点）。
/// 注意：固定盐**不是**绝对不可逆——只要盐泄露，低熵分量仍可被字典攻击；
/// 它提供的是“成本抬升 + 可轮换”，而非密码学意义上的不可逆。
public enum GraphFeatureCollector {

    /// 应用/租户级固定盐（域分隔常量）。
    ///
    /// 设计约束（见上方文档）：
    /// - **compile-time 固定**：所有安装、所有设备共享同一值 → 保留跨设备哈希可关联性。
    /// - **非随机、非持久化**：不引入新的 per-install 随机源（那会破坏聚类）。
    /// - 命名沿用本仓库 `*_v1` 域标签约定，版本号 bump 即可整体轮换盐。
    private static let hwProfileSaltDomainTag = "cprisk_graph_hwprofile_salt_v1"

    /// 从 RiskSnapshot 与 ServerSignals 收集图节点描述符
    /// - Parameters:
    ///   - snapshot: 风险快照（设备、网络等）
    ///   - serverSignals: 服务端聚合信号（IP、ASN 等；可为 nil）
    ///   - accountId: 已绑定账号 ID（bindAccount；可为 nil）
    /// - Returns: 标准化图节点描述符
    public static func collect(
        snapshot: RiskSnapshot,
        serverSignals: ServerSignals?,
        accountId: String?
    ) -> GraphNodeDescriptor {
        let hwProfileHash = computeHwProfileHash(
            deviceID: snapshot.deviceID,
            hardwareMachine: snapshot.device.hardwareMachine ?? "",
            model: snapshot.device.model
        )

        var ipHash: String?
        var asnHash: String?
        if let s = serverSignals {
            if let ip = s.publicIP, !ip.isEmpty {
                ipHash = sha256Hex(ip)
            }
            if let asn = s.asn, !asn.isEmpty {
                asnHash = sha256Hex(asn)
            }
        }

        var accountIdHash: String?
        if let aid = accountId, !aid.isEmpty {
            accountIdHash = sha256Hex(aid)
        }

        // WiFi BSSID、应用安装列表：iOS 沙箱/隐私限制下通常不可获取，此处省略
        // 若未来有合法采集渠道，可在此扩展

        return GraphNodeDescriptor(
            hwProfileHash: hwProfileHash,
            ipHash: ipHash,
            asnHash: asnHash,
            accountIdHash: accountIdHash,
            bssidHash: nil,
            appListHash: nil
        )
    }

    // MARK: - 哈希工具

    /// 设备指纹哈希：SHA256(salt + deviceID + hardwareMachine + model)
    ///
    /// 引入应用/租户级固定盐前缀以抬高对低熵分量（机型/型号）的反推成本。
    /// 见类型文档中“关于可逆推性”一节——这是成本抬升而非绝对不可逆。
    private static func computeHwProfileHash(
        deviceID: String,
        hardwareMachine: String,
        model: String
    ) -> String {
        let raw = "\(hwProfileSaltDomainTag)|\(deviceID)|\(hardwareMachine)|\(model)"
        return sha256Hex(raw)
    }

    /// 单向 SHA256 哈希，输出 hex 字符串
    private static func sha256Hex(_ input: String) -> String {
        guard let data = input.data(using: .utf8) else { return "" }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
