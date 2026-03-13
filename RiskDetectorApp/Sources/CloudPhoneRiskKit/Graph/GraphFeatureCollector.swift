import CryptoKit
import Foundation

// MARK: - 图特征采集器
///
/// 自动收集可供图计算的结构化特征，输出 GraphNodeDescriptor，
/// 标准化为服务端可直接入图的格式。
///
/// ## 隐私保护
/// - 所有哈希为单向 SHA256，不可逆推原始值
/// - IP、账号 ID、BSSID、应用列表等敏感字段均以哈希形式上报
public enum GraphFeatureCollector {

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
        var asn: String?
        if let s = serverSignals {
            if let ip = s.publicIP, !ip.isEmpty {
                ipHash = sha256Hex(ip)
            }
            asn = s.asn
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
            asn: asn,
            accountIdHash: accountIdHash,
            bssidHash: nil,
            appListHash: nil
        )
    }

    // MARK: - 哈希工具

    /// 设备指纹哈希：SHA256(deviceID + hardwareMachine + model)
    private static func computeHwProfileHash(
        deviceID: String,
        hardwareMachine: String,
        model: String
    ) -> String {
        let raw = "\(deviceID)|\(hardwareMachine)|\(model)"
        return sha256Hex(raw)
    }

    /// 单向 SHA256 哈希，输出 hex 字符串
    private static func sha256Hex(_ input: String) -> String {
        guard let data = input.data(using: .utf8) else { return "" }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
