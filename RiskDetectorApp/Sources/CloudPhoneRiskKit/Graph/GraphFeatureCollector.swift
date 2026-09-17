import CryptoKit
import Foundation

// MARK: - 图特征采集器
///
/// 自动收集可供图计算的结构化特征，输出 GraphNodeDescriptor，
/// 标准化为服务端可直接入图的格式。
///
/// Client digests are correlation hints, NOT tenant-isolated pseudonyms or proof of identity.
/// Low-entropy IP/ASN/account hashes are deliberately omitted. The collector resolves
/// authenticated account and observed network identity using server-held tenant keys.
public enum GraphFeatureCollector {
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

        return GraphNodeDescriptor(
            hwProfileHash: hwProfileHash,
            ipHash: nil,
            asnHash: nil,
            accountIdHash: nil,
            bssidHash: nil,
            appListHash: nil,
            installationKey: sha256Hex("cprisk.installation.v1|\(snapshot.deviceID)"),
            hardwareAttributes: ["hardware_machine": snapshot.device.hardwareMachine ?? "", "model": snapshot.device.model]
        )
    }

    // MARK: - 哈希工具

    /// 设备指纹哈希：SHA256(salt + deviceID + hardwareMachine + model)
    ///
    /// Legacy exact-match/churn hint only. Public domain tag is not a secret salt.
    /// Similarity must use hardwareAttributes, never hash distance.
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
