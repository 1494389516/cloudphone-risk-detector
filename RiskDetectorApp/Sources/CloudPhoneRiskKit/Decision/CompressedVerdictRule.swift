import Foundation

// MARK: - 压缩摘要快速判决规则
///
/// 纯位向量规则：基于 8 字节压缩摘要的快速判决通道。
/// 规则格式：layerIndex (1-4 或 5 表示 crossLayer)、bitMask、matchValue、action。
/// 若 (layerValue & bitMask) == matchValue，则规则命中。
///
/// 示例：layer2 & 0x0C != 0 --> block
/// 可配置为 layerIndex=2, bitMask=0x0C, matchValue=0x04 (jailbreak bit), action=block
public struct CompressedVerdictRule: Codable, Sendable {

    /// 规则 ID（用于日志与回溯）
    public let id: String

    /// 层索引：1-4 表示 Layer1(硬件)/Layer2(反篡改)/Layer3(行为)/Layer4(服务端)，5 表示 crossLayer
    public let layerIndex: Int

    /// 位掩码：layer 1-4 使用低 8 位，crossLayer 使用低 32 位
    public let bitMask: UInt64

    /// 匹配值：满足 (layerValue & bitMask) == matchValue 时命中
    public let matchValue: UInt64

    /// 命中时的动作
    public let action: RiskAction

    public init(
        id: String,
        layerIndex: Int,
        bitMask: UInt64,
        matchValue: UInt64,
        action: RiskAction
    ) {
        self.id = id
        self.layerIndex = layerIndex
        self.bitMask = bitMask
        self.matchValue = matchValue
        self.action = action
    }

    /// 检查 8 字节摘要是否命中此规则
    /// - Parameter digest: SignalCompressor 输出的 8 字节摘要
    /// - Returns: 是否命中
    public func matches(digest: Data) -> Bool {
        guard digest.count >= 8 else { return false }

        let layerValue: UInt64
        switch layerIndex {
        case 1:
            layerValue = UInt64(digest[0])
        case 2:
            layerValue = UInt64(digest[1])
        case 3:
            layerValue = UInt64(digest[2])
        case 4:
            layerValue = UInt64(digest[3])
        case 5:
            // crossLayer: bytes 4-7, big-endian
            layerValue = UInt64(digest[4]) << 24
                | UInt64(digest[5]) << 16
                | UInt64(digest[6]) << 8
                | UInt64(digest[7])
        default:
            return false
        }

        let effectiveMask: UInt64
        let effectiveMatch: UInt64
        if layerIndex >= 1 && layerIndex <= 4 {
            effectiveMask = bitMask & 0xFF
            effectiveMatch = matchValue & 0xFF
        } else {
            effectiveMask = bitMask & 0xFFFF_FFFF
            effectiveMatch = matchValue & 0xFFFF_FFFF
        }

        return (layerValue & effectiveMask) == effectiveMatch
    }
}
