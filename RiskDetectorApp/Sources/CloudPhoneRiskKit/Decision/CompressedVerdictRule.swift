import Foundation

// MARK: - 压缩摘要快速判决规则
///
/// 纯位向量规则：基于压缩摘要的快速判决通道（1.0=8 字节，1.1=9 字节）。
/// 规则格式：layerIndex (1-4 层摘要、5=crossLayer、6=byte8 行为熵)、bitMask、matchValue、action。
/// 若 (layerValue & bitMask) == matchValue，则规则命中。
///
/// 示例：layer2 & 0x0C != 0 --> block
/// 可配置为 layerIndex=2, bitMask=0x0C, matchValue=0x04 (jailbreak bit), action=block
public struct CompressedVerdictRule: Codable, Sendable {

    public let id: String
    public let layerIndex: Int
    public let bitMask: UInt64
    public let matchValue: UInt64
    public let action: RiskAction

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case layerIndex = "li"
        case bitMask = "bm"
        case matchValue = "mv"
        case action = "a"
    }

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

    /// 检查压缩摘要是否命中此规则
    /// - Parameter digest: SignalCompressor 输出的摘要（1.0=8 字节，1.1=9 字节）
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
        case 6:
            // byte8 行为熵（1.1）：仅当 digest 为 9 字节时有效，否则视为 0
            layerValue = digest.count >= 9 ? UInt64(digest[8]) : 0
        default:
            return false
        }

        let effectiveMask: UInt64
        let effectiveMatch: UInt64
        if layerIndex >= 1 && layerIndex <= 4 {
            effectiveMask = bitMask & 0xFF
            effectiveMatch = matchValue & 0xFF
        } else if layerIndex == 6 {
            effectiveMask = bitMask & 0x07  // byte8 仅 bits 0-2 有效
            effectiveMatch = matchValue & 0x07
        } else {
            effectiveMask = bitMask & 0xFFFF_FFFF
            effectiveMatch = matchValue & 0xFFFF_FFFF
        }

        return (layerValue & effectiveMask) == effectiveMatch
    }
}
