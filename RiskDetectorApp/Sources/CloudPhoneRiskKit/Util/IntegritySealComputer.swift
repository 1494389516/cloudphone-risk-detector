import CRiskCore
import CryptoKit
import Foundation

/// 完整性印章 — 把任意输入压成 16 字节摘要后，过一道 GF(2) 128-bit 仿射变换。
///
/// 设计借鉴小红书 x-mini-sig 的 transform_16：
///   - 单纯 SHA-256 摘要可以被攻击者通过 hook CryptoKit 替换成常量返回值；
///   - 但叠加一层 128×128 GF(2) 矩阵乘法后，攻击者必须同时还原矩阵才能伪造正确 seal；
///   - GF(2) 仿射只产生 AND/XOR/popcount 指令，没有可识别的密码学常量，反向时极难定位。
///
/// 用途：作为 evidence 字段嵌入在风险信号里，给上游审计/未来服务器侧校验当签名锚点。
///
/// 用法示例:
///   let seal = IntegritySealComputer.seal(forCanonicalString: "vendor=Apple,model=iPhone")
///   evidence["seal"] = seal.hexString
enum IntegritySealComputer {

    /// 16 字节印章。
    struct Seal: Equatable {
        let bytes: [UInt8]

        var hexString: String {
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// 对任意 Data 生成 16 字节印章。
    /// 流程：SHA-256 → 取前 16 字节 → GF(2) 仿射变换。
    static func seal(forData data: Data) -> Seal {
        let hash = SHA256.hash(data: data)
        let prefix = Array(hash.prefix(16))
        return seal(forSha256Prefix16: prefix)
    }

    /// 对任意 UTF-8 字符串生成印章（先 utf8 编码再 SHA-256）。
    static func seal(forCanonicalString string: String) -> Seal {
        seal(forData: Data(string.utf8))
    }

    /// 直接对 16 字节输入做 GF(2) 仿射（跳过 SHA-256 — 调用方已自备摘要时使用）。
    static func seal(forSha256Prefix16 input: [UInt8]) -> Seal {
        precondition(input.count == 16, "GF(2) affine input must be exactly 16 bytes")
        var output = [UInt8](repeating: 0, count: 16)
        input.withUnsafeBufferPointer { inBuf in
            output.withUnsafeMutableBufferPointer { outBuf in
                cprisk_gf2_affine_transform_16(
                    outBuf.baseAddress,
                    inBuf.baseAddress,
                    nil,  // 使用 SDK 默认矩阵
                    nil   // 使用 SDK 默认平移向量
                )
            }
        }
        return Seal(bytes: output)
    }

    /// 矩阵自校验。返回 true = 矩阵未被改 .rodata 篡改。
    static var isMatrixIntact: Bool {
        cprisk_gf2_affine_self_check() == 0
    }
}
