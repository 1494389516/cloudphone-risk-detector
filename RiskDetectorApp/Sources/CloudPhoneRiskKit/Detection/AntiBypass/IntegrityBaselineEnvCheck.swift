import Darwin
import Foundation
import MachO

/// 完整性基线建基线前的环境可信度检查
///
/// 首启/升级窗口建基线时，若当前环境已存在注入特征（DYLD_INSERT_LIBRARIES、suspicious image），
/// 不应将可能被篡改的状态写成可信基线，应拒绝建基线或产出高危信号。
enum IntegrityBaselineEnvCheck {

    /// 可疑环境检测结果
    struct Result {
        let isSuspicious: Bool
        let reason: String?
    }

    private static let suspiciousImagePatterns = ["frida", "substrate", "libhooker", "ellekit", "substitute"]

    /// 检查当前环境是否适合建立完整性基线
    /// - Returns: 若 isSuspicious 为 true，则不应建基线
    static func check() -> Result {
        if getenv("DYLD_INSERT_LIBRARIES") != nil {
            return Result(isSuspicious: true, reason: "DYLD_INSERT_LIBRARIES")
        }
        if let image = firstSuspiciousImage() {
            return Result(isSuspicious: true, reason: "suspicious_image:\(image)")
        }
        return Result(isSuspicious: false, reason: nil)
    }

    private static func firstSuspiciousImage() -> String? {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let raw = _dyld_get_image_name(index) else { continue }
            let image = String(cString: raw)
            let lower = image.lowercased()
            if suspiciousImagePatterns.contains(where: { lower.contains($0) }) {
                return (image as NSString).lastPathComponent
            }
        }
        return nil
    }
}
