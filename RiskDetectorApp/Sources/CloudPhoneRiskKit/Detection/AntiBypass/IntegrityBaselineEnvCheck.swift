import CRiskCore
import Darwin
import Foundation
import MachO

/// 完整性基线建基线前的环境可信度检查
///
/// 首启/升级窗口建基线时，若当前环境已存在注入特征（DYLD_INSERT_LIBRARIES、suspicious image、
/// P_TRACED、可疑父进程等），不应将可能被篡改的状态写成可信基线，应拒绝建基线或产出高危信号。
///
/// 加固：扩展检查项以应对「首次安装时 patch IPA」攻击——攻击者在首次启动前注入 Frida 等，
/// 若仅检查 DYLD_INSERT_LIBRARIES 和 suspicious image，可能漏检（如通过重打包注入 dylib 但
/// 未设置环境变量）。增加 P_TRACED、可疑父进程等维度，任一不满足则拒绝建基线。
enum IntegrityBaselineEnvCheck {

    /// 可疑环境检测结果
    struct Result {
        let isSuspicious: Bool
        let reason: String?
    }

    private static var suspiciousImagePatterns: [String] { ObfuscatedConstants.suspiciousImagePatternsBaseline }

    /// 检查当前环境是否适合建立完整性基线
    /// - Returns: 若 isSuspicious 为 true，则不应建基线
    static func check() -> Result {
        if getenv("DYLD_INSERT_LIBRARIES") != nil {
            return Result(isSuspicious: true, reason: "DYLD_INSERT_LIBRARIES")
        }
        if let image = firstSuspiciousImage() {
            return Result(isSuspicious: true, reason: "suspicious_image:\(image)")
        }
        if isBeingTraced() {
            return Result(isSuspicious: true, reason: "P_TRACED")
        }
        if let parent = suspiciousParentProcess() {
            return Result(isSuspicious: true, reason: "suspicious_parent:\(parent)")
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

    /// P_TRACED 非零表示进程正被调试器附加，建基线时不应信任
    private static func isBeingTraced() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return cprisk_is_being_traced() != 0
        #endif
    }

    /// 可疑父进程（lldb、gdb、frida、debugserver、cydia、sileo 等）
    private static func suspiciousParentProcess() -> String? {
        let ppid = cprisk_getppid_direct()
        guard ppid > 1 else { return nil }
        guard let parentPath = processPath(for: ppid), !parentPath.isEmpty else { return nil }
        let normalized = parentPath.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let needles = ObfuscatedConstants.sysctlSuspiciousParentNeedles
        if needles.contains(where: { normalized.contains($0) }) {
            return (parentPath as NSString).lastPathComponent
        }
        return nil
    }
}
