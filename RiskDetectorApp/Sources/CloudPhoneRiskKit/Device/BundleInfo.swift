import Foundation

/// Bundle 元信息采集器
///
/// 提供从 Bundle 中读取应用元信息的能力：
/// - 安装时间（首次安装时间，非本次更新）
/// - Bundle ID
/// - 版本号
/// - 构建号
public final class BundleInfo {

    /// 单例实例
    public static let shared = BundleInfo()

    private init() {}

    // MARK: - Install Date

    /// 应用首次安装时间（Unix 时间戳，秒）
    ///
    /// 通过检查 App Store 收据或 NSFileManager 创建时间推断。
    /// - 在 App Store 环境：通过 `_NSBundleReceiptPath` 读取收据目录 mtime
    /// - 在非 App Store 环境：通过主 Bundle 可执行文件创建时间推断（近似安装时间）
    public var installDate: Date? {
        // 尝试 App Store 收据路径
        if let receiptPath = BundleInfo.receiptPath {
            let attrs = try? FileManager.default.attributesOfItem(atPath: receiptPath)
            if let mtime = attrs?[.modificationDate] as? Date {
                return mtime
            }
        }
        // 回退：主 Bundle 可执行文件创建时间
        guard let execPath = Bundle.main.executablePath else { return nil }
        let attrs = try? FileManager.default.attributesOfItem(atPath: execPath)
        return attrs?[.creationDate] as? Date
    }

    // MARK: - Bundle ID

    public var bundleIdentifier: String? {
        Bundle.main.bundleIdentifier
    }

    // MARK: - Version Info

    /// CFBundleShortVersionString（如 "1.2.3"）
    public var shortVersion: String? {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
    }

    /// CFBundleVersion（如 "100"）
    public var buildVersion: String? {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String
    }

    /// 完整版本字符串（如 "1.2.3 (100)"）
    public var fullVersionString: String {
        let v = shortVersion ?? "unknown"
        let b = buildVersion ?? "unknown"
        return "\(v) (\(b))"
    }

    // MARK: - Private

    /// App Store 收据路径
    private static var receiptPath: String? {
        #if os(iOS)
        // 沙盒环境下有效路径：/private/var/mobile/Applications/{GUID}/StoreKit/receipt
        // 但在 Swift 层无法直接访问，保守处理
        // macOS App Store 收据：~/Library/Receipts 或 App Bundle 内的 receipt
        #if canImport(AppKit)
        if let appStoreReceiptURL = Bundle.main.appStoreReceiptURL {
            let url = appStoreReceiptURL
            if FileManager.default.fileExists(atPath: url.path) {
                return url.path
            }
        }
        #endif
        #endif
        return nil
    }
}
