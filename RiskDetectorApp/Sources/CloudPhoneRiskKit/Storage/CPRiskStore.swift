#if os(iOS)
import Foundation

@objc(CPRiskStore)
public final class CPRiskStore: NSObject {
    @objc public static let shared = CPRiskStore()

    /// 是否启用本地加密存储（AES-GCM + Keychain key）。
    @objc public var encryptionEnabled: Bool = true

    /// 最多保留多少份报告（超过会删除最旧的）。
    @objc public var maxFiles: Int = 50

    private override init() {}

    /// 保存报告到本地（Application Support）。
    /// - Returns: 保存后的绝对路径（失败返回 nil）
    @objc(saveReport:error:)
    public func save(_ report: CPRiskReport, error: NSErrorPointer) -> String? {
        do {
            let base = try directoryURL()
            try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)

            let filename = "risk-\(ISO8601.nowString()).\(encryptionEnabled ? "bin" : "json")"
            let url = base.appendingPathComponent(filename)

            let data: Data
            if encryptionEnabled {
                data = try report.encryptedData()
            } else {
                data = report.jsonData(prettyPrinted: true)
            }

            try data.write(to: url, options: [.atomic])
            try applyFileProtection(url: url)
            try enforceRetention(in: base, maxFiles: maxFiles)

            Logger.log("store.save: path=\(url.path) bytes=\(data.count) encrypted=\(encryptionEnabled)")
            return url.path
        } catch let e as NSError {
            Logger.log("store.save: failed error=\(e)")
            error?.pointee = e
            return nil
        }
    }

    /// 读取并解密（或直接读取明文）一份本地报告文件。
    /// - Returns: 解密后的 JSON 字符串（失败返回 nil）
    @objc(decryptReportAtPath:error:)
    public func decryptReport(atPath path: String, error: NSErrorPointer) -> String? {
        do {
            let url = URL(fileURLWithPath: path)
            let data = try Data(contentsOf: url)
            let plaintext: Data
            if path.hasSuffix(".json") {
                plaintext = data
            } else {
                plaintext = try PayloadCrypto.decrypt(data)
            }
            return String(data: plaintext, encoding: .utf8) ?? "{}"
        } catch let e as NSError {
            Logger.log("store.decrypt: failed path=\(path) error=\(e)")
            error?.pointee = e
            return nil
        }
    }

    private func directoryURL() throws -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        guard let base else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 1, userInfo: [NSLocalizedDescriptionKey: "applicationSupportDirectory unavailable"])
        }
        return base.appendingPathComponent("CloudPhoneRiskKit/reports", isDirectory: true)
    }

    private func applyFileProtection(url: URL) throws {
        try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
    }

    private func enforceRetention(in dir: URL, maxFiles: Int) throws {
        guard maxFiles > 0 else { return }
        let fm = FileManager.default
        let items = try fm.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: [.contentModificationDateKey],
            options: [.skipsHiddenFiles]
        )
        let sorted = try items.sorted { a, b in
            let ad = (try a.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let bd = (try b.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return ad < bd
        }
        if sorted.count <= maxFiles { return }
        for url in sorted.prefix(sorted.count - maxFiles) {
            try? fm.removeItem(at: url)
        }
    }
}
#endif
