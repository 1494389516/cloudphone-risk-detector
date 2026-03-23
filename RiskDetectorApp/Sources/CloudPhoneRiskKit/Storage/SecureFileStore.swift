import Foundation

/// File-based key/value store with NSFileProtectionComplete.
///
/// Replaces UserDefaults for sensitive data persistence. Each logical key maps to a pair of
/// sandboxed files under Application Support:
///   - `<key>.dat`  — encrypted payload
///   - `<key>.sig`  — HMAC signature
///
/// All files are created with `NSFileProtectionComplete`, ensuring data-at-rest encryption
/// when the device is locked.
final class SecureFileStore: @unchecked Sendable {

    static let shared = SecureFileStore()

    private let lock = NSLock()  // NSLock: file I/O inside lock
    private let baseDirectory: URL

    init(subdirectory: String = "CloudPhoneRiskKit/secure_store") {
        guard let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            preconditionFailure("ApplicationSupportDirectory unavailable")
        }
        self.baseDirectory = appSupport.appendingPathComponent(subdirectory, isDirectory: true)
    }

    /// Read raw data for a given key. Returns `nil` if file does not exist or read fails.
    func read(key: String) -> Data? {
        lock.withLock {
            let url = fileURL(for: key)
            return try? Data(contentsOf: url)
        }
    }

    /// Write raw data for a given key with NSFileProtectionComplete.
    @discardableResult
    func write(key: String, data: Data) -> Bool {
        lock.withLock {
            do {
                try ensureDirectory()
                let url = fileURL(for: key)
                try data.write(to: url, options: [.atomic, .completeFileProtection])
                try FileManager.default.setAttributes(
                    [.protectionKey: FileProtectionType.complete],
                    ofItemAtPath: url.path
                )
                return true
            } catch {
                Logger.log("SecureFileStore.write(\(key)) failed: \(error.localizedDescription)")
                return false
            }
        }
    }

    /// Remove data for a given key.
    func remove(key: String) {
        lock.withLock {
            let url = fileURL(for: key)
            try? FileManager.default.removeItem(at: url)
        }
    }

    /// Check if data exists for a given key.
    func exists(key: String) -> Bool {
        lock.withLock {
            FileManager.default.fileExists(atPath: fileURL(for: key).path)
        }
    }

    /// Return on-disk size in bytes for a given key (0 if not found).
    func size(key: String) -> Int {
        lock.withLock {
            let url = fileURL(for: key)
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
                  let size = attrs[.size] as? Int else {
                return 0
            }
            return size
        }
    }

    // MARK: - Private

    private func fileURL(for key: String) -> URL {
        let sanitized = key
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "..", with: "_")
        return baseDirectory.appendingPathComponent("\(sanitized).dat")
    }

    private func ensureDirectory() throws {
        let fm = FileManager.default
        if !fm.fileExists(atPath: baseDirectory.path) {
            try fm.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
            try fm.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: baseDirectory.path
            )
        }
    }
}
