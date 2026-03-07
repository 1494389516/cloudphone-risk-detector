import CryptoKit
import Darwin
import Foundation
import MachO
import Security

/// __TEXT.__text 代码段哈希完整性校验
///
/// 自包含方案：首次运行时计算 SDK 镜像 __TEXT.__text 段的 SHA-256 摘要作为基线，
/// 后续每次校验对比。哈希不一致 = 代码被 inline patch（函数替换、指令修改）。
///
/// 技术要点：
/// - ASLR 只改变基地址不改变段内容，直接哈希原始字节即可
/// - FairPlay 解密后的内容在同一版本内是稳定的
/// - 通过 LC_ENCRYPTION_INFO 检查加密状态，cryptid != 0 时跳过
enum TextSegmentIntegrityChecker {

    struct IntegrityResult {
        let isIntact: Bool
        let baselineHash: String
        let currentHash: String
        let sdkVersion: String
        let sectionSize: UInt64
        let detail: String
    }

    private static let baselineAccount = "text_hash_baseline_v1"
    private static let versionAccount = "text_hash_version_v1"

    /// Main entry: verify text segment integrity
    static func verify() -> IntegrityResult {
        let sdkVersion = Version.current

        guard let found = findSDKImage() else {
            return IntegrityResult(
                isIntact: true,
                baselineHash: "",
                currentHash: "",
                sdkVersion: sdkVersion,
                sectionSize: 0,
                detail: "sdk_image_not_found"
            )
        }

        let header = found.header
        let imageIndex = found.index

        if isEncrypted(header: header) {
            return IntegrityResult(
                isIntact: true,
                baselineHash: "",
                currentHash: "",
                sdkVersion: sdkVersion,
                sectionSize: 0,
                detail: "encrypted_skip"
            )
        }

        guard let (hash, size) = hashTextSection(header: header, imageIndex: imageIndex) else {
            return IntegrityResult(
                isIntact: true,
                baselineHash: "",
                currentHash: "",
                sdkVersion: sdkVersion,
                sectionSize: 0,
                detail: "hash_failed"
            )
        }

        let uuid = binaryUUID(header: header) ?? "unknown"
        let storedBaseline = loadBaseline()

        if let stored = storedBaseline, stored.version == uuid {
            let match = stored.hash == hash
            return IntegrityResult(
                isIntact: match,
                baselineHash: stored.hash,
                currentHash: hash,
                sdkVersion: sdkVersion,
                sectionSize: size,
                detail: match ? "intact" : "tampered"
            )
        }

        if let stored = storedBaseline, stored.version != uuid {
            saveBaseline(hash: hash, version: uuid)
            return IntegrityResult(
                isIntact: true,
                baselineHash: hash,
                currentHash: hash,
                sdkVersion: sdkVersion,
                sectionSize: size,
                detail: "version_changed"
            )
        }

        saveBaseline(hash: hash, version: uuid)
        return IntegrityResult(
            isIntact: true,
            baselineHash: hash,
            currentHash: hash,
            sdkVersion: sdkVersion,
            sectionSize: size,
            detail: "baseline_established"
        )
    }

    /// Convert result to RiskSignals
    static func asSignals(result: IntegrityResult) -> [RiskSignal] {
        switch result.detail {
        case "encrypted_skip":
            return []
        case "sdk_image_not_found":
            return [RiskSignal(
                id: "sdk_image_missing",
                category: "integrity",
                score: 15,
                evidence: ["detail": "sdk_image_not_found"],
                state: .soft(confidence: 0.6),
                layer: 2,
                weightHint: 70
            )]
        case "hash_failed":
            return [RiskSignal(
                id: "text_segment_hash_failed",
                category: "integrity",
                score: 10,
                evidence: ["detail": "hash_computation_failed"],
                state: .soft(confidence: 0.5),
                layer: 2,
                weightHint: 60
            )]
        case "tampered":
            return [
                RiskSignal(
                    id: "text_segment_tampered",
                    category: "integrity",
                    score: 30,
                    evidence: [
                        "baseline_hash": result.baselineHash,
                        "current_hash": result.currentHash,
                        "section_size": "\(result.sectionSize)",
                        "sdk_version": result.sdkVersion
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            ]
        case "intact":
            return [
                RiskSignal(
                    id: "text_segment_intact",
                    category: "integrity",
                    score: 0,
                    evidence: ["hash": result.currentHash],
                    state: .hard(detected: false),
                    layer: 2,
                    weightHint: 0
                )
            ]
        default:
            return []
        }
    }

    // MARK: - Internal Helpers

    /// Find CloudPhoneRiskKit's Mach-O header and dyld index
    private static func findSDKImage() -> (header: UnsafeRawPointer, index: UInt32)? {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let raw = _dyld_get_image_name(index) else { continue }
            let path = String(cString: raw)
            if path.lowercased().contains("cloudphoneriskkit") {
                guard let header = _dyld_get_image_header(index) else { continue }
                return (UnsafeRawPointer(header), index)
            }
        }
        return nil
    }

    /// Compute SHA-256 of __TEXT.__text section
    static func hashTextSection(header: UnsafeRawPointer, imageIndex: UInt32) -> (hash: String, size: UInt64)? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return nil
        }

        let slide = Int64(_dyld_get_image_vmaddr_slide(imageIndex))
        var cmd = UnsafeRawPointer(ptr).advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    var sect = cmd.advanced(by: MemoryLayout<segment_command_64>.size)
                        .assumingMemoryBound(to: section_64.self)
                    for _ in 0..<seg.nsects {
                        if tupleStringEquals(sect.pointee.sectname, "__text") {
                            let addr = UInt64(Int64(sect.pointee.addr) + slide)
                            let size = sect.pointee.size
                            guard size > 0, size < 50 * 1024 * 1024 else { return nil }
                            guard let bytes = UnsafeRawPointer(bitPattern: UInt(truncatingIfNeeded: addr)) else {
                                return nil
                            }
                            let data = Data(bytes: bytes, count: Int(size))
                            let digest = SHA256.hash(data: data)
                            let hex = digest.map { String(format: "%02x", $0) }.joined()
                            return (hex, size)
                        }
                        sect = sect.advanced(by: 1)
                    }
                }
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return nil
    }

    /// Check LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 cryptid
    static func isEncrypted(header: UnsafeRawPointer) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return false
        }

        var cmd = UnsafeRawPointer(ptr).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            if load.cmd == LC_ENCRYPTION_INFO || load.cmd == LC_ENCRYPTION_INFO_64 {
                let enc = cmd.advanced(by: 8).assumingMemoryBound(to: UInt32.self)
                let cryptid = enc.pointee
                return cryptid != 0
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return false
    }

    static func loadBaseline() -> (hash: String, version: String)? {
        guard let hash = keychainRead(account: baselineAccount),
              let version = keychainRead(account: versionAccount),
              !hash.isEmpty, !version.isEmpty
        else {
            return nil
        }
        return (hash, version)
    }

    static func saveBaseline(hash: String, version: String) {
        _ = keychainSave(account: baselineAccount, value: hash)
        _ = keychainSave(account: versionAccount, value: version)
    }

    private static let keychainService = "CloudPhoneRiskKit"
    private static let keychainAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    private static func keychainRead(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func keychainSave(account: String, value: String) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: keychainAccessible,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        if status != errSecItemNotFound { return false }
        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = keychainAccessible
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    /// Extract LC_UUID for version tracking
    static func binaryUUID(header: UnsafeRawPointer) -> String? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return nil
        }

        var cmd = UnsafeRawPointer(ptr).advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            if load.cmd == LC_UUID {
                let uuidCmd = cmd.assumingMemoryBound(to: uuid_command.self).pointee
                let bytes = withUnsafeBytes(of: uuidCmd.uuid) { Array($0) }
                return bytes.map { String(format: "%02x", $0) }.joined()
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return nil
    }
}

private func tupleStringEquals<T>(_ tuple: T, _ target: String) -> Bool {
    withUnsafePointer(to: tuple) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
            strncmp(cPtr, target, MemoryLayout<T>.size) == 0
        }
    }
}
