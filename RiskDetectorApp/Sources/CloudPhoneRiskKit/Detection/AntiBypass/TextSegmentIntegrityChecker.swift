import CryptoKit
import Darwin
import Foundation
import MachO
import Security

/// __TEXT.__text 代码段哈希完整性校验
///
/// SDK 4.4 Phase 6: Keychain 用 kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly；换号重装后基线自动重建。
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
        /// 是否使用服务端参考哈希完成校验（true=服务端锚点，false=Keychain 本地基线）
        let usedServerReference: Bool
        /// 参考哈希来源（如 remote_config / custom_resolver / keychain_baseline）
        let referenceSource: String?
        /// 参考哈希版本（如远程配置版本、业务侧参考表版本）
        let referenceVersion: String?
    }

    private static let baselineAccount = "text_hash_baseline_v1"
    private static let versionAccount = "text_hash_version_v1"
    /// 首次建基线后标记为「待确认」，下次启动环境干净且哈希一致才视为可信
    private static let pendingAccount = "text_hash_pending_v1"

    /// Main entry: verify text segment integrity
    /// 优先使用服务端下发的参考哈希（RemoteConfig.textSegmentHashReference），Keychain 基线仅作本地辅助。
    /// 无服务端参考时保持向后兼容，仍用 Keychain 本地基线。
    static func verify() -> IntegrityResult {
        let sdkVersion = Version.current

        guard let found = findSDKImage() else {
            return IntegrityResult(
                isIntact: true,
                baselineHash: "",
                currentHash: "",
                sdkVersion: sdkVersion,
                sectionSize: 0,
                detail: "sdk_image_not_found",
                usedServerReference: false,
                referenceSource: nil,
                referenceVersion: nil
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
                detail: "encrypted_skip",
                usedServerReference: false,
                referenceSource: nil,
                referenceVersion: nil
            )
        }

        guard let (hash, size) = hashTextSection(header: header, imageIndex: imageIndex) else {
            return IntegrityResult(
                isIntact: true,
                baselineHash: "",
                currentHash: "",
                sdkVersion: sdkVersion,
                sectionSize: 0,
                detail: "hash_failed",
                usedServerReference: false,
                referenceSource: nil,
                referenceVersion: nil
            )
        }

        // 1. 优先服务端参考哈希：若 RemoteConfig 有当前版本的参考值，直接对比
        if let reference = resolveServerReferenceHash(for: sdkVersion) {
            let match = reference.expectedHash.lowercased() == hash.lowercased()
            return IntegrityResult(
                isIntact: match,
                baselineHash: reference.expectedHash,
                currentHash: hash,
                sdkVersion: sdkVersion,
                sectionSize: size,
                detail: match ? "intact" : "tampered",
                usedServerReference: true,
                referenceSource: reference.source,
                referenceVersion: reference.version
            )
        }

        // 2. 无服务端参考时，回退到 Keychain 本地基线（向后兼容）
        let uuid = binaryUUID(header: header) ?? "unknown"
        let storedBaseline = loadBaseline()
        let isPending = loadPending()

        if let stored = storedBaseline, stored.version == uuid {
            // 待确认窗口：首次建基线后需下次启动环境干净且哈希一致才视为可信
            if isPending {
                if stored.hash != hash {
                    return IntegrityResult(
                        isIntact: false,
                        baselineHash: stored.hash,
                        currentHash: hash,
                        sdkVersion: sdkVersion,
                        sectionSize: size,
                        detail: "tampered",
                        usedServerReference: false,
                        referenceSource: "keychain_baseline",
                        referenceVersion: nil
                    )
                }
                let envCheck = IntegrityBaselineEnvCheck.check()
                if envCheck.isSuspicious {
                    clearBaseline()
                    clearPending()
                    return IntegrityResult(
                        isIntact: false,
                        baselineHash: "",
                        currentHash: hash,
                        sdkVersion: sdkVersion,
                        sectionSize: size,
                        detail: "baseline_cleared_suspicious_env",
                        usedServerReference: false,
                        referenceSource: nil,
                        referenceVersion: nil
                    )
                }
                clearPending()
                return IntegrityResult(
                    isIntact: true,
                    baselineHash: stored.hash,
                    currentHash: hash,
                    sdkVersion: sdkVersion,
                    sectionSize: size,
                    detail: "intact",
                    usedServerReference: false,
                    referenceSource: "keychain_baseline",
                    referenceVersion: nil
                )
            }
            let match = stored.hash == hash
            return IntegrityResult(
                isIntact: match,
                baselineHash: stored.hash,
                currentHash: hash,
                sdkVersion: sdkVersion,
                sectionSize: size,
                detail: match ? "intact" : "tampered",
                usedServerReference: false,
                referenceSource: "keychain_baseline",
                referenceVersion: nil
            )
        }

        if let stored = storedBaseline, stored.version != uuid {
            let envCheck = IntegrityBaselineEnvCheck.check()
            if envCheck.isSuspicious {
                return IntegrityResult(
                    isIntact: false,
                    baselineHash: stored.hash,
                    currentHash: hash,
                    sdkVersion: sdkVersion,
                    sectionSize: size,
                    detail: "baseline_rejected_suspicious_env",
                    usedServerReference: false,
                    referenceSource: "keychain_baseline",
                    referenceVersion: nil
                )
            }
            saveBaseline(hash: hash, version: uuid)
            savePending()
            return IntegrityResult(
                isIntact: false,  // 不可信窗口：待下次启动确认
                baselineHash: hash,
                currentHash: hash,
                sdkVersion: sdkVersion,
                sectionSize: size,
                detail: "version_changed",
                usedServerReference: false,
                referenceSource: "keychain_baseline",
                referenceVersion: nil
            )
        }

        // 首启：环境可疑时拒绝建基线（扩展检查：DYLD_INSERT_LIBRARIES、suspicious image、P_TRACED、可疑父进程）
        let envCheck = IntegrityBaselineEnvCheck.check()
        if envCheck.isSuspicious {
            return IntegrityResult(
                isIntact: false,
                baselineHash: "",
                currentHash: hash,
                sdkVersion: sdkVersion,
                sectionSize: size,
                detail: "baseline_rejected_suspicious_env",
                usedServerReference: false,
                referenceSource: "keychain_baseline",
                referenceVersion: nil
            )
        }
        saveBaseline(hash: hash, version: uuid)
        savePending()
        return IntegrityResult(
            isIntact: false,  // 不可信窗口：待下次启动确认
            baselineHash: hash,
            currentHash: hash,
            sdkVersion: sdkVersion,
            sectionSize: size,
            detail: "baseline_established",
            usedServerReference: false,
            referenceSource: "keychain_baseline",
            referenceVersion: nil
        )
    }

    /// 从 RemoteConfig 解析当前 SDK 版本的服务端参考哈希
    private static func resolveServerReferenceHash(for sdkVersion: String) -> TextSegmentReference? {
        CPRiskKit.shared.resolveTextSegmentReference(for: sdkVersion)
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
        case "baseline_rejected_suspicious_env":
            return [
                RiskSignal(
                    id: "text_segment_baseline_rejected_suspicious_env",
                    category: "integrity",
                    score: 55,
                    evidence: [
                        "detail": "baseline_rejected_suspicious_env",
                        "current_hash": result.currentHash,
                        "sdk_version": result.sdkVersion
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            ]
        case "baseline_cleared_suspicious_env":
            return [
                RiskSignal(
                    id: "text_segment_baseline_cleared_suspicious_env",
                    category: "integrity",
                    score: 55,
                    evidence: [
                        "detail": "baseline_cleared_suspicious_env",
                        "current_hash": result.currentHash,
                        "sdk_version": result.sdkVersion
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            ]
        case "baseline_established":
            return [
                RiskSignal(
                    id: "text_segment_baseline_pending",
                    category: "integrity",
                    score: 8,
                    evidence: [
                        "detail": "baseline_established",
                        "hash": result.currentHash,
                        "sdk_version": result.sdkVersion
                    ],
                    state: .soft(confidence: 0.55),
                    layer: 2,
                    weightHint: 45
                )
            ]
        case "version_changed":
            return [
                RiskSignal(
                    id: "text_segment_version_changed",
                    category: "integrity",
                    score: 12,
                    evidence: [
                        "detail": "version_changed",
                        "hash": result.currentHash,
                        "sdk_version": result.sdkVersion
                    ],
                    state: .soft(confidence: 0.72),
                    layer: 2,
                    weightHint: 58
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
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    var sect = cmd.advanced(by: MemoryLayout<segment_command_64>.size)
                        .assumingMemoryBound(to: section_64.self)
                    for _ in 0..<seg.nsects {
                        if tupleStringEquals(sect.pointee.sectname, "__text") {
                            let addr = UInt64(Int64(sect.pointee.addr) + slide)
                            let size = sect.pointee.size
                            guard size > 0, size < 50 * 1024 * 1024,
                                  addr > 0, addr <= UInt64(UInt.max) else { return nil }
                            guard let bytes = UnsafeRawPointer(bitPattern: UInt(addr)) else {
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
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
            if load.cmd == LC_ENCRYPTION_INFO_64 {
                guard load.cmdsize >= MemoryLayout<encryption_info_command_64>.size else { return false }
                let enc = cmd.assumingMemoryBound(to: encryption_info_command_64.self).pointee
                return enc.cryptid != 0
            }
            if load.cmd == LC_ENCRYPTION_INFO {
                guard load.cmdsize >= MemoryLayout<encryption_info_command>.size else { return false }
                let enc = cmd.assumingMemoryBound(to: encryption_info_command.self).pointee
                return enc.cryptid != 0
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

    /// 清除基线（用于待确认窗口内环境可疑时强制重新采集）
    private static func clearBaseline() {
        _ = keychainDelete(account: baselineAccount)
        _ = keychainDelete(account: versionAccount)
    }

    static func loadPending() -> Bool {
        keychainRead(account: pendingAccount) == "1"
    }

    private static func savePending() {
        _ = keychainSave(account: pendingAccount, value: "1")
    }

    private static func clearPending() {
        _ = keychainDelete(account: pendingAccount)
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

    private static func keychainDelete(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
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
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
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
