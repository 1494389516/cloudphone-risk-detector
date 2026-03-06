import Darwin
import Foundation
import MachO
import Security

/// SDK 二进制自身完整性校验
///
/// 防止攻击者直接替换 SDK framework 的 Mach-O 二进制。
/// 检测手段：
/// 1. 验证 SDK 镜像的 LC_CODE_SIGNATURE 是否存在且有效
/// 2. 检查 SDK 的 LC_UUID 是否在运行期间被篡改（对比 Keychain 存储）
/// 3. 验证 SDK 镜像的 segment 权限是否合理
/// 4. 检查 SDK 二进制大小是否在合理范围
enum SDKBinaryIntegrityChecker {
    
    struct IntegrityResult {
        let isIntact: Bool
        let checks: [String: Bool]
        let detail: String
    }
    
    private static let keychainService = "CloudPhoneRiskKit"
    private static let keychainUUIDAcc = "sdk_binary_uuid_v1"
    private static let keychainSizeAcc = "sdk_binary_size_v1"
    
    static func verify() -> IntegrityResult {
        #if targetEnvironment(simulator)
        return IntegrityResult(isIntact: true, checks: [:], detail: "simulator_skip")
        #else
        var checks: [String: Bool] = [:]
        var allPassed = true
        
        guard let image = findSDKImage() else {
            return IntegrityResult(isIntact: true, checks: [:], detail: "sdk_image_not_found")
        }
        
        // 1. LC_CODE_SIGNATURE existence
        let hasCodeSig = checkCodeSignature(header: image.header)
        checks["code_signature"] = hasCodeSig
        if !hasCodeSig { allPassed = false }
        
        // 2. LC_UUID consistency (compare with Keychain-stored value)
        let uuidCheck = checkUUIDConsistency(header: image.header)
        checks["uuid_consistent"] = uuidCheck.consistent
        if !uuidCheck.consistent { allPassed = false }
        
        // 3. Segment permission sanity
        let permCheck = checkSegmentPermissions(header: image.header)
        checks["segment_permissions"] = permCheck
        if !permCheck { allPassed = false }
        
        // 4. Binary size sanity (SDK binary should be within reasonable range)
        let sizeCheck = checkBinarySize(header: image.header, index: image.index)
        checks["binary_size"] = sizeCheck
        if !sizeCheck { allPassed = false }
        
        let detail: String
        if allPassed {
            detail = "intact"
        } else {
            let failed = checks.filter { !$0.value }.map { $0.key }
            detail = "tampered:\(failed.joined(separator: ","))"
        }
        
        return IntegrityResult(isIntact: allPassed, checks: checks, detail: detail)
        #endif
    }
    
    static func asSignals(result: IntegrityResult) -> [RiskSignal] {
        guard !result.isIntact else { return [] }
        
        var signals: [RiskSignal] = []
        
        if result.checks["code_signature"] == false {
            signals.append(RiskSignal(
                id: "sdk_code_signature_missing",
                category: "integrity",
                score: 30,
                evidence: ["detail": "SDK binary LC_CODE_SIGNATURE missing or invalid"],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }
        
        if result.checks["uuid_consistent"] == false {
            signals.append(RiskSignal(
                id: "sdk_binary_replaced",
                category: "integrity",
                score: 35,
                evidence: ["detail": "SDK binary UUID changed unexpectedly"],
                state: .tampered,
                layer: 2,
                weightHint: 95
            ))
        }
        
        if result.checks["segment_permissions"] == false {
            signals.append(RiskSignal(
                id: "sdk_segment_tampered",
                category: "integrity",
                score: 20,
                evidence: ["detail": "SDK binary has abnormal segment permissions"],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }
        
        if result.checks["binary_size"] == false {
            signals.append(RiskSignal(
                id: "sdk_binary_size_anomaly",
                category: "integrity",
                score: 15,
                evidence: ["detail": "SDK binary size changed significantly"],
                state: .soft(confidence: 0.7),
                layer: 2,
                weightHint: 70
            ))
        }
        
        return signals
    }
    
    // MARK: - Check Methods
    
    private static func findSDKImage() -> (header: UnsafeRawPointer, index: UInt32)? {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let raw = _dyld_get_image_name(i) else { continue }
            let path = String(cString: raw)
            if path.lowercased().contains("cloudphoneriskkit") {
                guard let header = _dyld_get_image_header(i) else { continue }
                return (UnsafeRawPointer(header), i)
            }
        }
        return nil
    }
    
    private static func checkCodeSignature(header: UnsafeRawPointer) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return false }
        
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            if loadCmd.cmd == LC_CODE_SIGNATURE {
                return true
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        return false
    }
    
    private static func checkUUIDConsistency(header: UnsafeRawPointer) -> (consistent: Bool, uuid: String?) {
        guard let currentUUID = extractUUID(header: header) else {
            return (true, nil)
        }
        
        if let storedUUID = keychainRead(account: keychainUUIDAcc) {
            if storedUUID == currentUUID {
                return (true, currentUUID)
            }
            // UUID changed — could be an update or a replacement
            // Store new UUID but flag as inconsistent on first detection
            // To distinguish update from attack: the TextSegmentIntegrityChecker
            // handles version changes via LC_UUID, so if BOTH change simultaneously,
            // it's likely an update. If only this changes, suspicious.
            keychainWrite(account: keychainUUIDAcc, value: currentUUID)
            return (false, currentUUID)
        }
        
        // First run — establish baseline
        keychainWrite(account: keychainUUIDAcc, value: currentUUID)
        return (true, currentUUID)
    }
    
    private static func extractUUID(header: UnsafeRawPointer) -> String? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return nil }
        
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            if loadCmd.cmd == LC_UUID {
                let uuidCmd = cmd.assumingMemoryBound(to: uuid_command.self).pointee
                let bytes = withUnsafeBytes(of: uuidCmd.uuid) { Array($0) }
                return bytes.map { String(format: "%02x", $0) }.joined()
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        return nil
    }
    
    private static func checkSegmentPermissions(header: UnsafeRawPointer) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return false }
        
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            if loadCmd.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                let segName = withUnsafePointer(to: seg.segname) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                }
                // __TEXT should be r-x, never writable
                if segName == "__TEXT" && (seg.initprot & VM_PROT_WRITE) != 0 {
                    return false
                }
                // __DATA should never be executable
                if segName == "__DATA" && (seg.initprot & VM_PROT_EXECUTE) != 0 {
                    return false
                }
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        return true
    }
    
    private static func checkBinarySize(header: UnsafeRawPointer, index: UInt32) -> Bool {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 else { return false }
        
        var totalSize: UInt64 = 0
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)
        for _ in 0..<ptr.pointee.ncmds {
            let loadCmd = cmd.assumingMemoryBound(to: load_command.self).pointee
            if loadCmd.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                totalSize += seg.filesize
            }
            cmd = cmd.advanced(by: Int(loadCmd.cmdsize))
        }
        
        let sizeStr = "\(totalSize)"
        if let storedSize = keychainRead(account: keychainSizeAcc) {
            guard let stored = UInt64(storedSize) else {
                keychainWrite(account: keychainSizeAcc, value: sizeStr)
                return true
            }
            let ratio = Double(totalSize) / Double(stored)
            // Size should not change by more than 30% without a version update
            if ratio < 0.7 || ratio > 1.3 {
                keychainWrite(account: keychainSizeAcc, value: sizeStr)
                return false
            }
            return true
        }
        
        keychainWrite(account: keychainSizeAcc, value: sizeStr)
        return true
    }
    
    // MARK: - Keychain Helpers
    
    private static func keychainRead(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    private static func keychainWrite(account: String, value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }
}
