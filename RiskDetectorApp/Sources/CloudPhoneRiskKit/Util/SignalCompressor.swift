import Foundation

// MARK: - 内存语义压缩模块
///
/// 将多维检测信号压缩为紧凑的、语义不透明的内存表示，降低内存驻留风险。
/// - 固定长度：1.1 为 9 字节（bytes 0-3 层摘要 + bytes 4-7 crossLayer + byte 8 行为熵）
/// - 分层摘要：Layer1(硬件) 8bit + Layer2(反篡改) 8bit + Layer3(行为) 8bit + Layer4(服务端) 8bit
/// - 跨层关联 bits 编码在层摘要中
/// - 使用 SecureBuffer 承载敏感中间结果，用完即焚
/// - 确定性：相同输入 → 相同输出

public enum SignalCompressor {

    /// 映射表版本，服务端需用同一版本解码
    public static let mappingVersion = "1.2"
    private static let signalTamperingDetectedID = StringDeobfuscator.base64Decode("dGFtcGVyaW5nX2RldGVjdGVk")
    private static let signalJailbreakDeviceID = "\(ObfuscatedConstants.signalJailbreak)_device"

    /// 压缩结果：9 字节固定长度摘要（1.1：byte8 扩展跨层 + 行为熵迁移）
    public struct CompressResult: Sendable {
        public let digest: Data
        public let mappingVersion: String

        public var digestHex: String {
            digest.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// 将信号列表压缩为固定 9 字节摘要（确定性：相同输入→相同输出）
    /// - Parameter signals: 风险信号列表（collectSignals 完成后的完整列表）
    /// - Returns: 压缩摘要与映射版本
    public static func compress(signals: [RiskSignal]) -> CompressResult {
        let layer1 = layer1Summary(signals: signals)
        let layer2 = layer2Summary(signals: signals)
        let layer3 = layer3Summary(signals: signals)
        let layer4 = layer4Summary(signals: signals)
        let (crossLayer, extendedByte) = crossLayerBits(signals: signals)

        let digest = SecureBuffer(size: 9).use { ptr in
            let bytes = ptr.assumingMemoryBound(to: UInt8.self)
            bytes[0] = layer1
            bytes[1] = layer2
            bytes[2] = layer3
            bytes[3] = layer4
            bytes[4] = UInt8((crossLayer >> 24) & 0xFF)
            bytes[5] = UInt8((crossLayer >> 16) & 0xFF)
            bytes[6] = UInt8((crossLayer >> 8) & 0xFF)
            bytes[7] = UInt8(crossLayer & 0xFF)
            bytes[8] = extendedByte
            return Data(bytes: ptr, count: 9)
        }

        return CompressResult(digest: digest, mappingVersion: mappingVersion)
    }

    // MARK: - Layer 摘要

    /// Layer1 硬件层：云手机、GPU、BoardID、DRM、指纹、挂载等
    private static func layer1Summary(signals: [RiskSignal]) -> UInt8 {
        var bits: UInt8 = 0
        let ids = Set(signals.map(\.id))

        if ids.contains("gpu_virtual") { bits |= 0x01 }
        if ids.contains("vphone_hardware") { bits |= 0x02 }
        if ids.contains("board_id_virtual") { bits |= 0x04 }
        if ids.contains("hardware_inconsistency") { bits |= 0x08 }
        if ids.contains("drm_capability") || ids.contains("drm_device_mismatch") { bits |= 0x10 }
        if ids.contains("fingerprint_simulator") || ids.contains("fingerprint_virtualization") { bits |= 0x20 }
        if ids.contains("mount_virtual_fs") || ids.contains("mount_missing_required") { bits |= 0x40 }
        if ids.contains("simulator") || ids.contains("suspicious_device_name") { bits |= 0x80 }

        return bits
    }

    /// Layer2 反篡改层：Hook、越狱、Frida、PLT、SDK 完整性等
    private static func layer2Summary(signals: [RiskSignal]) -> UInt8 {
        var bits: UInt8 = 0
        let ids = Set(signals.map(\.id))

        if ids.contains(ObfuscatedConstants.signalHookDetected) || ids.contains(Self.signalTamperingDetectedID) { bits |= 0x01 }
        if ids.contains("cross_layer_inconsistency") { bits |= 0x02 }
        if ids.contains(ObfuscatedConstants.signalJailbreak) || ids.contains(Self.signalJailbreakDeviceID) { bits |= 0x04 }
        if ids.contains(ObfuscatedConstants.signalFridaDetected)
            || ids.contains(ObfuscatedConstants.signalFridaJSEngineHeap)
            || ids.contains(ObfuscatedConstants.signalFridaUnixSocket)
            || ids.contains(ObfuscatedConstants.signalFridaModuleDetected)
            || ids.contains(ObfuscatedConstants.signalFridaModuleImage)
            || ids.contains(ObfuscatedConstants.signalFridaModuleSection)
            || ids.contains(ObfuscatedConstants.signalFridaModuleString) {
            bits |= 0x08
        }
        if ids.contains("plt_integrity_tampered") || ids.contains("text_segment_tampered")
            || ids.contains("text_segment_baseline_rejected_suspicious_env")
            || ids.contains("text_segment_baseline_cleared_suspicious_env") { bits |= 0x10 }
        if ids.contains("sdk_binary_replaced") || ids.contains("sdk_code_signature_missing") { bits |= 0x20 }
        if ids.contains("dyld_interpose_detected") || ids.contains(ObfuscatedConstants.signalLibcInlineHookDetected) { bits |= 0x40 }
        if ids.contains(ObfuscatedConstants.signalMultipathHookDetected) || ids.contains("objc_method_swizzled") || ids.contains("isa_swizzle_detected") { bits |= 0x80 }

        return bits
    }

    /// Layer3 行为层：触摸熵、传感器熵、时序异常、行为模式
    private static func layer3Summary(signals: [RiskSignal]) -> UInt8 {
        var bits: UInt8 = 0
        let ids = Set(signals.map(\.id))

        if ids.contains("sensor_entropy") || ids.contains("touch_entropy") { bits |= 0x01 }
        if ids.contains("timing_anomaly") { bits |= 0x02 }
        if ids.contains("touch_spread_low") || ids.contains("touch_spread_high") { bits |= 0x04 }
        if ids.contains("touch_interval_too_regular") || ids.contains("touch_interval_too_chaotic") { bits |= 0x08 }
        if ids.contains("swipe_too_linear") || ids.contains("swipe_too_curvy") { bits |= 0x10 }
        if ids.contains("motion_too_still") || ids.contains("touch_motion_weak_coupling") { bits |= 0x20 }
        if ids.contains("insufficient_behavior_data") { bits |= 0x40 }
        if ids.contains("sensor_replay_detected") || ids.contains("gpu_render_anomaly") { bits |= 0x80 }

        return bits
    }

    /// Layer4 服务端层：机房 IP、聚合度、黑名单
    private static func layer4Summary(signals: [RiskSignal]) -> UInt8 {
        var bits: UInt8 = 0
        let ids = Set(signals.map(\.id))

        if ids.contains("datacenter_ip") { bits |= 0x01 }
        if ids.contains("ip_device_agg") { bits |= 0x02 }
        if ids.contains("ip_account_agg") { bits |= 0x04 }
        if ids.contains("blocklist_hit") { bits |= 0x08 }
        if ids.contains("risk_tags") || ids.contains("graph_community_risk") { bits |= 0x10 }
        if ids.contains("graph_hw_profile_cluster") || ids.contains("graph_dense_subgraph") || ids.contains("local_device_cluster") { bits |= 0x20 }
        if ids.contains(ObfuscatedConstants.requiredSignalVpnActive) || ids.contains("proxy_enabled") { bits |= 0x40 }
        if ids.contains("provider_tamper_attempt") || ids.contains("provider_instance_replaced") { bits |= 0x80 }

        return bits
    }

    /// 跨层关联 bits：L1 vs L2、L1 vs L3、L2 tampered 计数等
    /// 返回 (crossLayer UInt32, extendedByte)：bit 12-15 映射 SDK 5.2 新信号；行为熵迁移至 extendedByte
    private static func crossLayerBits(signals: [RiskSignal]) -> (UInt32, UInt8) {
        var bits: UInt32 = 0
        let ids = Set(signals.map(\.id))

        let hasL1Suspicious = ids.contains("gpu_virtual") || ids.contains("vphone_hardware") || ids.contains("hardware_inconsistency")
        let hasL2Tampered = signals.contains { $0.layer == 2 && $0.state == .tampered }
        let hasL3Virtual = ids.contains("sensor_entropy") || ids.contains("touch_entropy")
        let tamperedCount = signals.filter { $0.state == .tampered }.count

        if hasL1Suspicious { bits |= 0x0001 }
        if hasL2Tampered { bits |= 0x0002 }
        if hasL3Virtual { bits |= 0x0004 }
        if ids.contains("cross_layer_inconsistency") { bits |= 0x0008 }
        if tamperedCount >= 1 { bits |= 0x0010 }
        if tamperedCount >= 2 { bits |= 0x0020 }
        if tamperedCount >= 3 { bits |= 0x0040 }
        if ids.contains("physical_sensor_anomaly") { bits |= 0x0080 }
        let hasEnvironmentStatic = ids.contains("thermal_state_static") || ids.contains("battery_state_static") || ids.contains("screen_brightness_static")
        if hasEnvironmentStatic { bits |= 0x0100 }
        let hasHardwareCapabilityMismatch = ids.contains("haptic_capability_mismatch") || ids.contains("refresh_rate_mismatch") || ids.contains("proximity_sensor_absent")
        if hasHardwareCapabilityMismatch { bits |= 0x0200 }
        if ids.contains("network_interface_anomaly") { bits |= 0x0400 }
        if ids.contains(ObfuscatedConstants.signalLibcDirectSyscallFallback) { bits |= 0x0001_0000 }

        // bit 12-15：SDK 5.2 新信号（原 bits 12-14 行为熵已迁移至 extendedByte）
        if ids.contains("screen_captured") { bits |= 0x1000 }
        if ids.contains("external_display_attached") { bits |= 0x2000 }
        if ids.contains("usb_audio_routed") { bits |= 0x4000 }
        if ids.contains("no_cellular_provider") { bits |= 0x8000 }

        // 行为熵量化：0-7 档，迁移至 extendedByte bits 0-2
        let behaviorEntropy = min(7, signals.filter { $0.category == "behavior" }.count)
        let extendedByte = UInt8(behaviorEntropy & 0x07)

        return (bits, extendedByte)
    }
}

// MARK: - SignalToBitMapping 版本化协议（服务端解码用）
///
/// 服务端需维护与 mappingVersion 对应的解码表，用于从摘要还原语义维度。
/// 1.0=8 字节，1.1=9 字节（byte 8 为行为熵扩展）。
/// 映射表设计见下方注释。
public struct SignalToBitMapping {

    /// 当前支持的映射版本（占位，便于后续扩展）
    public static let supportedVersions: [String] = ["1.0", "1.1", "1.2"]

    /// Layer1 位定义（8-bit）
    /// bit0: gpu_virtual, bit1: vphone_hardware, bit2: board_id_virtual,
    /// bit3: hardware_inconsistency, bit4: drm_*, bit5: fingerprint_*,
    /// bit6: mount_*, bit7: simulator/suspicious_device_name
    public static let layer1BitNames: [Int: String] = [
        0: "gpu_virtual",
        1: "vphone_hardware",
        2: "board_id_virtual",
        3: "hardware_inconsistency",
        4: "drm",
        5: "fingerprint_virtual",
        6: "mount_anomaly",
        7: "simulator_like",
    ]

    /// Layer2 位定义（8-bit）
    public static let layer2BitNames: [Int: String] = [
        0: "\(ObfuscatedConstants.keywordHook)_\(ObfuscatedConstants.keywordTamper)ing",
        1: "cross_layer_inconsistency",
        2: ObfuscatedConstants.keywordJailbreak,
        3: ObfuscatedConstants.keywordFrida,
        4: "plt_text_tampered",
        5: "sdk_integrity",
        6: "dyld_libc_\(ObfuscatedConstants.keywordHook)",
        7: "multipath_objc_isa",
    ]

    /// Layer3 位定义（8-bit）
    public static let layer3BitNames: [Int: String] = [
        0: "sensor_touch_entropy",
        1: "timing_anomaly",
        2: "touch_spread",
        3: "touch_interval",
        4: "swipe_linearity",
        5: "motion_coupling",
        6: "insufficient_behavior",
        7: "sensor_replay_gpu",
    ]

    /// Layer4 位定义（8-bit）
    public static let layer4BitNames: [Int: String] = [
        0: "datacenter_ip",
        1: "ip_device_agg",
        2: "ip_account_agg",
        3: "blocklist_hit",
        4: "risk_tags",
        5: "graph_cluster",
        6: "vpn_proxy",
        7: "provider_tamper",
    ]

    /// 跨层 bits（bytes 4-7）
    /// bits 0-3: L1 suspicious, L2 tampered, L3 virtual, cross_layer
    /// bits 4-6: tampered count tier (0/1/2/3+)
    /// bit 7: physical_sensor_anomaly
    /// bit 8: environment_static (thermal_state_static, battery_state_static, screen_brightness_static 任一)
    /// bit 9: hardware_capability_mismatch (haptic_capability_mismatch, refresh_rate_mismatch, proximity_sensor_absent 任一)
    /// bit 10: network_interface_anomaly
    /// bit 11: physical_sensor_anomaly（PhysicalSensorProbe 未单独输出 barometer_anomaly）
    /// bits 12-15: SDK 5.2 screen_captured, external_display_attached, usb_audio_routed, no_cellular_provider
    /// byte 8 (extended): bits 0-2 = behavior entropy tier (0-7)，迁移自原 crossLayer bits 12-14
    public static let crossLayerBitNames: [Int: String] = [
        0: "l1_suspicious",
        1: "l2_tampered",
        2: "l3_virtual",
        3: "cross_layer_inconsistency",
        4: "tampered_1",
        5: "tampered_2",
        6: "tampered_3",
        7: "physical_sensor_anomaly",
        8: "environment_static",
        9: "hardware_capability_mismatch",
        10: "network_interface_anomaly",
        11: "barometer_anomaly",
        12: "screen_captured",
        13: "external_display_attached",
        14: "usb_audio_routed",
        15: "no_cellular_provider",
        16: "libc_direct_syscall_fallback",
    ]
}
