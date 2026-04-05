import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

public struct DeviceFingerprint: Codable, Sendable {
    public var systemName: String
    public var systemVersion: String
    public var model: String
    public var localizedModel: String
    public var identifierForVendor: String?

    public var localeIdentifier: String
    public var timeZoneIdentifier: String
    public var timeZoneOffsetSeconds: Int

    public var screenWidth: Int
    public var screenHeight: Int
    public var screenScale: Double

    public var hardwareMachine: String? = nil
    public var hardwareModel: String? = nil
    public var isSimulator: Bool = false
    public var kernelBuild: String? = nil

    private enum CodingKeys: String, CodingKey {
        case systemName = "sn"
        case systemVersion = "sv"
        case model = "m"
        case localizedModel = "lm"
        case identifierForVendor = "iv"
        case localeIdentifier = "li"
        case timeZoneIdentifier = "tz"
        case timeZoneOffsetSeconds = "to"
        case screenWidth = "sw"
        case screenHeight = "sh"
        case screenScale = "ss"
        case hardwareMachine = "hm"
        case hardwareModel = "hd"
        case isSimulator = "is"
        case kernelBuild = "kb"
    }

    public static func current() -> DeviceFingerprint {
#if canImport(UIKit)
        let device = UIDevice.current
        let locale = Locale.current
        let tz = TimeZone.current
        let bounds = UIScreen.main.bounds
        let scale = UIScreen.main.scale
        let machine = Sysctl.string("hw.machine")
        let model = Sysctl.string("hw.model")
        #if targetEnvironment(simulator)
        let simulator = true
        #else
        let simulator = false
        #endif

        return DeviceFingerprint(
            systemName: device.systemName,
            systemVersion: device.systemVersion,
            model: device.model,
            localizedModel: device.localizedModel,
            identifierForVendor: device.identifierForVendor?.uuidString,
            localeIdentifier: locale.identifier,
            timeZoneIdentifier: tz.identifier,
            timeZoneOffsetSeconds: tz.secondsFromGMT(),
            screenWidth: Int(bounds.width * scale),
            screenHeight: Int(bounds.height * scale),
            screenScale: Double(scale),
            hardwareMachine: machine,
            hardwareModel: model,
            isSimulator: simulator,
            kernelBuild: Self.extractKernelBuild(from: Sysctl.string("kern.version"))
        )
#elseif canImport(AppKit)
        let locale = Locale.current
        let tz = TimeZone.current
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let version = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let scale = NSScreen.main?.backingScaleFactor ?? 2.0
        let frame = NSScreen.main?.frame ?? .zero
        return DeviceFingerprint(
            systemName: "macOS",
            systemVersion: version,
            model: "Mac",
            localizedModel: "Mac",
            identifierForVendor: nil,
            localeIdentifier: locale.identifier,
            timeZoneIdentifier: tz.identifier,
            timeZoneOffsetSeconds: tz.secondsFromGMT(),
            screenWidth: Int(frame.width * scale),
            screenHeight: Int(frame.height * scale),
            screenScale: Double(scale),
            hardwareMachine: Sysctl.string("hw.machine"),
            hardwareModel: Sysctl.string("hw.model"),
            isSimulator: false,
            kernelBuild: Self.extractKernelBuild(from: Sysctl.string("kern.version"))
        )
#else
        let locale = Locale.current
        let tz = TimeZone.current
        return DeviceFingerprint(
            systemName: "unknown",
            systemVersion: "unknown",
            model: "unknown",
            localizedModel: "unknown",
            identifierForVendor: nil,
            localeIdentifier: locale.identifier,
            timeZoneIdentifier: tz.identifier,
            timeZoneOffsetSeconds: tz.secondsFromGMT(),
            screenWidth: 0,
            screenHeight: 0,
            screenScale: 1,
            hardwareMachine: nil,
            hardwareModel: nil,
            isSimulator: false,
            kernelBuild: nil
        )
#endif
    }

    /// 从 kern.version 字符串中提取 kernel build ID（如 "22A400"、"23F79"）。
    ///
    /// ## 典型格式
    ///
    /// - Darwin Kernel Version 22.0.0: Mon Aug  7 16:06:22 PDT 2023; root:xnu-8792.1.25.3~2/RELEASE_ARM64_T8101
    ///   → "22A400"（通过 build 版本号推断）
    /// - kern.version 示例: "Darwin Kernel Version 23.0.0.0: Thu Oct 26 15:18:41 PDT 2023; root:xnu-10002.1.13.100.1~1/RELEASE_ARM64_T8101"
    ///   → "23F79"
    ///
    /// ## 提取策略
    ///
    /// 优先从 `kern.osversion` sysctl 直接读取（最可靠），
    /// 备用从 `kern.version` 字符串中解析 "Build" 后面的字母数字组合。
    public static func extractKernelBuild(from versionString: String?, osVersion: String? = nil) -> String? {
        // 策略1：直接读 kern.osversion（最可靠）
        let effectiveOSVersion = osVersion ?? Sysctl.string("kern.osversion")
        if let effectiveOSVersion, Self.looksLikeKernelBuild(effectiveOSVersion) {
            return effectiveOSVersion
        }

        // 策略2：从 kern.version 字符串解析 "Build" 标记后的内容
        guard let versionString, !versionString.isEmpty else { return nil }

        // 匹配 "Build " 后面的字符序列（不含空格和分号）
        // 例如: "... Build 22A400; ..." 或 "... Build 23F79 ..."
        if let buildRange = versionString.range(of: "Build ") {
            let afterBuild = versionString[buildRange.upperBound...]
            // Build ID 通常是连续的字母数字，最多约 8 个字符
            let buildID = afterBuild.prefix(8).trimmingCharacters(in: .whitespacesAndNewlines)
                .components(separatedBy: CharacterSet.alphanumerics.inverted).first ?? ""
            if Self.looksLikeKernelBuild(buildID) {
                return buildID
            }
        }

        // 策略3：扫描整段字符串中的 build-like token，避免把 RELEASE_ARM64_T8101 误判成 kernel build。
        let candidates = versionString.components(separatedBy: CharacterSet.alphanumerics.inverted)
        if let buildID = candidates.first(where: { Self.looksLikeKernelBuild($0) }) {
            return buildID
        }

        return nil
    }

    public static func looksLikeKernelBuild(_ candidate: String) -> Bool {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }

        let bytes = Array(trimmed.utf8)
        guard (5...8).contains(bytes.count) else { return false }

        var index = 0
        while index < bytes.count, bytes[index] >= 48, bytes[index] <= 57 {
            index += 1
        }
        guard index >= 2, index <= 3, index < bytes.count else { return false }

        let letter = bytes[index]
        guard letter >= 65, letter <= 90 else { return false }
        index += 1

        var digitCount = 0
        while index < bytes.count, bytes[index] >= 48, bytes[index] <= 57 {
            digitCount += 1
            index += 1
        }
        guard digitCount >= 2, digitCount <= 4 else { return false }

        if index == bytes.count {
            return true
        }

        guard index == bytes.count - 1 else { return false }
        let suffix = bytes[index]
        return suffix >= 97 && suffix <= 122
    }
}
