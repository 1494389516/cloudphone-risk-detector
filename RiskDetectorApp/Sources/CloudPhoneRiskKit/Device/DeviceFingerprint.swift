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
            isSimulator: simulator
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
            isSimulator: false
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
            isSimulator: false
        )
#endif
    }
}
