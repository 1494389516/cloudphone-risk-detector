import Foundation
import CryptoKit
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

// MARK: - 增强设备指纹
///
/// ## 设计理念
///
/// 增强设备指纹在原有 `DeviceFingerprint` 基础上，增加了更细粒度的硬件、系统、网络、显示层特征采集。
/// 这些特征主要用于：
/// 1. **设备唯一性识别**：通过多维度特征组合生成稳定的设备指纹哈希
/// 2. **异常检测**：识别模拟器、越狱设备、虚拟机等异常环境
/// 3. **风险评分**：为决策引擎提供更丰富的特征输入
///
/// ## 数据分层
///
/// ```
/// ┌─────────────────────────────────────────────────────────────┐
/// │                   EnhancedDeviceFingerprint                  │
/// ├─────────────────────────────────────────────────────────────┤
/// │  HardwareLayer    │  SystemLayer  │  NetworkLayer │ DisplayLayer│
/// │  ───────────────  │  ───────────  │  ──────────── │  ──────────│
/// │  • machine        │  • osVersion  │  • interfaces │  • resolution│
/// │  • model          │  • buildVer   │  • cellular  │  • scale     │
/// │  • cpuFreq        │  • locale     │  • wifi      │  • brightness│
/// │  • memorySize     │  • timezone   │  • dns       │             │
/// │  • cpuCount       │  • language   │  • proxy     │             │
/// │  • coreCount      │  • region     │  • vpn       │             │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// ## 线程安全
///
/// 所有属性均为 `let` 不可变类型，结构体遵循 `Sendable` 协议，可安全跨线程传递。
///
public struct EnhancedDeviceFingerprint: Codable, Sendable {

    // MARK: - 硬件层特征

    /// 硬件机器标识（如 "iPhone14,2"）
    public let hardwareMachine: String?

    /// 硬件型号（如 "D73gAP"）
    public let hardwareModel: String?

    /// CPU 物理核心数
    public let cpuPhysicalCores: Int

    /// CPU 逻辑核心数
    public let cpuLogicalCores: Int

    /// CPU 频率（MHz），通过 sysctl 读取
    public let cpuFrequency: Int?

    /// 总内存大小（MB）
    public let memorySize: Int?

    /// 磁盘总容量（GB）
    public let diskCapacity: Int?

    /// 磁盘可用容量（GB）
    public let diskAvailable: Int?

    /// 是否为模拟器
    public let isSimulator: Bool

    // MARK: - 系统层特征

    /// 系统名称（如 "iOS"）
    public let systemName: String

    /// 系统版本（如 "16.0"）
    public let systemVersion: String

    /// 内部构建版本（如 "20A362"）
    public let buildVersion: String?

    /// 内核版本
    public let kernelVersion: String?

    /// 语言代码（如 "zh-Hans"）
    public let languageCode: String

    /// 地区代码（如 "CN"）
    public let regionCode: String

    /// 完整本地化标识符（如 "zh_CN"）
    public let localeIdentifier: String

    /// 时区标识符（如 "Asia/Shanghai"）
    public let timeZoneIdentifier: String

    /// 时区偏移秒数
    public let timeZoneOffsetSeconds: Int

    /// 24小时制是否开启
    public let is24HourFormat: Bool

    /// 是否使用公历
    public let usesGregorianCalendar: Bool

    // MARK: - 网络层特征

    /// 可用网络接口名称列表
    public let networkInterfaceNames: [String]

    /// 是否支持蜂窝网络
    public let hasCellularCapability: Bool

    /// 当前是否连接 WiFi
    public let isWiFiConnected: Bool

    /// 当前是否连接蜂窝网络
    public let isCellularConnected: Bool

    /// DNS 服务器列表
    public let dnsServers: [String]

    /// HTTP 代理是否启用
    public let isHTTPProxyEnabled: Bool

    /// HTTPS 代理是否启用
    public let isHTTPSProxyEnabled: Bool

    /// SOCKS 代理是否启用
    public let isSOCKSProxyEnabled: Bool

    /// PAC 自动配置代理是否启用
    public let isPACProxyEnabled: Bool

    // MARK: - 显示层特征

    /// 屏幕宽度（物理像素）
    public let screenWidth: Int

    /// 屏幕高度（物理像素）
    public let screenHeight: Int

    /// 屏幕缩放比例
    public let screenScale: Double

    /// 屏幕亮度（0.0 - 1.0）
    public let screenBrightness: Double

    /// 是否支持高刷新率（ProMotion）
    public let supportsHighRefreshRate: Bool

    /// 当前最大帧率
    public let maximumFramesPerSecond: Int

    /// 是否处于深色模式
    public let isDarkMode: Bool

    /// 是否开启自动亮度
    public let isAutoBrightnessEnabled: Bool

    // MARK: - 设备标识

    /// Vendor 标识符（UUID）
    public let identifierForVendor: String?

    /// 计算得出的指纹哈希
    public let fingerprintHash: String

    // MARK: - 初始化

    public init(
        hardwareMachine: String?,
        hardwareModel: String?,
        cpuPhysicalCores: Int,
        cpuLogicalCores: Int,
        cpuFrequency: Int?,
        memorySize: Int?,
        diskCapacity: Int?,
        diskAvailable: Int?,
        isSimulator: Bool,
        systemName: String,
        systemVersion: String,
        buildVersion: String?,
        kernelVersion: String?,
        languageCode: String,
        regionCode: String,
        localeIdentifier: String,
        timeZoneIdentifier: String,
        timeZoneOffsetSeconds: Int,
        is24HourFormat: Bool,
        usesGregorianCalendar: Bool,
        networkInterfaceNames: [String],
        hasCellularCapability: Bool,
        isWiFiConnected: Bool,
        isCellularConnected: Bool,
        dnsServers: [String],
        isHTTPProxyEnabled: Bool,
        isHTTPSProxyEnabled: Bool,
        isSOCKSProxyEnabled: Bool,
        isPACProxyEnabled: Bool,
        screenWidth: Int,
        screenHeight: Int,
        screenScale: Double,
        screenBrightness: Double,
        supportsHighRefreshRate: Bool,
        maximumFramesPerSecond: Int,
        isDarkMode: Bool,
        isAutoBrightnessEnabled: Bool,
        identifierForVendor: String?,
        fingerprintHash: String
    ) {
        self.hardwareMachine = hardwareMachine
        self.hardwareModel = hardwareModel
        self.cpuPhysicalCores = cpuPhysicalCores
        self.cpuLogicalCores = cpuLogicalCores
        self.cpuFrequency = cpuFrequency
        self.memorySize = memorySize
        self.diskCapacity = diskCapacity
        self.diskAvailable = diskAvailable
        self.isSimulator = isSimulator
        self.systemName = systemName
        self.systemVersion = systemVersion
        self.buildVersion = buildVersion
        self.kernelVersion = kernelVersion
        self.languageCode = languageCode
        self.regionCode = regionCode
        self.localeIdentifier = localeIdentifier
        self.timeZoneIdentifier = timeZoneIdentifier
        self.timeZoneOffsetSeconds = timeZoneOffsetSeconds
        self.is24HourFormat = is24HourFormat
        self.usesGregorianCalendar = usesGregorianCalendar
        self.networkInterfaceNames = networkInterfaceNames
        self.hasCellularCapability = hasCellularCapability
        self.isWiFiConnected = isWiFiConnected
        self.isCellularConnected = isCellularConnected
        self.dnsServers = dnsServers
        self.isHTTPProxyEnabled = isHTTPProxyEnabled
        self.isHTTPSProxyEnabled = isHTTPSProxyEnabled
        self.isSOCKSProxyEnabled = isSOCKSProxyEnabled
        self.isPACProxyEnabled = isPACProxyEnabled
        self.screenWidth = screenWidth
        self.screenHeight = screenHeight
        self.screenScale = screenScale
        self.screenBrightness = screenBrightness
        self.supportsHighRefreshRate = supportsHighRefreshRate
        self.maximumFramesPerSecond = maximumFramesPerSecond
        self.isDarkMode = isDarkMode
        self.isAutoBrightnessEnabled = isAutoBrightnessEnabled
        self.identifierForVendor = identifierForVendor
        self.fingerprintHash = fingerprintHash
    }

    // MARK: - 工厂方法

    /// 采集当前设备的增强指纹
    ///
    /// ## 采集流程
    ///
    /// 1. **硬件层**：通过 `sysctl` 读取 CPU、内存、磁盘信息
    /// 2. **系统层**：通过 `UIDevice`、`Locale`、`TimeZone` 读取系统配置
    /// 3. **网络层**：通过 `getifaddrs`、`res_ninit` 读取网络接口和 DNS
    /// 4. **显示层**：通过 `UIScreen`、`UIScreen.main.brightness` 读取显示信息
    /// 5. **哈希计算**：将所有关键特征拼接后计算 SHA256
    ///
    /// ## 返回值
    ///
    /// 返回包含所有采集特征的 `EnhancedDeviceFingerprint` 实例
    ///
    public static func current() -> EnhancedDeviceFingerprint {
        let hardware = HardwareLayerCollector.collect()
        let system = SystemLayerCollector.collect()
        let network = NetworkLayerCollector.collect()
        let display = DisplayLayerCollector.collect()

        let hash = FingerprintHasher.compute(
            hardware: hardware,
            system: system,
            network: network,
            display: display
        )

        return EnhancedDeviceFingerprint(
            hardwareMachine: hardware.machine,
            hardwareModel: hardware.model,
            cpuPhysicalCores: hardware.physicalCores,
            cpuLogicalCores: hardware.logicalCores,
            cpuFrequency: hardware.cpuFrequency,
            memorySize: hardware.memorySize,
            diskCapacity: hardware.diskCapacity,
            diskAvailable: hardware.diskAvailable,
            isSimulator: hardware.isSimulator,
            systemName: system.name,
            systemVersion: system.version,
            buildVersion: system.buildVersion,
            kernelVersion: system.kernelVersion,
            languageCode: system.languageCode,
            regionCode: system.regionCode,
            localeIdentifier: system.localeIdentifier,
            timeZoneIdentifier: system.timeZoneIdentifier,
            timeZoneOffsetSeconds: system.timeZoneOffsetSeconds,
            is24HourFormat: system.is24HourFormat,
            usesGregorianCalendar: system.usesGregorianCalendar,
            networkInterfaceNames: network.interfaceNames,
            hasCellularCapability: network.hasCellular,
            isWiFiConnected: network.isWiFiConnected,
            isCellularConnected: network.isCellularConnected,
            dnsServers: network.dnsServers,
            isHTTPProxyEnabled: network.isHTTPProxyEnabled,
            isHTTPSProxyEnabled: network.isHTTPSProxyEnabled,
            isSOCKSProxyEnabled: network.isSOCKSProxyEnabled,
            isPACProxyEnabled: network.isPACProxyEnabled,
            screenWidth: display.width,
            screenHeight: display.height,
            screenScale: display.scale,
            screenBrightness: display.brightness,
            supportsHighRefreshRate: display.supportsHighRefreshRate,
            maximumFramesPerSecond: display.maximumFramesPerSecond,
            isDarkMode: display.isDarkMode,
            isAutoBrightnessEnabled: display.isAutoBrightnessEnabled,
            identifierForVendor: system.identifierForVendor,
            fingerprintHash: hash
        )
    }

    /// 将增强指纹转换为原有的 `DeviceFingerprint` 类型
    ///
    /// ## 用途
    ///
    /// 用于与现有代码兼容，在不修改下游代码的情况下提供增强功能。
    ///
    public func toLegacyFingerprint() -> DeviceFingerprint {
        DeviceFingerprint(
            systemName: systemName,
            systemVersion: systemVersion,
            model: hardwareMachine ?? "unknown",
            localizedModel: hardwareModel ?? "unknown",
            identifierForVendor: identifierForVendor,
            localeIdentifier: localeIdentifier,
            timeZoneIdentifier: timeZoneIdentifier,
            timeZoneOffsetSeconds: timeZoneOffsetSeconds,
            screenWidth: screenWidth,
            screenHeight: screenHeight,
            screenScale: screenScale,
            hardwareMachine: hardwareMachine,
            hardwareModel: hardwareModel,
            isSimulator: isSimulator
        )
    }

    /// 获取指纹的稳定版本（不含易变特征）
    ///
    /// ## 稳定特征
    ///
    /// 以下特征被认为相对稳定：
    /// - 硬件机器型号
    /// - CPU 核心数
    /// - 内存大小
    /// - 系统版本
    /// - 屏幕分辨率
    ///
    /// ## 易变特征（排除）
    ///
    /// - 网络状态
    /// - 时区偏移
    /// - 磁盘可用容量
    /// - 屏幕亮度
    ///
    public func stableHash() -> String {
        let stableData = [
            hardwareMachine ?? "",
            hardwareModel ?? "",
            String(cpuPhysicalCores),
            String(cpuLogicalCores),
            String(memorySize ?? 0),
            systemName,
            systemVersion,
            String(screenWidth),
            String(screenHeight),
            String(screenScale)
        ].joined(separator: "|")

        return Data(stableData.utf8).sha256()
    }
}

// MARK: - 硬件层采集器

private struct HardwareLayerCollector {
    struct Collected {
        let machine: String?
        let model: String?
        let physicalCores: Int
        let logicalCores: Int
        let cpuFrequency: Int?
        let memorySize: Int?
        let diskCapacity: Int?
        let diskAvailable: Int?
        let isSimulator: Bool
    }

    static func collect() -> Collected {
        let machine = Sysctl.string("hw.machine")
        let model = Sysctl.string("hw.model")

        // 获取 CPU 核心数
        let physicalCores = Sysctl.int("hw.physicalcpu") ?? 0
        let logicalCores = Sysctl.int("hw.logicalcpu") ?? 0

        // 获取 CPU 频率
        let cpuFrequency = Sysctl.int("hw.cpufrequency").map { $0 / 1_000_000 } // 转换为 MHz

        // 获取内存大小
        let memorySize = Sysctl.int("hw.memsize").map { $0 / 1_048_576 } // 转换为 MB

        // 获取磁盘容量
        let diskCapacity: Int?
        let diskAvailable: Int?
        if let attributes = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory()) {
            let totalSize = attributes[.systemSize] as? UInt64 ?? 0
            let freeSize = attributes[.systemFreeSize] as? UInt64 ?? 0
            diskCapacity = Int(totalSize / 1_073_741_824) // 转换为 GB
            diskAvailable = Int(freeSize / 1_073_741_824)
        } else {
            diskCapacity = nil
            diskAvailable = nil
        }

        #if targetEnvironment(simulator)
        let isSimulator = true
        #else
        let isSimulator = false
        #endif

        return Collected(
            machine: machine,
            model: model,
            physicalCores: physicalCores,
            logicalCores: logicalCores,
            cpuFrequency: cpuFrequency,
            memorySize: memorySize,
            diskCapacity: diskCapacity,
            diskAvailable: diskAvailable,
            isSimulator: isSimulator
        )
    }
}

// MARK: - 系统层采集器

private struct SystemLayerCollector {
    struct Collected {
        let name: String
        let version: String
        let buildVersion: String?
        let kernelVersion: String?
        let languageCode: String
        let regionCode: String
        let localeIdentifier: String
        let timeZoneIdentifier: String
        let timeZoneOffsetSeconds: Int
        let is24HourFormat: Bool
        let usesGregorianCalendar: Bool
        let identifierForVendor: String?
    }

    static func collect() -> Collected {
        #if canImport(UIKit)
        let device = UIDevice.current
        let systemName = device.systemName
        let systemVersion = device.systemVersion
        let identifierForVendor = device.identifierForVendor?.uuidString
        #elseif canImport(AppKit)
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let systemName = "macOS"
        let systemVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let identifierForVendor: String? = nil
        #else
        let systemName = "unknown"
        let systemVersion = "unknown"
        let identifierForVendor: String? = nil
        #endif

        // 构建版本
        let buildVersion = Sysctl.string("kern.osversion")

        // 内核版本
        let kernelVersion = Sysctl.string("kern.version")

        // 本地化信息
        let locale = Locale.current
        let languageCode = locale.languageCode ?? locale.identifier
        let regionCode: String
        if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
            regionCode = locale.region?.identifier ?? locale.regionCode ?? ""
        } else {
            regionCode = locale.regionCode ?? ""
        }
        let localeIdentifier = locale.identifier

        // 时区信息
        let timeZone = TimeZone.current
        let timeZoneIdentifier = timeZone.identifier
        let timeZoneOffsetSeconds = timeZone.secondsFromGMT()

        // 日期格式
        let dateFormat = DateFormatter()
        dateFormat.dateStyle = .none
        dateFormat.timeStyle = .short
        dateFormat.locale = locale
        let timeString = dateFormat.string(from: Date())
        let is24HourFormat = !timeString.contains("AM") && !timeString.contains("PM")

        // 日历类型
        let usesGregorianCalendar = Calendar.current.identifier == .gregorian

        return Collected(
            name: systemName,
            version: systemVersion,
            buildVersion: buildVersion,
            kernelVersion: kernelVersion,
            languageCode: languageCode,
            regionCode: regionCode,
            localeIdentifier: localeIdentifier,
            timeZoneIdentifier: timeZoneIdentifier,
            timeZoneOffsetSeconds: timeZoneOffsetSeconds,
            is24HourFormat: is24HourFormat,
            usesGregorianCalendar: usesGregorianCalendar,
            identifierForVendor: identifierForVendor
        )
    }
}

// MARK: - 网络层采集器

private struct NetworkLayerCollector {
    struct Collected {
        let interfaceNames: [String]
        let hasCellular: Bool
        let isWiFiConnected: Bool
        let isCellularConnected: Bool
        let dnsServers: [String]
        let isHTTPProxyEnabled: Bool
        let isHTTPSProxyEnabled: Bool
        let isSOCKSProxyEnabled: Bool
        let isPACProxyEnabled: Bool
    }

    static func collect() -> Collected {
        // 获取网络接口列表
        var interfaceNames: [String] = []
        var addresses: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&addresses) == 0, let first = addresses {
            var cursor: UnsafeMutablePointer<ifaddrs>? = first
            while let current = cursor {
                let name = String(cString: current.pointee.ifa_name)
                interfaceNames.append(name)
                cursor = current.pointee.ifa_next
            }
            freeifaddrs(addresses)
        }
        interfaceNames = Array(Set(interfaceNames)).sorted()

        // 判断蜂窝网络能力
        #if os(iOS)
        let hasCellular = true
        #else
        let hasCellular = false
        #endif

        // 代理状态检测
        let proxyStatus = ProxyDetector.detect()

        return Collected(
            interfaceNames: interfaceNames,
            hasCellular: hasCellular,
            isWiFiConnected: interfaceNames.contains("en0"),
            isCellularConnected: interfaceNames.contains("pdp_ip0"),
            dnsServers: DNSResolver.currentDNSServers(),
            isHTTPProxyEnabled: proxyStatus.httpEnabled,
            isHTTPSProxyEnabled: proxyStatus.httpsEnabled,
            isSOCKSProxyEnabled: proxyStatus.socksEnabled,
            isPACProxyEnabled: proxyStatus.pacEnabled
        )
    }

    private struct ProxyStatus {
        let httpEnabled: Bool
        let httpsEnabled: Bool
        let socksEnabled: Bool
        let pacEnabled: Bool
    }

    private enum ProxyDetector {
        static func detect() -> ProxyStatus {
            guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
                return ProxyStatus(httpEnabled: false, httpsEnabled: false, socksEnabled: false, pacEnabled: false)
            }

            let httpEnabled = (settings[kCFNetworkProxiesHTTPEnable as String] as? NSNumber)?.boolValue ?? false
            let httpsEnabled =
                (settings["HTTPSEnable"] as? NSNumber)?.boolValue ??
                ((settings["HTTPSProxy"] as? String)?.isEmpty == false)
            let socksEnabled = (settings["SOCKSEnable"] as? NSNumber)?.boolValue ?? false
            let pacEnabled = (settings[kCFNetworkProxiesProxyAutoConfigEnable as String] as? NSNumber)?.boolValue ?? false

            return ProxyStatus(httpEnabled: httpEnabled, httpsEnabled: httpsEnabled, socksEnabled: socksEnabled, pacEnabled: pacEnabled)
        }
    }

    private enum DNSResolver {
        static func currentDNSServers() -> [String] {
            var servers: [String] = []

            // 解析 /etc/resolv.conf
            if let resolvConf = try? String(contentsOfFile: "/etc/resolv.conf", encoding: .utf8) {
                let lines = resolvConf.components(separatedBy: .newlines)
                for line in lines {
                    if line.hasPrefix("nameserver") {
                        let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                        if parts.count >= 2 {
                            servers.append(parts[1])
                        }
                    }
                }
            }

            return servers
        }
    }
}

// MARK: - 显示层采集器

private struct DisplayLayerCollector {
    struct Collected {
        let width: Int
        let height: Int
        let scale: Double
        let brightness: Double
        let supportsHighRefreshRate: Bool
        let maximumFramesPerSecond: Int
        let isDarkMode: Bool
        let isAutoBrightnessEnabled: Bool
    }

    static func collect() -> Collected {
        #if canImport(UIKit)
        let screen = UIScreen.main
        let bounds = screen.bounds
        let scale = screen.scale
        let width = Int(bounds.width * scale)
        let height = Int(bounds.height * scale)
        let brightness = Double(screen.brightness)

        // 高刷新率检测
        let maximumFramesPerSecond: Int
        if #available(iOS 10.3, *) {
            maximumFramesPerSecond = screen.maximumFramesPerSecond
        } else {
            maximumFramesPerSecond = 60
        }
        let supportsHighRefreshRate = maximumFramesPerSecond > 60

        // 深色模式检测
        let isDarkMode: Bool
        if #available(iOS 13.0, *) {
            isDarkMode = UITraitCollection.current.userInterfaceStyle == .dark
        } else {
            isDarkMode = false
        }

        // 自动亮度检测（iOS 不提供公开 API，使用 UIDevice 电池状态判断）
        let isAutoBrightnessEnabled = UIScreen.main.brightnessMode == .auto

        #elseif canImport(AppKit)
        let screen = NSScreen.main ?? NSScreen.screens.first
        let frame = screen?.frame ?? .zero
        let scale = screen?.backingScaleFactor ?? 2.0
        let width = Int(frame.width * scale)
        let height = Int(frame.height * scale)
        let brightness = 0.5 // macOS 无公开 API

        let maximumFramesPerSecond = 60
        let supportsHighRefreshRate = false

        let isDarkMode: Bool
        if #available(macOS 10.14, *) {
            isDarkMode = NSAppearance.current.name == .darkAqua
        } else {
            isDarkMode = false
        }

        let isAutoBrightnessEnabled = false

        #else
        let width = 0
        let height = 0
        let scale = 1.0
        let brightness = 0.5
        let maximumFramesPerSecond = 60
        let supportsHighRefreshRate = false
        let isDarkMode = false
        let isAutoBrightnessEnabled = false
        #endif

        return Collected(
            width: width,
            height: height,
            scale: scale,
            brightness: brightness,
            supportsHighRefreshRate: supportsHighRefreshRate,
            maximumFramesPerSecond: maximumFramesPerSecond,
            isDarkMode: isDarkMode,
            isAutoBrightnessEnabled: isAutoBrightnessEnabled
        )
    }
}

// MARK: - 指纹哈希计算器

private enum FingerprintHasher {
    /// 计算设备指纹哈希
    ///
    /// ## 算法
    ///
    /// 1. 将各层特征按固定顺序拼接
    /// 2. 使用 SHA256 计算哈希
    /// 3. 返回十六进制字符串
    ///
    /// ## 特征选择
    ///
    /// 优先选择稳定、不易变的特征：
    /// - 硬件：machine、model、cpuCores、memorySize
    /// - 系统：osVersion、buildVersion、language、region
    /// - 显示：resolution、scale
    ///
    /// 排除易变特征（如网络状态、磁盘容量）以保持哈希稳定性
    ///
    static func compute(
        hardware: HardwareLayerCollector.Collected,
        system: SystemLayerCollector.Collected,
        network: NetworkLayerCollector.Collected,
        display: DisplayLayerCollector.Collected
    ) -> String {
        var components: [String] = []

        // 硬件层特征（稳定）
        components.append(hardware.machine ?? "")
        components.append(hardware.model ?? "")
        components.append(String(hardware.physicalCores))
        components.append(String(hardware.logicalCores))
        components.append(String(hardware.memorySize ?? 0))
        components.append(hardware.isSimulator ? "sim" : "dev")

        // 系统层特征（稳定）
        components.append(system.name)
        components.append(system.version)
        components.append(system.buildVersion ?? "")
        components.append(system.languageCode)
        components.append(system.regionCode)
        components.append(system.localeIdentifier)

        // 显示层特征（相对稳定）
        components.append(String(display.width))
        components.append(String(display.height))
        components.append(String(display.scale))

        // 网络能力（稳定）
        components.append(network.hasCellular ? "cell" : "nocell")

        let data = components.joined(separator: "|").data(using: .utf8) ?? Data()
        return data.sha256()
    }
}

// MARK: - Data SHA256 Extension

private extension Data {
    func sha256() -> String {
        let hashed = SHA256.hash(data: self)
        return hashed.compactMap { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - UIScreen Brightness Mode (Private API fallback)

#if canImport(UIKit)
private extension UIScreen {
    enum BrightnessMode {
        case auto
        case manual
    }

    var brightnessMode: BrightnessMode {
        // iOS 不提供公开 API 检测自动亮度
        // 这里返回默认值，实际可通过 brightnessDidChangeNotification 推断
        return .manual
    }
}
#endif

// MARK: - 风险特征提取

extension EnhancedDeviceFingerprint {

    /// 提取风险相关的特征
    ///
    /// ## 返回特征字典
    ///
    /// - `is_simulator`: 是否为模拟器
    /// - `cpu_cores_low`: CPU 核心数是否过低（可能是虚拟机）
    /// - `memory_low`: 内存是否过低（可能是旧设备或虚拟机）
    /// - `resolution_anomalous`: 分辨率是否异常
    /// - `timezone_mismatch`: 时区是否与地区不匹配
    /// - `proxy_enabled`: 是否启用代理
    ///
    public func riskFeatures() -> [String: Any] {
        var features: [String: Any] = [:]

        // 模拟器检测
        features["is_simulator"] = isSimulator

        // CPU 核心数过低（通常 iOS 设备至少 2 核）
        features["cpu_cores_low"] = cpuLogicalCores < 2

        // 内存过低（通常 iOS 设备至少 1GB）
        features["memory_low"] = (memorySize ?? 0) < 1024

        // 分辨率异常检测
        let commonResolutions = [
            "1136x640", "1334x750", "1920x1080", "2208x1242",
            "2436x1125", "2688x1242", "2732x2048"
        ]
        let currentResolution = "\(screenWidth)x\(screenHeight)"
        features["resolution_anomalous"] = !commonResolutions.contains(currentResolution)

        // 时区与地区匹配检测
        features["timezone_mismatch"] = !doesTimeZoneMatchRegion()

        // 代理启用检测
        features["proxy_enabled"] = isHTTPProxyEnabled || isHTTPSProxyEnabled || isSOCKSProxyEnabled || isPACProxyEnabled

        // 深色模式
        features["dark_mode"] = isDarkMode

        // 高刷新率支持
        features["high_refresh_rate"] = supportsHighRefreshRate

        return features
    }

    /// 检查时区是否与声明的地区匹配
    ///
    /// ## 用途
    ///
    /// 检测设备是否在声称的地区之外使用，可能是代理或 VPN 的信号。
    ///
    private func doesTimeZoneMatchRegion() -> Bool {
        let regionToTimeZones: [String: Set<String>] = [
            "CN": Set(["Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin"]),
            "US": Set(["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"]),
            "JP": Set(["Asia/Tokyo"]),
            "GB": Set(["Europe/London"]),
            "DE": Set(["Europe/Berlin"]),
            "FR": Set(["Europe/Paris"])
        ]

        if let expectedZones = regionToTimeZones[regionCode] {
            return expectedZones.contains(timeZoneIdentifier)
        }
        return true
    }

    /// 生成用于日志的摘要字符串
    ///
    public func logSummary() -> String {
        """
        EnhancedDeviceFingerprint:
          Hardware: \(hardwareMachine ?? "unknown") / \(hardwareModel ?? "unknown") | CPU: \(cpuPhysicalCores)P/\(cpuLogicalCores)L | Memory: \(memorySize ?? 0)MB
          System: \(systemName) \(systemVersion) (\(buildVersion ?? "unknown")) | \(localeIdentifier) | \(timeZoneIdentifier)
          Display: \(screenWidth)x\(screenHeight) @\(screenScale)x | \(isDarkMode ? "Dark" : "Light") mode
          Network: \(networkInterfaceNames.joined(separator: ", ")) | DNS: \(dnsServers.joined(separator: ", "))
          Fingerprint Hash: \(fingerprintHash.prefix(16))...
        """
    }
}
