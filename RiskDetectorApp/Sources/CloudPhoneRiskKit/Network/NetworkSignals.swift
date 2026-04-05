import CFNetwork
import CoreTelephony
import Darwin
import Foundation
import Network
#if canImport(UIKit)
import UIKit
#endif

public enum SignalConfidence: String, Codable, Sendable {
    case weak
    case medium
    case strong
}

public struct DetectionSignal<Evidence: Codable & Sendable>: Codable, Sendable {
    public var detected: Bool
    public var method: String
    public var evidence: Evidence?
    public var confidence: SignalConfidence

    private enum CodingKeys: String, CodingKey {
        case detected = "d"
        case method = "m"
        case evidence = "e"
        case confidence = "c"
    }

    public init(detected: Bool, method: String, evidence: Evidence? = nil, confidence: SignalConfidence) {
        self.detected = detected
        self.method = method
        self.evidence = evidence
        self.confidence = confidence
    }
}

public struct InterfaceTypeSignal: Codable, Sendable {
    public var value: String
    public var method: String

    private enum CodingKeys: String, CodingKey {
        case value = "v"
        case method = "m"
    }

    public init(value: String, method: String) {
        self.value = value
        self.method = method
    }
}

public struct NetworkSignals: Codable, Sendable {
    public var interfaceType: InterfaceTypeSignal
    public var isExpensive: Bool
    public var isConstrained: Bool
    public var vpn: DetectionSignal<[String]>
    public var proxy: DetectionSignal<[String: String]>
    public var mcc: String? = nil
    public var mnc: String? = nil

    /// Battery level (0.0 to 1.0). Nil if monitoring is disabled or unavailable.
    public var batteryLevel: Double? = nil
    /// Battery state: "charging" / "unplugged" / "full" / "unknown". Nil if monitoring is disabled or unavailable.
    public var batteryState: String? = nil

    private enum CodingKeys: String, CodingKey {
        case interfaceType = "it"
        case isExpensive = "ie"
        case isConstrained = "ic"
        case vpn = "vp"
        case proxy = "px"
        case mcc = "mc"
        case mnc = "mn"
        case batteryLevel = "bl"
        case batteryState = "bs"
    }

    public var isVPNActive: Bool { vpn.detected }
    public var proxyEnabled: Bool { proxy.detected }

    public static func current() -> NetworkSignals {
        let path = NetworkPathSnapshot.shared.snapshot()
        #if targetEnvironment(simulator)
        // Simulator network stack is the macOS host network; VPN/proxy heuristics will commonly false-positive.
        let vpnIfaces: [String] = []
        let proxyEvidence: [String: String] = [:]
        let vpnMethod = "unavailable_simulator"
        let proxyMethod = "unavailable_simulator"
        #else
        let vpnIfaces = VPNDetector.detectedTunnelInterfaces()
        let proxyEvidence = ProxyDetector.proxyEvidence()
        let vpnMethod = "ifaddrs_prefix"
        let proxyMethod = "CFNetworkCopySystemProxySettings"
        #endif

        // Fetch MCC/MNC from CoreTelephony. Use String? to preserve leading zeros (e.g., "001").
        var mcc: String?
        var mnc: String?
        #if os(iOS)
        if let providers = CTTelephonyNetworkInfo().serviceSubscriberCellularProviders {
            for (_, provider) in providers {
                // Take the first carrier; dual-SIM devices have multiple, we report the primary.
                mcc = provider.mobileCountryCode
                mnc = provider.mobileNetworkCode
                break
            }
        }
        #endif

        let signals = NetworkSignals(
            interfaceType: InterfaceTypeSignal(value: path.interfaceType, method: "NWPathMonitor"),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            vpn: DetectionSignal(
                detected: !vpnIfaces.isEmpty,
                method: vpnMethod,
                evidence: vpnIfaces.isEmpty ? nil : vpnIfaces,
                confidence: .weak
            ),
            proxy: DetectionSignal(
                detected: !proxyEvidence.isEmpty,
                method: proxyMethod,
                evidence: proxyEvidence.isEmpty ? nil : proxyEvidence,
                confidence: .weak
            ),
            mcc: mcc,
            mnc: mnc,
            batteryLevel: nil,
            batteryState: nil
        )

        let (batteryLevel, batteryState) = Self.captureBattery()
        // Mutate after construction to avoid repeating battery capture in every path
        var mutableSignals = signals
        mutableSignals.batteryLevel = batteryLevel
        mutableSignals.batteryState = batteryState

        #if DEBUG
        Logger.log("network: iface=\(mutableSignals.interfaceType.value) expensive=\(mutableSignals.isExpensive) constrained=\(mutableSignals.isConstrained) vpn=\(mutableSignals.isVPNActive) proxy=\(mutableSignals.proxyEnabled) mcc=\(String(describing: mcc)) mnc=\(String(describing: mnc)) batteryLevel=\(mutableSignals.batteryLevel.map { String(format: "%.2f", $0) } ?? "nil") batteryState=\(mutableSignals.batteryState ?? "nil")")
        #endif
        return mutableSignals
    }

    /// Capture battery level and state from UIDevice.
    /// Returns (nil, nil) on non-UIKit platforms or when battery monitoring is unavailable.
    private static func captureBattery() -> (level: Double?, state: String?) {
        #if canImport(UIKit)
        UIDevice.current.isBatteryMonitoringEnabled = true
        let rawLevel = UIDevice.current.batteryLevel
        // batteryLevel returns -1.0 when monitoring is unavailable
        guard rawLevel >= 0 else { return (nil, nil) }
        let state: UIDevice.BatteryState = UIDevice.current.batteryState
        let stateStr: String
        switch state {
        case .unknown: stateStr = "unknown"
        case .unplugged: stateStr = "unplugged"
        case .charging: stateStr = "charging"
        case .full: stateStr = "full"
        @unknown default: stateStr = "unknown"
        }
        return (Double(rawLevel), stateStr)
        #else
        return (nil, nil)
        #endif
    }
}

private final class NetworkPathSnapshot {
    static let shared = NetworkPathSnapshot()
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "CloudPhoneRiskKit.NetworkPathMonitor")
    private let lock = UnfairLock()
    private var latest: NWPath?
    private var started = false

    private init() {}

    func snapshot() -> (interfaceType: String, isExpensive: Bool, isConstrained: Bool) {
        startIfNeeded()
        let path = lock.withLock { latest }
        guard let path else {
            return ("unknown", false, false)
        }

        let type: String
        if path.usesInterfaceType(.wifi) { type = "wifi" }
        else if path.usesInterfaceType(.cellular) { type = "cellular" }
        else if path.usesInterfaceType(.wiredEthernet) { type = "ethernet" }
        else if path.usesInterfaceType(.loopback) { type = "loopback" }
        else { type = "other" }

        return (type, path.isExpensive, path.isConstrained)
    }

    private func startIfNeeded() {
        let shouldStart = lock.withLock {
            let s = !started
            if s { started = true }
            return s
        }
        guard shouldStart else { return }
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.lock.withLock {
                self.latest = path
            }
        }
        monitor.start(queue: queue)
    }
}

enum ProxyDetector {
    static func proxyEvidence() -> [String: String] {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return [:]
        }

        let httpEnabled = (settings[kCFNetworkProxiesHTTPEnable as String] as? NSNumber)?.boolValue ?? false
        let httpProxy = settings[kCFNetworkProxiesHTTPProxy as String] as? String
        let httpPort = settings[kCFNetworkProxiesHTTPPort as String] as? NSNumber
        let pacEnabled = (settings[kCFNetworkProxiesProxyAutoConfigEnable as String] as? NSNumber)?.boolValue ?? false
        let pacURL = settings[kCFNetworkProxiesProxyAutoConfigURLString as String] as? String

        var out: [String: String] = [:]
        if pacEnabled, let pacURL, !pacURL.isEmpty {
            out["pac_url"] = pacURL
        }
        if httpEnabled, let httpProxy, !httpProxy.isEmpty {
            if let httpPort {
                out["http_proxy"] = "\(httpProxy):\(httpPort)"
            } else {
                out["http_proxy"] = httpProxy
            }
        }
        return out
    }
}

enum VPNDetector {
    static func detectedTunnelInterfaces() -> [String] {
        // Best-effort: look for common VPN tunnel interfaces.
        // iOS sandbox prevents deep inspection; this is a signal, not a verdict.
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0, let first = addresses else { return [] }
        defer { freeifaddrs(addresses) }

        var out: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let name = String(cString: current.pointee.ifa_name)
            if name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("ipsec") {
                out.append(name)
            }
            cursor = current.pointee.ifa_next
        }
        return Array(Set(out)).sorted()
    }
}
