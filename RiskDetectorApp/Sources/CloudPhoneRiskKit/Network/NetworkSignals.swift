import CFNetwork
import Darwin
import Foundation
import Network

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
            )
        )
        Logger.log("network: iface=\(signals.interfaceType.value) expensive=\(signals.isExpensive) constrained=\(signals.isConstrained) vpn=\(signals.isVPNActive) proxy=\(signals.proxyEnabled)")
        return signals
    }
}

private final class NetworkPathSnapshot {
    static let shared = NetworkPathSnapshot()
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "CloudPhoneRiskKit.NetworkPathMonitor")
    private let lock = NSLock()
    private var latest: NWPath?
    private var started = false

    private init() {}

    func snapshot() -> (interfaceType: String, isExpensive: Bool, isConstrained: Bool) {
        startIfNeeded()
        guard let path = latest else {
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
        lock.lock()
        let shouldStart = !started
        if shouldStart { started = true }
        lock.unlock()
        guard shouldStart else { return }
        monitor.pathUpdateHandler = { [weak self] path in
            self?.latest = path
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
