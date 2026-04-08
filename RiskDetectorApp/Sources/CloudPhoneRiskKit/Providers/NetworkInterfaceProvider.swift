import Darwin
import Foundation

/// 网络接口 Provider：检测 network_interface_anomaly
/// 用于识别云手机/模拟器环境下网络接口配置异常
///
/// 检测逻辑（iOS 上 getifaddrs 可用）：
/// - 虚拟接口：接口名含 bridge/tap/tun/veth/docker（排除 utun，iOS 正常隧道接口）-> 可疑
/// - MTU 异常：en0 的 MTU 非 1500（如 0、过大）-> 可疑
/// - 接口数量：> 10 个 -> network_interface_count_anomaly
/// - 缺少蜂窝：机型为 iPhone 且无 pdp_ip0/ap1 等蜂窝接口（简化：接口数<3 且无 pdp 前缀）-> 弱信号
final class NetworkInterfaceProvider: RiskSignalProvider {
    static let shared = NetworkInterfaceProvider()
    private init() {}

    let id = "network_interface"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: SignalID.networkInterfaceAnomaly,
                category: SignalCategory.network,
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 1,
                weightHint: 55
            ),
        ]
        #else
        return collectSignals(snapshot: snapshot)
        #endif
    }

    #if !targetEnvironment(simulator)
    private func collectSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var addresses: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addresses) == 0, let first = addresses else {
            let err = errno
            return [
                RiskSignal(
                    id: SignalID.networkInterfaceAnomaly,
                    category: SignalCategory.network,
                    score: 0,
                    evidence: [
                        "detail": "getifaddrs_failed",
                        "errno": "\(err)",
                    ],
                    state: .unavailable,
                    layer: 1,
                    weightHint: 55
                ),
            ]
        }
        defer { freeifaddrs(addresses) }

        var interfaceNames: [String] = []
        var en0MTU: UInt32?
        var cursor: UnsafeMutablePointer<ifaddrs>? = first

        while let current = cursor {
            let name = String(cString: current.pointee.ifa_name)
            interfaceNames.append(name)

            // AF_LINK (18) 时 ifa_data 指向 struct if_data，含 ifi_mtu
            // Darwin net/if_var.h: 8 u_char + u_int32 ifi_mtu @ offset 8
            if (current.pointee.ifa_addr?.pointee.sa_family).map({ Int32($0) }) == AF_LINK,
               name == "en0",
               let data = current.pointee.ifa_data
            {
                // struct if_data is at least 120 bytes on Darwin; validate offset 8 + sizeof(UInt32) is within bounds
                let minIfDataSize = 12  // offset 8 + 4 bytes for UInt32
                let ifDataPtr = UnsafeRawBufferPointer(start: data, count: minIfDataSize)
                en0MTU = ifDataPtr.load(fromByteOffset: 8, as: UInt32.self)
            }

            cursor = current.pointee.ifa_next
        }

        let uniqueNames = Array(Set(interfaceNames)).sorted()
        let count = uniqueNames.count

        var hitMethods: [String] = []

        // 1. 虚拟接口检测（排除 utun：iOS/macOS 正常隧道接口，非云手机特征）
        let virtualKeywords = ["bridge", "tap", "tun", "veth", "docker"]
        let virtualHits = uniqueNames.filter { name in
            let lower = name.lowercased()
            return virtualKeywords.contains { kw in
                if kw == "tun" {
                    return lower.contains("tun") && !lower.contains("utun")
                }
                return lower.contains(kw)
            }
        }
        if !virtualHits.isEmpty {
            hitMethods.append("virtual_interface:\(virtualHits.joined(separator: ","))")
        }

        // 1b. Hypervisor/CVD 特征接口名检测
        // CVD (Cuttlefish)、QEMU、libvirt 等虚拟化平台暴露的接口命名模式
        let hypervisorKeywords = ["vnet", "qemu", "kvm", "xen", "virtio", "cvd", "crosvm"]
        let hypervisorHits = uniqueNames.filter { name in
            let lower = name.lowercased()
            return hypervisorKeywords.contains { lower.contains($0) }
        }
        if !hypervisorHits.isEmpty {
            hitMethods.append("hypervisor_interface:\(hypervisorHits.joined(separator: ","))")
        }

        // 2. MTU 异常：en0 非 1500
        if let mtu = en0MTU {
            if mtu == 0 || mtu > 9000 {
                hitMethods.append("mtu_anomaly:en0=\(mtu)")
            } else if mtu != 1500 {
                hitMethods.append("mtu_non_standard:en0=\(mtu)")
            }
        }

        // 3. 接口数量 > 10
        if count > 10 {
            hitMethods.append("count_anomaly:\(count)")
        }

        // 4. 缺少蜂窝：iPhone 且 接口数<3 且无 pdp 前缀
        let machine = snapshot.device.hardwareMachine ?? ""
        let isIPhone = machine.lowercased().hasPrefix("iphone")
        let hasCellular = uniqueNames.contains { $0.hasPrefix("pdp_") }
        if isIPhone, count < 3, !hasCellular {
            hitMethods.append("missing_cellular:iPhone_no_pdp")
        }

        guard !hitMethods.isEmpty else {
            return []
        }

        return [
            RiskSignal(
                id: SignalID.networkInterfaceAnomaly,
                category: SignalCategory.network,
                score: 0,
                evidence: [
                    "methods": hitMethods.joined(separator: ";"),
                    "count": "\(count)",
                    "interfaces": uniqueNames.prefix(20).joined(separator: ","),
                ],
                state: .soft(confidence: 0.55),
                layer: 1,
                weightHint: 55
            ),
        ]
    }
    #endif
}
