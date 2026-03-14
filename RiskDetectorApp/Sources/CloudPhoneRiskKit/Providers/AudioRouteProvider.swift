import Foundation
#if canImport(AVFoundation)
import AVFoundation
#endif

/// 音频路由探测 Provider
///
/// 检测云手机/虚拟化环境下的音频输出异常：
/// - USB/LineOut 路由：云手机常通过 USB 或 LineOut 输出到宿主机，真机通常为扬声器/听筒
/// - 虚拟音频输出：portType.rawValue 含 "Virtual" 表示虚拟音频设备
///
/// 注意：仅只读 currentRoute，不调用 setActive/setCategory，避免干扰主业务音频。
/// 读取 currentRoute 无需先 activate，Apple 文档确认可随时读取。
/// AVAudioSession 主线程访问更安全，使用 runOnMainIfNeeded。
final class AudioRouteProvider: RiskSignalProvider {
    static let shared = AudioRouteProvider()
    private init() {}

    let id = "audio_route"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        #if os(iOS)
        return runOnMainIfNeeded { collectSignals() }
        #else
        return []
        #endif
        #endif
    }

    #if !targetEnvironment(simulator) && os(iOS)
    private func collectSignals() -> [RiskSignal] {
        var out: [RiskSignal] = []
        let session = AVAudioSession.sharedInstance()
        let outputs = session.currentRoute.outputs

        // CarPlay 连接时也会走 USB，需排除以免误报
        let isCarPlayConnected = (session.availableInputs ?? []).contains { input in
            input.portType == .carAudio || input.portName == "CarPlay"
        }

        for port in outputs {
            let portType = port.portType
            let rawValue = portType.rawValue

            // USB 或 LineOut 路由 -> 云手机常见（输出到宿主机）
            // 排除 CarPlay：真机连 CarPlay 时也会走 USB
            // 蓝牙耳机 (.bluetoothA2DP/.bluetoothHFP/.bluetoothLE) 不触发，避免误杀录屏+充电+蓝牙的正常用户
            if !isCarPlayConnected && (portType == .usbAudio || portType == .lineOut) {
                out.append(RiskSignal(
                    id: "usb_audio_routed",
                    category: "device",
                    score: 0,
                    evidence: [
                        "portType": rawValue,
                        "portName": port.portName,
                    ],
                    state: .soft(confidence: 0.7),
                    layer: 1,
                    weightHint: 55
                ))
                break
            }
        }

        for port in outputs {
            let rawValue = port.portType.rawValue
            // rawValue 大小写不固定（如 "virtual"/"Virtual"），用不敏感匹配
            if rawValue.localizedCaseInsensitiveContains("virtual") {
                out.append(RiskSignal(
                    id: "virtual_audio_output",
                    category: "device",
                    score: 0,
                    evidence: [
                        "portType": rawValue,
                        "portName": port.portName,
                    ],
                    state: .soft(confidence: 0.8),
                    layer: 1,
                    weightHint: 70
                ))
                break
            }
        }

        return out
    }

    private func runOnMainIfNeeded<T>(_ block: () -> T) -> T {
        if Thread.isMainThread {
            return block()
        }
        return DispatchQueue.main.sync(execute: block)
    }
    #endif
}
