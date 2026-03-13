import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 显示多路复用探测 Provider
///
/// 检测云手机/虚拟化环境下的显示输出异常：
/// - screen_captured：屏幕正在被录屏/投屏（UIScreen.isCaptured）
/// - external_display_attached：外接显示器已连接（UIScreen.screens.count > 1）
///
/// 云手机常通过录屏或外接显示输出到宿主机，真机单用户场景下较少同时出现。
///
/// ## 已知边界
/// - **isCaptured 竞态**：录屏结束瞬间，isCaptured 可能与 capturedDidChangeNotification 不同步，
///   存在短暂过渡期；单次采样可能偶发误报/漏报，建议在组合规则中与其他信号联合判断。
/// - **UIScreen.screens**：仅外接键盘/触控板不会增加 screens.count，只有外接显示器才会。iPad 外接
///   Magic Keyboard 等不会误报 external_display_attached。
final class DisplayMuxProvider: RiskSignalProvider {
    static let shared = DisplayMuxProvider()
    private init() {}

    let id = "display_mux"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        #if canImport(UIKit)
        return runOnMainIfNeeded { collectSignals() }
        #else
        return []
        #endif
        #endif
    }

    #if !targetEnvironment(simulator) && canImport(UIKit)
    private func collectSignals() -> [RiskSignal] {
        var out: [RiskSignal] = []

        // 屏幕正在被录屏/投屏
        if UIScreen.main.isCaptured {
            out.append(RiskSignal(
                id: SignalID.screenCaptured,
                category: "device",
                score: 0,
                evidence: ["detail": "isCaptured"],
                state: .soft(confidence: 0.75),
                layer: 1,
                weightHint: 50
            ))
        }

        // 外接显示器已连接
        if UIScreen.screens.count > 1 {
            out.append(RiskSignal(
                id: SignalID.externalDisplayAttached,
                category: "device",
                score: 0,
                evidence: [
                    "screenCount": "\(UIScreen.screens.count)",
                    "detail": "external_display",
                ],
                state: .soft(confidence: 0.6),
                layer: 1,
                weightHint: 45
            ))
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
