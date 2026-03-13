import Foundation
#if canImport(CoreTelephony)
import CoreTelephony
#endif
#if canImport(UIKit)
import UIKit
#endif

/// 基带隔离探测 Provider
///
/// 检测云手机/虚拟化环境中基带与系统 App 的异常：
/// - 无蜂窝运营商：CTTelephonyNetworkInfo.serviceSubscriberCellularProviders 全为空或 mobileNetworkCode 全为 nil
///   - iOS 16+ 已废弃此 API，Apple 未提供替代；当前仍可用，未来可能进一步受限。
/// - 系统 App 缺失：iPhone 上 canOpenURL(itms-watch://) 为 false 表示 Watch 等系统 App 被阉割
///   - iPad 无 Watch App，不检测此项。
///
/// 注意：CTTelephonyNetworkInfo、UIApplication.canOpenURL 可能需主线程，使用 runOnMainIfNeeded 保险。
/// LSApplicationQueriesSchemes 需在 Info.plist 配置 itms-watch、x-apple-health 等，否则 canOpenURL 恒返回 false；本 Provider 会运行时校验，缺失时跳过 system_app_missing 检测。
final class BasebandIsolationProvider: RiskSignalProvider {
    static let shared = BasebandIsolationProvider()

    let id = "baseband_isolation"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        return runOnMainIfNeeded {
            var out: [RiskSignal] = []

            if let s = noCellularProviderSignal() {
                out.append(s)
            }
            if let s = systemAppMissingSignal() {
                out.append(s)
            }

            return out
        }
        #endif
    }

    /// 若当前非主线程则派发到主线程同步执行
    private func runOnMainIfNeeded<T>(_ block: () -> T) -> T {
        if Thread.isMainThread {
            return block()
        }
        return DispatchQueue.main.sync(execute: block)
    }

    // MARK: - 无蜂窝运营商

    /// serviceSubscriberCellularProviders 全为空或 mobileNetworkCode 全为 nil -> no_cellular_provider
    /// 注意：iOS 16+ 已废弃 serviceSubscriberCellularProviders，无官方替代 API，当前仍可用。
    private func noCellularProviderSignal() -> RiskSignal? {
        #if canImport(CoreTelephony)
        let networkInfo = CTTelephonyNetworkInfo()
        guard let providers = networkInfo.serviceSubscriberCellularProviders else {
            return RiskSignal(
                id: "no_cellular_provider",
                category: "device",
                score: 0,
                evidence: ["reason": "serviceSubscriberCellularProviders_nil"],
                state: .soft(confidence: 0.6),
                layer: 1,
                weightHint: 50
            )
        }

        guard !providers.isEmpty else {
            return RiskSignal(
                id: "no_cellular_provider",
                category: "device",
                score: 0,
                evidence: ["reason": "providers_empty"],
                state: .soft(confidence: 0.6),
                layer: 1,
                weightHint: 50
            )
        }

        let allMNCNil = providers.values.allSatisfy { $0.mobileNetworkCode == nil }
        guard allMNCNil else { return nil }

        return RiskSignal(
            id: "no_cellular_provider",
            category: "device",
            score: 0,
            evidence: ["reason": "mobileNetworkCode_all_nil"],
            state: .soft(confidence: 0.6),
            layer: 1,
            weightHint: 50
        )
        #else
        return nil
        #endif
    }

    // MARK: - 系统 App 缺失

    /// iPhone 上 canOpenURL(itms-watch://) 为 false 表示 Watch 等系统 App 被阉割
    /// 注意：若 Info.plist 未配置 LSApplicationQueriesSchemes 含 itms-watch，canOpenURL 恒 false 会误报，故先校验。
    private func systemAppMissingSignal() -> RiskSignal? {
        #if canImport(UIKit)
        guard UIDevice.current.userInterfaceIdiom == .phone else { return nil }

        // LSApplicationQueriesSchemes 缺失 itms-watch 时 canOpenURL 恒 false，导致误报
        let schemes = Bundle.main.infoDictionary?["LSApplicationQueriesSchemes"] as? [String] ?? []
        guard schemes.contains("itms-watch") else { return nil }

        guard let url = URL(string: "itms-watch://") else { return nil }

        let canOpen = UIApplication.shared.canOpenURL(url)
        guard !canOpen else { return nil }

        return RiskSignal(
            id: "system_app_missing",
            category: "device",
            score: 0,
            evidence: [
                "scheme": "itms-watch",
                "reason": "iphone_watch_app_unreachable",
            ],
            state: .soft(confidence: 0.75),
            layer: 1,
            weightHint: 65
        )
        #else
        return nil
        #endif
    }
}
