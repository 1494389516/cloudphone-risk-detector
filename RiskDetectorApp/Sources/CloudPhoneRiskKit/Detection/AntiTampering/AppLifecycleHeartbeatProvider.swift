import Foundation
#if canImport(UIKit)
import UIKit
#endif

/*
 * AppLifecycleHeartbeatProvider
 *
 * 借鉴自小红书 x208 字段的心跳 t 结构：
 *   小红书在指纹里上报一个心跳计数器结构。如果一个"设备"从来没有心跳数据
 *   （tt 始终为空），说明它不是通过正常 App 启动的，而是通过协议直接请求 API
 *   的（headless protocol replay）。
 *
 * iOS 等价实现：
 *   注册 UIApplication 的生命周期通知。正常用户启动 App 在 ~1s 内一定会触发
 *   didBecomeActiveNotification。如果 SDK 启动后 5 秒内一次 lifecycle 事件都没
 *   触发，且当前 applicationState 又声称是 .active，强烈指示这个进程不是被 UI
 *   驱动的 — 典型场景：headless 反编译注入、unidbg/Frida 直接拉起 SDK 模拟
 *   接口调用。
 *
 * 加权策略：
 *   - 启动 < warmupSeconds: 静默期，不报；
 *   - 启动 ≥ warmupSeconds 且 0 个事件 + applicationState == active: 强信号 (60)；
 *   - 启动 ≥ warmupSeconds 且 0 个事件 + applicationState ∈ {inactive, background}:
 *     合理（如 BackgroundFetch / Push extension），不报；
 *   - 启动 ≥ warmupSeconds 且仅 willResign/didEnterBackground 没有 didBecomeActive:
 *     轻信号 (25) — 异常但不致命。
 */

final class AppLifecycleHeartbeatProvider: RiskSignalProvider {

    static let shared = AppLifecycleHeartbeatProvider()
    let id = "app_lifecycle_heartbeat"

    private static let warmupSeconds: TimeInterval = 5.0

    private let lock = UnfairLock()
    private var providerStartTime: Date = Date()
    private var didBecomeActiveCount: Int = 0
    private var willResignActiveCount: Int = 0
    private var didEnterBackgroundCount: Int = 0
    private var willEnterForegroundCount: Int = 0
    private var observers: [NSObjectProtocol] = []

    private init() {
        // 立即记录启动时间。observers 在第一次 signals() 调用时延迟注册，
        // 避免 init 期间访问 UIApplication（可能不在主线程，会触发警告）。
    }

    deinit {
        unregisterObservers()
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        ensureObserversRegistered()

        let elapsed = Date().timeIntervalSince(providerStartTimeSnapshot())
        let counts = countsSnapshot()
        let totalEvents = counts.didBecomeActiveCount
            + counts.willResignActiveCount
            + counts.didEnterBackgroundCount
            + counts.willEnterForegroundCount

        // 静默期：刚启动，给系统时间发出第一个 didBecomeActive 通知。
        guard elapsed >= Self.warmupSeconds else {
            return []
        }

        let appState = currentApplicationStateString()

        if totalEvents == 0 {
            // 0 个事件 — 是真的 headless 还是合理的后台启动？
            if appState == "active" {
                // 进程 active 但 0 个生命周期事件 — 强信号。
                return [
                    RiskSignal(
                        id: "headless_no_lifecycle_events",
                        category: ObfuscatedConstants.categoryAntiTamper,
                        score: 60,
                        evidence: [
                            "elapsed_seconds": String(format: "%.1f", elapsed),
                            "app_state": appState,
                            "hint": "AppState=.active 但未观察到任何 UIApplication 生命周期通知 — 协议模拟 / unidbg / 注入式启动",
                        ],
                        state: .hard(detected: true),
                        layer: 1,
                        weightHint: 70
                    )
                ]
            } else {
                // 后台 / 不活跃 — 合理静默。
                return []
            }
        }

        if counts.didBecomeActiveCount == 0 && counts.willResignActiveCount + counts.didEnterBackgroundCount > 0 {
            // 只有"resign / background"事件但从未"becomeActive" — 异常但不致命。
            return [
                RiskSignal(
                    id: "lifecycle_partial_no_become_active",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 25,
                    evidence: [
                        "elapsed_seconds": String(format: "%.1f", elapsed),
                        "app_state": appState,
                        "did_become_active_count": "0",
                        "will_resign_count": "\(counts.willResignActiveCount)",
                        "did_enter_background_count": "\(counts.didEnterBackgroundCount)",
                    ],
                    state: .soft(confidence: 0.6),
                    layer: 1,
                    weightHint: 50
                )
            ]
        }

        return []
    }

    // MARK: - State

    private func providerStartTimeSnapshot() -> Date {
        lock.withLock { providerStartTime }
    }

    private struct Counts {
        let didBecomeActiveCount: Int
        let willResignActiveCount: Int
        let didEnterBackgroundCount: Int
        let willEnterForegroundCount: Int
    }

    private func countsSnapshot() -> Counts {
        lock.withLock {
            Counts(
                didBecomeActiveCount: didBecomeActiveCount,
                willResignActiveCount: willResignActiveCount,
                didEnterBackgroundCount: didEnterBackgroundCount,
                willEnterForegroundCount: willEnterForegroundCount
            )
        }
    }

    // MARK: - Observers

    private func ensureObserversRegistered() {
        let alreadyRegistered = lock.withLock { !observers.isEmpty }
        guard !alreadyRegistered else { return }

        #if canImport(UIKit)
        let center = NotificationCenter.default
        let queue = OperationQueue.main

        let didBecomeActive = center.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            self?.lock.withLock { self?.didBecomeActiveCount += 1 }
        }
        let willResign = center.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            self?.lock.withLock { self?.willResignActiveCount += 1 }
        }
        let didBackground = center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            self?.lock.withLock { self?.didEnterBackgroundCount += 1 }
        }
        let willForeground = center.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil, queue: queue
        ) { [weak self] _ in
            self?.lock.withLock { self?.willEnterForegroundCount += 1 }
        }

        lock.withLock {
            observers = [didBecomeActive, willResign, didBackground, willForeground]
        }
        #endif
    }

    private func unregisterObservers() {
        let toRemove = lock.withLock { () -> [NSObjectProtocol] in
            let copy = observers
            observers = []
            return copy
        }
        let center = NotificationCenter.default
        for token in toRemove {
            center.removeObserver(token)
        }
    }

    private func currentApplicationStateString() -> String {
        #if canImport(UIKit)
        if Thread.isMainThread {
            return Self.applicationStateString(UIApplication.shared.applicationState)
        }
        var captured: String = "unknown"
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.main.async {
            captured = Self.applicationStateString(UIApplication.shared.applicationState)
            semaphore.signal()
        }
        // 100ms 超时上限 — 防止主线程死锁场景拖死 signal pipeline
        _ = semaphore.wait(timeout: .now() + .milliseconds(100))
        return captured
        #else
        return "unsupported"
        #endif
    }

    #if canImport(UIKit)
    private static func applicationStateString(_ state: UIApplication.State) -> String {
        switch state {
        case .active: return "active"
        case .inactive: return "inactive"
        case .background: return "background"
        @unknown default: return "unknown"
        }
    }
    #endif
}
