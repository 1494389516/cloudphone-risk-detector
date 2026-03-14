import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 环境一致性检测：热状态、电池状态、屏幕亮度等长期不变可能暗示云手机/模拟器
final class EnvironmentConsistencyProvider: RiskSignalProvider {
    static let shared = EnvironmentConsistencyProvider()
    private init() {}

    let id = "environment_consistency"

    private static let thermalHistoryKey = "cprk_thermal_history"
    private static let batteryHistoryKey = "cprk_battery_history"
    private static let thermalHistoryMaxCount = 10
    private static let batteryHistoryMaxCount = 10

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        #if canImport(UIKit)
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.thermalStateStaticSignals() },
            { self.batteryStateStaticSignals() },
            { self.screenBrightnessStaticSignals() },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "env_consistency_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "env_consistency_emit_order")
        #else
        return []
        #endif
        #endif
    }

    private func activeMutationStrategy() -> MutationStrategy? {
        guard let mutation = PolicyManager.shared.activePolicy?.mutation else { return nil }
        return MutationStrategy(
            seed: mutation.seed,
            shuffleChecks: mutation.shuffleChecks,
            thresholdJitterBps: mutation.thresholdJitterBps,
            scoreJitterBps: mutation.scoreJitterBps
        )
    }

    // MARK: - thermal_state_static

    private func thermalStateStaticSignals() -> [RiskSignal] {
        let current = thermalStateString(ProcessInfo.processInfo.thermalState)
        appendToHistory(key: Self.thermalHistoryKey, value: current, maxCount: Self.thermalHistoryMaxCount)

        let history = loadHistory(key: Self.thermalHistoryKey)
        guard history.count >= 5 else { return [] }

        let unique = Set(history)
        guard unique.count == 1 else { return [] }

        return [
            RiskSignal(
                id: "thermal_state_static",
                category: "device",
                score: 0,
                evidence: [
                    "state": current,
                    "count": "\(history.count)",
                ],
                state: .soft(confidence: 0.6),
                layer: 3,
                weightHint: 40
            ),
        ]
    }

    private func thermalStateString(_ state: ProcessInfo.ThermalState) -> String {
        switch state {
        case .nominal: return "nominal"
        case .fair: return "fair"
        case .serious: return "serious"
        case .critical: return "critical"
        @unknown default: return "unknown"
        }
    }

    // MARK: - battery_state_static

    private func batteryStateStaticSignals() -> [RiskSignal] {
        #if canImport(UIKit)
        return batteryStateStaticSignalsUIKit()
        #else
        return []
        #endif
    }

    #if canImport(UIKit)
    private func batteryStateStaticSignalsUIKit() -> [RiskSignal] {
        let entry: String
        if Thread.isMainThread {
            entry = captureBatteryEntry()
        } else {
            entry = DispatchQueue.main.sync { captureBatteryEntry() }
        }
        appendToHistory(key: Self.batteryHistoryKey, value: entry, maxCount: Self.batteryHistoryMaxCount)

        let history = loadHistory(key: Self.batteryHistoryKey)
        guard history.count >= 2 else { return [] }

        let states = history.compactMap { parseBatteryEntry($0)?.state }
        let levels = history.compactMap { parseBatteryEntry($0)?.level }
        guard states.count == history.count, levels.count == history.count else { return [] }

        let allCharging = states.allSatisfy { $0 == .charging }
        guard allCharging else { return [] }

        let levelRange = (levels.max() ?? 0) - (levels.min() ?? 0)
        guard levelRange < 0.01 else { return [] }

        return [
            RiskSignal(
                id: "battery_state_static",
                category: "device",
                score: 0,
                evidence: [
                    "state": "charging",
                    "level_range": String(format: "%.4f", levelRange),
                    "count": "\(history.count)",
                ],
                state: .soft(confidence: 0.7),
                layer: 3,
                weightHint: 50
            ),
        ]
    }

    /// 必须在主线程调用（UIDevice 为 @MainActor）
    private func captureBatteryEntry() -> String {
        UIDevice.current.isBatteryMonitoringEnabled = true
        let state = UIDevice.current.batteryState
        let level = Double(UIDevice.current.batteryLevel >= 0 ? UIDevice.current.batteryLevel : 0)
        return "\(batteryStateString(state)):\(String(format: "%.4f", level))"
    }

    private func batteryStateString(_ state: UIDevice.BatteryState) -> String {
        switch state {
        case .unknown: return "unknown"
        case .unplugged: return "unplugged"
        case .charging: return "charging"
        case .full: return "full"
        @unknown default: return "unknown"
        }
    }

    private func parseBatteryEntry(_ entry: String) -> (state: UIDevice.BatteryState, level: Double)? {
        let parts = entry.split(separator: ":", maxSplits: 1).map { String($0).trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2,
              !parts[0].isEmpty, !parts[1].isEmpty,
              let level = Double(parts[1]), level >= 0, level <= 1 else { return nil }
        let stateStr = parts[0]
        let state: UIDevice.BatteryState
        switch stateStr {
        case "charging": state = .charging
        case "unplugged": state = .unplugged
        case "full": state = .full
        default: state = .unknown
        }
        return (state, level)
    }
    #endif

    // MARK: - screen_brightness_static

    private func screenBrightnessStaticSignals() -> [RiskSignal] {
        #if canImport(UIKit)
        return screenBrightnessStaticSignalsUIKit()
        #else
        return []
        #endif
    }

    #if canImport(UIKit)
    private func screenBrightnessStaticSignalsUIKit() -> [RiskSignal] {
        let samples = captureBrightnessSamples()
        guard samples.count >= 5 else { return [] }

        let variance = computeVariance(samples)
        guard variance < 0.001 else { return [] }

        return [
            RiskSignal(
                id: "screen_brightness_static",
                category: "device",
                score: 0,
                evidence: [
                    "variance": String(format: "%.6f", variance),
                    "samples": "\(samples.count)",
                ],
                state: .soft(confidence: 0.5),
                layer: 3,
                weightHint: 35
            ),
        ]
    }

    /// UIScreen 必须在主线程访问；Provider 在 global 队列执行，故通过 main.async + asyncAfter 采样，避免主线程长时间阻塞
    ///
    /// **主线程调用禁止**: collectWithTimeout 在主线程直接同步调用 provider.signals。
    /// 若此时执行 `DispatchQueue.main.async + semaphore.wait`，会产生：
    ///   主线程 wait(2s) → 阻塞 main queue → main.async/asyncAfter 永远不执行 → 超时返回 []
    /// 结果：brightness check 静默失败，且白白阻塞主线程 2 秒。
    /// 解决：检测到主线程调用时直接跳过，等待下次后台线程调用时再采样。
    private func captureBrightnessSamples() -> [Double] {
        guard !Thread.isMainThread else {
            // 主线程 semaphore.wait 会阻塞 main queue，导致 asyncAfter 永不触发 → 2s 超时
            // 跳过采样，等下次在后台线程执行时再收集亮度数据
            Logger.log("captureBrightnessSamples: skipped on main thread (would deadlock)")
            return []
        }
        var samples: [Double] = []
        let semaphore = DispatchSemaphore(value: 0)
        func sample(index: Int) {
            samples.append(Double(UIScreen.main.brightness))
            if index < 4 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { sample(index: index + 1) }
            } else {
                semaphore.signal()
            }
        }
        DispatchQueue.main.async { sample(index: 0) }
        _ = semaphore.wait(timeout: .now() + 2.0)
        return samples
    }
    #endif

    private func computeVariance(_ series: [Double]) -> Double {
        guard series.count > 1 else { return 0 }
        let mean = series.reduce(0, +) / Double(series.count)
        let squaredDiffs = series.map { pow($0 - mean, 2) }
        // 使用样本方差（÷n-1），而非总体方差（÷n）。
        // 总体公式在样本数较小时（5-10个）会低估方差约 10-20%，
        // 可能导致正常设备（亮度有轻微波动）被误判为亮度静止。
        return squaredDiffs.reduce(0, +) / Double(series.count - 1)
    }

    // MARK: - Persistence

    private func appendToHistory(key: String, value: String, maxCount: Int) {
        var history = loadHistory(key: key)
        history.append(value)
        if history.count > maxCount {
            history.removeFirst(history.count - maxCount)
        }
        UserDefaults.standard.set(history.joined(separator: ","), forKey: key)
    }

    private func loadHistory(key: String) -> [String] {
        guard let raw = UserDefaults.standard.string(forKey: key), !raw.isEmpty else {
            return []
        }
        return raw.split(separator: ",")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}
