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
            { self.environmentFreezeLockSignals() },
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
            RiskSignal(
                id: SignalID.batteryLevelStatic,
                category: "device",
                score: 0,
                evidence: [
                    "level_range": String(format: "%.4f", levelRange),
                    "count": "\(history.count)",
                ],
                state: .soft(confidence: 0.7),
                layer: 3,
                weightHint: 50
            ),
            RiskSignal(
                id: SignalID.noChargeStateChange,
                category: "device",
                score: 0,
                evidence: [
                    "state": "charging",
                    "count": "\(history.count)",
                ],
                state: .soft(confidence: 0.68),
                layer: 3,
                weightHint: 45
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

    // MARK: - environment_freeze_lock

    /// CVD 云手机三维环境冻结联合检测：
    /// 热状态 + 电池 + 屏幕亮度三者同时静止是真实设备上极不可能的组合。
    /// 真实 iPhone 长期使用必然会出现热状态波动（CPU 负载）、电池电量变化
    /// （充放电循环）、亮度调节（自动亮度/手动操作）。三者全冻结强烈暗示
    /// CVD 或云手机虚拟环境。
    private func environmentFreezeLockSignals() -> [RiskSignal] {
        #if canImport(UIKit)
        let thermalHistory = loadHistory(key: Self.thermalHistoryKey)
        let batteryHistory = loadHistory(key: Self.batteryHistoryKey)

        // 至少需要每个维度 3 个以上历史点才有判定意义
        guard thermalHistory.count >= 3, batteryHistory.count >= 2 else {
            return []
        }

        let thermalFrozen = Set(thermalHistory).count <= 1
        let batteryFrozen = Set(batteryHistory).count <= 1

        // 亮度无 history 存储，使用当前采样代替（非主线程安全时跳过）
        let brightnessFrozen: Bool
        if !Thread.isMainThread {
            let samples = captureBrightnessSamplesSync()
            brightnessFrozen = samples.count >= 3 && computeVariance(samples) < 0.001
        } else {
            brightnessFrozen = false
        }

        // 计分：每个冻结维度贡献权重，2/3 以上才触发信号
        let frozenCount = [thermalFrozen, batteryFrozen, brightnessFrozen].filter { $0 }.count
        guard frozenCount >= 2 else { return [] }

        let confidence: Double
        switch frozenCount {
        case 3:  confidence = 0.85
        case 2:  confidence = 0.65
        default: return []
        }

        return [
            RiskSignal(
                id: SignalID.environmentFreezeLock,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: [
                    "thermal_frozen": "\(thermalFrozen)",
                    "battery_frozen": "\(batteryFrozen)",
                    "brightness_frozen": "\(brightnessFrozen)",
                    "frozen_dimensions": "\(frozenCount)/3",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 75
            ),
        ]
        #else
        return []
        #endif
    }

    #if canImport(UIKit)
    /// 非主线程安全的亮度采样（不使用 asyncAfter，直接同步读取多次）
    private func captureBrightnessSamplesSync() -> [Double] {
        guard !Thread.isMainThread else { return [] }
        var samples: [Double] = []
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.main.async {
            for _ in 0..<3 {
                samples.append(Double(UIScreen.main.brightness))
            }
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 1.0)
        return samples
    }
    #endif

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
