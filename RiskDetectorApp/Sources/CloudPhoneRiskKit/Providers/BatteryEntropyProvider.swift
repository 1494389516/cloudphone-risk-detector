import Foundation
#if canImport(IOKit)
import IOKit
import IOKit.ps
#endif
#if canImport(UIKit)
import UIKit
#endif

struct BatteryEntropyCollector {
    func collectVoltageSeries(samples: Int, interval: TimeInterval) -> [Double] {
        #if targetEnvironment(simulator)
        return []
        #elseif canImport(UIKit)
        return collectFromUIDevice(samples: samples, interval: interval)
        #elseif canImport(IOKit)
        return collectFromIOKit(samples: samples, interval: interval)
        #else
        return []
        #endif
    }

    func computeVariance(_ series: [Double]) -> Double {
        guard series.count > 1 else { return 0 }
        let mean = series.reduce(0, +) / Double(series.count)
        let squaredDiffs = series.map { pow($0 - mean, 2) }
        return squaredDiffs.reduce(0, +) / Double(series.count)
    }

    func readChargeCounter() -> Int? {
        #if targetEnvironment(simulator)
        return nil
        #elseif os(macOS) && canImport(IOKit)
        return readPowerSourceInt(key: "ChargeCounter")
        #else
        return nil
        #endif
    }

    func readEnergyCounter() -> Int? {
        #if targetEnvironment(simulator)
        return nil
        #elseif os(macOS) && canImport(IOKit)
        return readPowerSourceInt(key: "EnergyCounter")
        #else
        return nil
        #endif
    }

    #if os(macOS) && canImport(IOKit)
    private func collectFromIOKit(samples: Int, interval: TimeInterval) -> [Double] {
        var result: [Double] = []
        for _ in 0..<samples {
            if let voltage = readPowerSourceVoltage() {
                result.append(voltage)
            }
            if result.count < samples {
                Thread.sleep(forTimeInterval: interval)
            }
        }
        return result
    }

    private func readPowerSourceVoltage() -> Double? {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue() as CFTypeRef? else { return nil }
        guard let list = IOPSCopyPowerSourcesList(info)?.takeRetainedValue() as? [CFTypeRef], !list.isEmpty else { return nil }
        guard let desc = IOPSGetPowerSourceDescription(info, list[0])?.takeUnretainedValue() as? [String: Any] else { return nil }
        if let v = desc["Voltage"] as? Int {
            return Double(v)
        }
        if let v = desc["Voltage"] as? Double {
            return v
        }
        if let cap = desc["Current Capacity"] as? Int {
            return Double(cap)
        }
        return nil
    }

    private func readPowerSourceInt(key: String) -> Int? {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue() as CFTypeRef? else { return nil }
        guard let list = IOPSCopyPowerSourcesList(info)?.takeRetainedValue() as? [CFTypeRef], !list.isEmpty else { return nil }
        guard let desc = IOPSGetPowerSourceDescription(info, list[0])?.takeUnretainedValue() as? [String: Any] else { return nil }
        if let v = desc[key] as? Int {
            return v
        }
        if let v = desc[key] as? NSNumber {
            return v.intValue
        }
        let altKey = key == "ChargeCounter" ? "Charge Counter" : (key == "EnergyCounter" ? "Energy Counter" : key)
        if let v = desc[altKey] as? Int {
            return v
        }
        if let v = desc[altKey] as? NSNumber {
            return v.intValue
        }
        return nil
    }
    #endif

    #if canImport(UIKit)
    private func collectFromUIDevice(samples: Int, interval: TimeInterval) -> [Double] {
        UIDevice.current.isBatteryMonitoringEnabled = true
        var result: [Double] = []
        for _ in 0..<samples {
            let level = Float(UIDevice.current.batteryLevel)
            result.append(Double(level >= 0 ? level : 0) * 1000)
            if result.count < samples {
                Thread.sleep(forTimeInterval: interval)
            }
        }
        return result
    }
    #endif
}

final class BatteryEntropyProvider: RiskSignalProvider {
    static let shared = BatteryEntropyProvider()

    let id = "battery_entropy"

    private let collector: BatteryEntropyCollector

    init(collector: BatteryEntropyCollector = BatteryEntropyCollector()) {
        self.collector = collector
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.chargeCounterSignals() },
            { self.voltageEntropySignals() },
            { self.energyCounterSignals() },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "battery_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "battery_emit_order")
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

    private func chargeCounterSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        guard let cc = collector.readChargeCounter() else { return [] }
        if cc == -1 || cc == 0 {
            return [
                RiskSignal(
                    id: "battery_charge_counter",
                    category: "device",
                    score: 0,
                    evidence: ["charge_counter": "\(cc)"],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 95
                ),
            ]
        }
        return []
        #endif
    }

    private func voltageEntropySignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "battery_voltage_entropy",
                category: "device",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 3,
                weightHint: 55
            ),
        ]
        #else
        let series = collector.collectVoltageSeries(samples: 5, interval: 0.1)
        guard series.count >= 2 else {
            return [
                RiskSignal(
                    id: "battery_voltage_entropy",
                    category: "device",
                    score: 0,
                    evidence: ["detail": "insufficient_samples"],
                    state: .unavailable,
                    layer: 3,
                    weightHint: 55
                ),
            ]
        }

        let variance = collector.computeVariance(series)
        let confidence: Double
        if variance < 0.001 {
            confidence = 0.9
        } else if variance < 0.01 {
            confidence = 0.7
        } else if variance < 0.1 {
            confidence = 0.5
        } else {
            confidence = 0.2
        }

        return [
            RiskSignal(
                id: "battery_voltage_entropy",
                category: "device",
                score: 0,
                evidence: [
                    "variance": String(format: "%.6f", variance),
                    "samples": "\(series.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 3,
                weightHint: 55
            ),
        ]
        #endif
    }

    private func energyCounterSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        guard let ec = collector.readEnergyCounter() else { return [] }
        if ec == -1 || ec == 0 {
            return [
                RiskSignal(
                    id: "battery_energy_counter",
                    category: "device",
                    score: 0,
                    evidence: ["energy_counter": "\(ec)"],
                    state: .soft(confidence: 0.8),
                    layer: 1,
                    weightHint: 85
                ),
            ]
        }
        return []
        #endif
    }
}
