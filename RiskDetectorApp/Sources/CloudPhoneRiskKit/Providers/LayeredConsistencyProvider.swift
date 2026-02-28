import Foundation
import Darwin

final class LayeredConsistencyProvider: RiskSignalProvider {
    static let shared = LayeredConsistencyProvider()
    private init() {}

    let id = "layered_consistency"

    private static let criticalSymbols: [String] = [
        "sysctlbyname",
        "sysctl",
        "getenv",
        "dlopen",
        "ptrace",
    ]

    private static let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        var out: [RiskSignal] = []

        let checks: [() -> [RiskSignal]] = [
            { self.detectPrologueIntegrity() },
            { self.detectTimingAnomaly().map { [$0] } ?? [] },
            { self.detectSensorEntropy(snapshot: snapshot).map { [$0] } ?? [] },
            { self.detectTouchEntropy(snapshot: snapshot).map { [$0] } ?? [] },
        ]
        let orderedChecks = planner.maybeShuffle(checks, salt: "layer23_checks")
        for check in orderedChecks {
            out.append(contentsOf: check())
        }

        return planner.maybeShuffle(out, salt: "layer23_emit_order")
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

    private func detectPrologueIntegrity() -> [RiskSignal] {
        var tampered: [String] = []
        for symbol in Self.criticalSymbols {
            guard let ptr = dlsym(Self.rtldDefault, symbol) else { continue }
            let bytes = ptr.assumingMemoryBound(to: UInt8.self)
            let first = bytes[0]
            let second = bytes[1]

            let hooked: Bool
            switch first {
            case 0x14, 0x17:
                hooked = true
            case 0xD6:
                hooked = true
            case 0x00 where second == 0x00:
                hooked = true
            default:
                hooked = false
            }

            if hooked {
                tampered.append(symbol)
            }
        }

        if tampered.isEmpty {
            return [
                RiskSignal(
                    id: "hook_detected",
                    category: "anti_tamper",
                    score: 0,
                    evidence: ["status": "clean"],
                    state: .hard(detected: false),
                    layer: 2,
                    weightHint: 80
                ),
            ]
        }

        let hasCriticalHook = tampered.contains("sysctlbyname") || tampered.contains("sysctl")
        let hookState: RiskSignalState = hasCriticalHook ? .hard(detected: true) : .soft(confidence: 0.7)

        return [
            RiskSignal(
                id: "hook_detected",
                category: "anti_tamper",
                score: 0,
                evidence: ["hooked": tampered.joined(separator: ",")],
                state: hookState,
                layer: 2,
                weightHint: 80
            ),
            RiskSignal(
                id: "tampering_detected",
                category: "anti_tamper",
                score: 0,
                evidence: ["hooked": tampered.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ),
        ]
    }

    private func detectTimingAnomaly() -> RiskSignal? {
        let medianUs = measureSysctlMedianMicroseconds(sampleCount: 24)
        guard medianUs > 0 else { return nil }

        if medianUs > 50 {
            let confidence = min(0.9, medianUs / 200.0)
            return RiskSignal(
                id: "timing_anomaly",
                category: "anti_tamper",
                score: 0,
                evidence: ["median_us": String(format: "%.1f", medianUs)],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 45
            )
        }

        return RiskSignal(
            id: "timing_anomaly",
            category: "anti_tamper",
            score: 0,
            evidence: ["median_us": String(format: "%.1f", medianUs)],
            state: .soft(confidence: 0),
            layer: 2,
            weightHint: 45
        )
    }

    private func detectSensorEntropy(snapshot: RiskSnapshot) -> RiskSignal? {
        let motion = snapshot.behavior.motion
        guard motion.sampleCount > 0 else {
            return RiskSignal(
                id: "sensor_entropy",
                category: "behavior",
                score: 0,
                evidence: ["detail": "motion_unavailable"],
                state: .unavailable,
                layer: 3,
                weightHint: 60
            )
        }

        let stillness = motion.stillnessRatio ?? 0
        let energy = motion.motionEnergy ?? 0
        let lowNoise = energy < 1e-7
        let suspiciousStillness = stillness > 0.999 && snapshot.behavior.actionCount >= 10
        let confidence = (lowNoise ? 0.45 : 0) + (suspiciousStillness ? 0.35 : 0)

        return RiskSignal(
            id: "sensor_entropy",
            category: "behavior",
            score: 0,
            evidence: [
                "stillness": "\(stillness)",
                "motion_energy": "\(energy)",
            ],
            state: .soft(confidence: confidence),
            layer: 3,
            weightHint: 60
        )
    }

    private func detectTouchEntropy(snapshot: RiskSnapshot) -> RiskSignal? {
        let touch = snapshot.behavior.touch
        guard touch.sampleCount >= 10 else {
            return RiskSignal(
                id: "touch_entropy",
                category: "behavior",
                score: 0,
                evidence: ["detail": "insufficient_samples"],
                state: .unavailable,
                layer: 3,
                weightHint: 50
            )
        }

        guard let forceVar = touch.forceVariance, let radiusVar = touch.majorRadiusVariance else {
            return RiskSignal(
                id: "touch_entropy",
                category: "behavior",
                score: 0,
                evidence: ["detail": "force_or_radius_unavailable"],
                state: .unavailable,
                layer: 3,
                weightHint: 50
            )
        }

        let virtualTouch = forceVar < 1e-10 && radiusVar < 0.01
        let confidence = virtualTouch ? 0.75 : 0
        return RiskSignal(
            id: "touch_entropy",
            category: "behavior",
            score: 0,
            evidence: [
                "force_variance": "\(forceVar)",
                "radius_variance": "\(radiusVar)",
            ],
            state: .soft(confidence: confidence),
            layer: 3,
            weightHint: 50
        )
    }

    private func measureSysctlMedianMicroseconds(sampleCount: Int) -> Double {
        guard sampleCount > 0 else { return 0 }
        var values: [UInt64] = []
        values.reserveCapacity(sampleCount)

        for _ in 0..<sampleCount {
            var size: size_t = 0
            let t0 = mach_absolute_time()
            _ = sysctlbyname("hw.machine", nil, &size, nil, 0)
            let t1 = mach_absolute_time()
            values.append(t1 - t0)
        }

        guard values.isEmpty == false else { return 0 }
        values.sort()
        let median = values[sampleCount / 2]

        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)

        let ns = Double(median) * Double(timebase.numer) / Double(timebase.denom)
        return ns / 1000.0
    }
}
