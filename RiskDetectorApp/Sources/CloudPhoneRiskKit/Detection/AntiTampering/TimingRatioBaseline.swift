import CRiskCore
import Foundation

struct TimingRatioBaseline {
    struct PairEvaluation {
        let baselineName: String
        let probeName: String
        let sampleCount: Int
        let baselineMedianNs: UInt64
        let probeMedianNs: UInt64
        let medianRatio: Double
        let p95Ratio: Double
        let isAnomalous: Bool
    }

    private static var timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        ticks * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
    }

    // MARK: - Sampling Noise (Stalker DBT Overhead Amplification)

    /// 在采样循环中调用的无副作用计算噪声，用于放大 Stalker DBT 的指令翻译开销。
    /// 包含 5–10 次累加/位运算、多分支逻辑及 volatile 风格内存读写，使 Frida Stalker 产生更多开销。
    @_optimize(none)
    static func samplingNoise() {
        var acc: UInt64 = 0x9E3779B97F4A7C15
        let ptr = UnsafeMutablePointer<UInt64>.allocate(capacity: 1)
        defer { ptr.deallocate() }

        for i in 0..<8 {
            switch i & 3 {
            case 0:
                acc = acc &+ 1
                acc ^= acc << 13
            case 1:
                acc ^= acc >> 7
                acc = acc &* 0x9E3779B97F4A7C15
            case 2:
                acc ^= acc << 17
                acc = acc &+ (acc >> 11)
            default:
                acc = (acc ^ (acc << 5)) &+ (acc >> 3)
            }
            ptr.pointee = acc
            acc = ptr.pointee
        }
    }

    // MARK: - Amplified Stalker Probe

    /// 放大版时序探针：通过间接函数指针调用和交替多种 syscall，最大化 Stalker DBT 开销，
    /// 同时保持原生执行速度不变。Stalker 必须为每个间接分支目标做翻译，无法缓存优化。
    /// 返回 (getpidSamples, probeSamples)，单位为 mach_absolute_time ticks（比值不受单位影响）。
    @_optimize(none)
    static func amplifiedSamples(count: Int = defaultSampleCount) -> (getpid: [UInt64], stat: [UInt64]) {
#if targetEnvironment(simulator)
        return ([], [])
#else
        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(count)
        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(count)

        typealias PidFn = @convention(c) () -> pid_t
        typealias UidFn = @convention(c) () -> uid_t

        // 将 syscall wrapper 存入可变指针槽位——Stalker 无法对间接分支做静态翻译缓存
        let fnSlot = UnsafeMutablePointer<PidFn>.allocate(capacity: 2)
        defer { fnSlot.deallocate() }
        fnSlot[0] = cprisk_getpid_direct
        fnSlot[1] = cprisk_getpid_direct

        let uidFn: UidFn = cprisk_getuid_direct

        let statFirst = Bool.random()

        func sampleGetpidAmplified() {
            for i in 0..<count {
                samplingNoise()
                // 在测量间隙插入 getuid 调用，迫使 Stalker 翻译更多不同的 syscall 路径
                _ = uidFn()

                let slot = i & 1
                let fn = fnSlot[slot]
                let start = mach_absolute_time()
                _ = fn()
                let end = mach_absolute_time()
                getpidSamples.append(end &- start)
            }
        }

        func sampleStatAmplified() {
            for i in 0..<count {
                samplingNoise()
                _ = uidFn()

                let pathIdx = i & 1
                let path = pathIdx == 0 ? "/usr/lib/dyld" : "/etc/passwd"
                let start = mach_absolute_time()
                _ = path.withCString { cprisk_access_direct($0, F_OK, nil) }
                let end = mach_absolute_time()
                statSamples.append(end &- start)
            }
        }

        if statFirst {
            sampleStatAmplified()
            sampleGetpidAmplified()
        } else {
            sampleGetpidAmplified()
            sampleStatAmplified()
        }

        return (getpidSamples, statSamples)
#endif
    }

    struct Evaluation {
        let medianRatio: Double
        let p95Ratio: Double
        let isAnomalous: Bool
    }

    private struct TimingStats {
        let median: UInt64
        let p95: UInt64
    }

    static let defaultSampleCount = 30
    static let defaultRatioThreshold = 15.0

    @_optimize(none)
    private static func measureTicks(
        noiseIterations: Int = 6,
        block: () -> Void
    ) -> UInt64 {
        for _ in 0..<noiseIterations {
            samplingNoise()
        }
        let start = mach_absolute_time()
        block()
        let end = mach_absolute_time()
        return end &- start
    }

    static func evaluatePair(
        baselineName: String,
        probeName: String,
        sampleCount: Int = defaultSampleCount,
        warmupCount: Int = 3,
        noiseIterations: Int = 6,
        ratioThreshold: Double = defaultRatioThreshold,
        baseline: () -> Void,
        probe: () -> Void
    ) -> PairEvaluation? {
        guard sampleCount > 0 else { return nil }

        for _ in 0..<warmupCount {
            baseline()
            probe()
        }

        var baselineSamples: [UInt64] = []
        baselineSamples.reserveCapacity(sampleCount)
        var probeSamples: [UInt64] = []
        probeSamples.reserveCapacity(sampleCount)

        for i in 0..<sampleCount {
            let baselineFirst = (i % 2 == 0)
            if baselineFirst {
                baselineSamples.append(measureTicks(noiseIterations: noiseIterations, block: baseline))
                probeSamples.append(measureTicks(noiseIterations: noiseIterations, block: probe))
            } else {
                probeSamples.append(measureTicks(noiseIterations: noiseIterations, block: probe))
                baselineSamples.append(measureTicks(noiseIterations: noiseIterations, block: baseline))
            }
        }

        guard let evaluation = evaluate(
            getpidSamples: baselineSamples,
            statSamples: probeSamples,
            ratioThreshold: ratioThreshold
        ) else {
            return nil
        }

        let baselineStats = computeStats(baselineSamples)
        let probeStats = computeStats(probeSamples)
        return PairEvaluation(
            baselineName: baselineName,
            probeName: probeName,
            sampleCount: sampleCount,
            baselineMedianNs: nanoseconds(from: baselineStats.median),
            probeMedianNs: nanoseconds(from: probeStats.median),
            medianRatio: evaluation.medianRatio,
            p95Ratio: evaluation.p95Ratio,
            isAnomalous: evaluation.isAnomalous
        )
    }

    static func evaluate(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = defaultRatioThreshold
    ) -> Evaluation? {
        let getpidStats = computeStats(getpidSamples)
        let statStats = computeStats(statSamples)

        guard getpidStats.median > 0 else { return nil }

        let medianRatio = Double(statStats.median) / Double(getpidStats.median)
        let p95Ratio = getpidStats.p95 > 0
            ? Double(statStats.p95) / Double(getpidStats.p95)
            : 0.0

        return Evaluation(
            medianRatio: medianRatio,
            p95Ratio: p95Ratio,
            isAnomalous: medianRatio > ratioThreshold || p95Ratio > ratioThreshold
        )
    }

    static func isAnomalous(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = defaultRatioThreshold
    ) -> Bool {
        evaluate(
            getpidSamples: getpidSamples,
            statSamples: statSamples,
            ratioThreshold: ratioThreshold
        )?.isAnomalous ?? false
    }

    private static func computeStats(_ samples: [UInt64]) -> TimingStats {
        let sorted = samples.sorted()
        let count = sorted.count
        guard count > 0 else {
            return TimingStats(median: 0, p95: 0)
        }

        let median = count % 2 == 1
            ? sorted[count / 2]
            : (sorted[count / 2 - 1] + sorted[count / 2]) / 2
        let p95Index = min(Int(Double(count) * 0.95), count - 1)
        let p95 = sorted[p95Index]
        return TimingStats(median: median, p95: p95)
    }
}
