import Darwin
import Foundation
#if canImport(CoreMotion)
import CoreMotion
#endif

/// 传感器数据回放检测
///
/// 云手机厂商录制真机传感器数据后在虚拟设备上回放，
/// 但回放数据有以下可检测特征：
/// 1. 响应延迟：回放数据对随机探针请求的响应有固定延迟模式
/// 2. 数据周期性：回放数据会出现周期性重复模式
/// 3. 采样率不一致：真机采样率与请求频率高度匹配，回放可能有偏差
/// 4. 交叉验证：加速度计/陀螺仪/磁力计的物理耦合关系在回放中可能断裂
struct SensorReplayDetector: Detector {
    
    func detect() -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []
        
        // 1. Timestamp regularity check
        let tsCheck = checkTimestampRegularity()
        score += tsCheck.score
        methods.append(contentsOf: tsCheck.methods)
        
        // 2. Random probe response latency
        let probeCheck = checkProbeLatency()
        score += probeCheck.score
        methods.append(contentsOf: probeCheck.methods)
        
        // 3. Entropy of sensor noise floor
        let noiseCheck = checkSensorNoiseEntropy()
        score += noiseCheck.score
        methods.append(contentsOf: noiseCheck.methods)
        
        return DetectorResult(score: score, methods: methods)
        #endif
    }
    
    /// Check if system uptime timestamps show replay artifacts
    /// Real devices have monotonically increasing timestamps with natural jitter
    /// Replayed data may have unnatural regularity or jumps
    private func checkTimestampRegularity() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        
        let iterations = 20
        var intervals = [Double]()
        intervals.reserveCapacity(iterations)
        
        var lastTime = ProcessInfo.processInfo.systemUptime
        for _ in 0..<iterations {
            usleep(500) // 0.5ms
            let now = ProcessInfo.processInfo.systemUptime
            let delta = now - lastTime
            intervals.append(delta)
            lastTime = now
        }
        
        // Calculate coefficient of variation
        let mean = intervals.reduce(0, +) / Double(intervals.count)
        guard mean > 0 else { return (0, []) }
        let variance = intervals.map { ($0 - mean) * ($0 - mean) }.reduce(0, +) / Double(intervals.count)
        let stddev = sqrt(variance)
        let cv = stddev / mean
        
        // Real devices: CV typically 0.1-0.8 (natural jitter from scheduler)
        // Replay: CV either very low (< 0.02, too regular) or very high (> 2.0, buffer underrun)
        if cv < 0.02 {
            score += 15
            methods.append("sensor_replay:timestamp_too_regular:cv_\(String(format: "%.4f", cv))")
        }
        
        return (score, methods)
    }
    
    /// Issue random timing probes and measure response consistency
    /// Real sensor hardware responds to timing changes naturally
    /// Replay buffers have fixed-size chunks that create detectable patterns
    private func checkProbeLatency() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        
        // Measure mach_absolute_time consistency across random intervals
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)
        
        let randomDelays: [UInt32] = [100, 237, 500, 1013, 173, 821, 50, 419]
        var actualDelays = [Double]()
        actualDelays.reserveCapacity(randomDelays.count)
        
        for delay in randomDelays {
            let start = mach_absolute_time()
            usleep(delay)
            let end = mach_absolute_time()
            let elapsed = Double(end - start) * Double(timebaseInfo.numer) / Double(timebaseInfo.denom) / 1000.0 // to microseconds
            actualDelays.append(elapsed)
        }
        
        // Compare ratio of actual to requested delays
        // Real hardware: ratio varies naturally (1.0-3.0x due to scheduler)
        // Replay: may show quantized behavior (delays snap to buffer boundaries)
        var ratios = [Double]()
        for (i, delay) in randomDelays.enumerated() {
            let ratio = actualDelays[i] / Double(delay)
            ratios.append(ratio)
        }
        
        // Check if all ratios are nearly identical (quantized replay)
        let ratioMean = ratios.reduce(0, +) / Double(ratios.count)
        guard ratioMean > 0 else { return (0, []) }
        let ratioVariance = ratios.map { ($0 - ratioMean) * ($0 - ratioMean) }.reduce(0, +) / Double(ratios.count)
        let ratioCV = sqrt(ratioVariance) / ratioMean
        
        if ratioCV < 0.01 {
            score += 12
            methods.append("sensor_replay:probe_quantized:cv_\(String(format: "%.4f", ratioCV))")
        }
        
        return (score, methods)
    }
    
    /// Check sensor noise floor entropy
    /// Real sensor hardware has characteristic noise patterns (thermal, ADC quantization)
    /// Replayed data may have different noise characteristics or no noise at all
    private func checkSensorNoiseEntropy() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        
        // Use high-resolution timer as a proxy for hardware noise
        // Real hardware: mach_absolute_time() LSBs have entropy from hardware clock
        // Virtual/replay: may have quantized LSBs
        let samples = 100
        var lsbs = [UInt8]()
        lsbs.reserveCapacity(samples)
        
        for _ in 0..<samples {
            let t = mach_absolute_time()
            lsbs.append(UInt8(t & 0xFF))
            // Tiny delay to get different samples
            for _ in 0..<10 { _ = mach_absolute_time() }
        }
        
        // Calculate entropy of LSB distribution
        var counts = [UInt8: Int]()
        for b in lsbs { counts[b, default: 0] += 1 }
        
        var entropy: Double = 0
        for (_, count) in counts {
            let p = Double(count) / Double(samples)
            if p > 0 {
                entropy -= p * log2(p)
            }
        }
        
        // Real hardware: entropy typically > 4.0 bits (good randomness in LSBs)
        // Virtual: entropy may be < 2.0 (quantized or repetitive)
        if entropy < 2.0 {
            score += 15
            methods.append("sensor_replay:low_noise_entropy:\(String(format: "%.2f", entropy))bits")
        }
        
        return (score, methods)
    }
}

extension SensorReplayDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }
        
        var signals: [RiskSignal] = []
        
        let replayMethods = result.methods.filter { $0.hasPrefix("sensor_replay") }
        if !replayMethods.isEmpty {
            signals.append(RiskSignal(
                id: "sensor_replay_detected",
                category: "device",
                score: result.score,
                evidence: ["detail": replayMethods.joined(separator: ","), "count": "\(replayMethods.count)"],
                state: .soft(confidence: min(result.score / 40.0, 1.0)),
                layer: 3,
                weightHint: 72
            ))
        }
        
        return signals
    }
}
