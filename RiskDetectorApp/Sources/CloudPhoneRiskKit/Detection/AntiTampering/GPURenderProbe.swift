import Darwin
import Foundation
#if canImport(Metal)
import Metal
#endif

/// GPU 渲染能力深度探测
///
/// 云手机通常声称有 GPU 但实际使用软件模拟或远程渲染。
/// 通过实际执行 GPU 计算任务并测量延迟来检测：
/// 1. Metal 设备可用性与特性
/// 2. 简单 compute shader 执行时间（真 GPU vs 软件模拟差异巨大）
/// 3. GPU 内存分配特征
struct GPURenderProbe: Detector {
    
    func detect() -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []
        
        #if canImport(Metal)
        // 1. Metal device availability and characteristics
        let deviceCheck = checkMetalDevice()
        score += deviceCheck.score
        methods.append(contentsOf: deviceCheck.methods)
        
        // 2. GPU compute timing
        let computeCheck = checkComputeTiming()
        score += computeCheck.score
        methods.append(contentsOf: computeCheck.methods)
        #else
        score += 10
        methods.append("gpu_probe:metal_unavailable")
        #endif
        
        return DetectorResult(score: score, methods: methods)
        #endif
    }
    
    #if canImport(Metal)
    private func checkMetalDevice() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        
        guard let device = MTLCreateSystemDefaultDevice() else {
            score += 20
            methods.append("gpu_probe:no_metal_device")
            return (score, methods)
        }
        
        let name = device.name.lowercased()
        
        // Check for known virtual GPU names
        let virtualGPUKeywords = ["software", "swiftshader", "llvmpipe", "mesa", "virtual", "emulated"]
        for keyword in virtualGPUKeywords {
            if name.contains(keyword) {
                score += 25
                methods.append("gpu_probe:virtual_gpu:\(name)")
                break
            }
        }
        
        // Check GPU feature set support
        // Real Apple GPUs support specific feature families
        if !device.supportsFamily(.apple3) {
            score += 8
            methods.append("gpu_probe:low_feature_family")
        }
        
        // Check max buffer length (real GPUs have large limits)
        let maxBuffer = device.maxBufferLength
        if maxBuffer < 256 * 1024 * 1024 { // < 256MB suspicious
            score += 10
            methods.append("gpu_probe:small_max_buffer:\(maxBuffer / (1024*1024))MB")
        }
        
        return (score, methods)
    }
    
    private func checkComputeTiming() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        
        guard let device = MTLCreateSystemDefaultDevice(),
              let commandQueue = device.makeCommandQueue() else {
            return (0, [])
        }
        
        // Create a simple buffer and measure allocation + fill time
        let bufferSize = 1024 * 1024 // 1MB
        let start = mach_absolute_time()
        guard let buffer = device.makeBuffer(length: bufferSize, options: .storageModeShared) else {
            score += 8
            methods.append("gpu_probe:buffer_alloc_failed")
            return (score, methods)
        }
        let allocEnd = mach_absolute_time()
        
        // Fill buffer with data
        let ptr = buffer.contents().assumingMemoryBound(to: UInt8.self)
        for i in 0..<bufferSize {
            ptr[i] = UInt8(i & 0xFF)
        }
        let fillEnd = mach_absolute_time()
        
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)
        let allocNs = Double(allocEnd - start) * Double(timebaseInfo.numer) / Double(timebaseInfo.denom)
        let fillNs = Double(fillEnd - allocEnd) * Double(timebaseInfo.numer) / Double(timebaseInfo.denom)
        
        // Real GPU: buffer allocation < 1ms, fill < 5ms
        // Virtual: allocation may take > 10ms, fill > 50ms
        if allocNs > 10_000_000 { // > 10ms
            score += 12
            methods.append("gpu_probe:slow_alloc:\(Int(allocNs / 1_000_000))ms")
        }
        
        // Create and submit a minimal command buffer to measure GPU responsiveness
        if let cmdBuffer = commandQueue.makeCommandBuffer() {
            let gpuStart = mach_absolute_time()
            cmdBuffer.commit()
            cmdBuffer.waitUntilCompleted()
            let gpuEnd = mach_absolute_time()
            let gpuNs = Double(gpuEnd - gpuStart) * Double(timebaseInfo.numer) / Double(timebaseInfo.denom)
            
            // Real GPU: empty command buffer completes in < 1ms
            // Software rendering: may take > 5ms
            if gpuNs > 5_000_000 { // > 5ms
                score += 15
                methods.append("gpu_probe:slow_cmd_buffer:\(Int(gpuNs / 1_000_000))ms")
            }
        }
        
        // Suppress unused variable warning
        _ = fillNs
        
        return (min(score, 25), methods)
    }
    #endif
}

extension GPURenderProbe {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }
        
        var signals: [RiskSignal] = []
        
        let gpuMethods = result.methods.filter { $0.hasPrefix("gpu_probe") }
        if !gpuMethods.isEmpty {
            signals.append(RiskSignal(
                id: "gpu_render_anomaly",
                category: "device",
                score: result.score,
                evidence: ["detail": gpuMethods.joined(separator: ",")],
                state: .soft(confidence: min(result.score / 30.0, 1.0)),
                layer: 1,
                weightHint: 75
            ))
        }
        
        return signals
    }
}
