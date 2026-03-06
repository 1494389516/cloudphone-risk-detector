import Darwin
import Foundation
import MachO

/// 检测 Frida 注入的线程枚举异常与 Mach 异常端口劫持
///
/// 实现两种检测技术：
/// 1. 线程枚举异常 — 检测 Frida 的 GumJS/GLib 额外线程（gum-js-loop、gmain、gdbus 等）
/// 2. Mach 异常端口劫持 — 检测 Frida 劫持的异常处理端口
struct FridaThreadDetector: Detector {

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        let (threadScore, threadMethods) = detectAnomalousThreads()
        score += threadScore
        methods.append(contentsOf: threadMethods)

        let (exceptionScore, exceptionMethods) = detectExceptionPortHijack()
        score += exceptionScore
        methods.append(contentsOf: exceptionMethods)

        return DetectorResult(score: min(score, 80), methods: methods)
#endif
    }

    // MARK: - 1. 线程枚举异常检测

    private func detectAnomalousThreads() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        let kr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let threads = threadList else {
            return (0, [])
        }
        defer {
            vm_deallocate(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: threads)),
                vm_size_t(Int(threadCount) * MemoryLayout<thread_act_t>.size)
            )
        }

        let suspiciousNames = ["gum-js-loop", "gmain", "gdbus", "frida", "gum-js", "v8:"]

        for i in 0..<Int(threadCount) {
            let thread = threads[i]
            guard let pt = pthread_from_mach_thread_np(thread) else { continue }

            var name = [CChar](repeating: 0, count: 256)
            guard pthread_getname_np(pt, &name, 256) == 0 else { continue }

            let threadName = String(cString: name).lowercased()
            guard !threadName.isEmpty else { continue }

            for marker in suspiciousNames {
                if threadName.contains(marker) {
                    score += 15
                    methods.append("frida_thread:\(marker)")
                    break
                }
            }
        }

        // 线程数量异常：典型 iOS 应用约 5–15 个线程，Frida 会额外增加 2–5 个
        if threadCount > 25 {
            score += 8
            methods.append("frida_thread:count_anomaly:\(threadCount)")
        }

        return (min(score, 40), methods)
    }

    // MARK: - 2. Mach 异常端口劫持检测

    private func detectExceptionPortHijack() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        var masks = [exception_mask_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var ports = [mach_port_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var behaviors = [exception_behavior_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var flavors = [thread_state_flavor_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var count = mach_msg_type_number_t(EXC_TYPES_COUNT)

        // 使用常见异常类型掩码（Frida 通常劫持 BAD_ACCESS/BAD_INSTRUCTION/BREAKPOINT/SOFTWARE）
        let excMask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT | EXC_MASK_SOFTWARE
        let kr = task_get_exception_ports(
            mach_task_self_,
            exception_mask_t(excMask),
            &masks,
            &count,
            &ports,
            &behaviors,
            &flavors
        )

        guard kr == KERN_SUCCESS else {
            return (0, [])
        }

        for i in 0..<Int(count) {
            let port = ports[i]
            if port != MACH_PORT_NULL && port != mach_port_t(bitPattern: -1) {
                score += 20
                methods.append("frida_exception_port:mask_\(masks[i])")
                break
            }
        }

        return (score, methods)
    }
}

// MARK: - RiskSignal 转换

extension FridaThreadDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let threadMethods = result.methods.filter { $0.hasPrefix("frida_thread") }
        if !threadMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_thread_anomaly",
                category: "anti_tamper",
                score: min(Double(threadMethods.count) * 10, 30),
                evidence: [
                    "methods": threadMethods.joined(separator: ","),
                    "count": "\(threadMethods.count)"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        let exceptionMethods = result.methods.filter { $0.hasPrefix("frida_exception") }
        if !exceptionMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_exception_port",
                category: "anti_tamper",
                score: 20,
                evidence: ["detail": exceptionMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        return signals
    }
}
