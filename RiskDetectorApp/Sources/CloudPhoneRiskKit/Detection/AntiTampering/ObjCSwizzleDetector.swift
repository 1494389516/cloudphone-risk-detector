import Darwin
import Foundation
import ObjectiveC

/// 检测 ObjC 方法实现劫持与 Frida 特征 GCD 队列
///
/// 实现两种检测技术：
/// 1. ObjC 方法 IMP 劫持 — 检测关键 ObjC 方法的 IMP 是否指向预期框架镜像外
/// 2. Dispatch 队列名扫描 — 检测 Frida 特征性 GCD 队列标签（通过线程名）
struct ObjCSwizzleDetector: Detector {

    struct MethodCheck {
        let className: String
        let selector: String
        let expectedFramework: String  // substring to match in image path
        let score: Double
    }

    private var methodChecks: [MethodCheck] {
        var checks: [MethodCheck] = [
            // File system methods (critical for jailbreak detection bypass)
            MethodCheck(className: "NSFileManager", selector: "fileExistsAtPath:", expectedFramework: "Foundation", score: 15),
            MethodCheck(className: "NSFileManager", selector: "contentsOfDirectoryAtPath:error:", expectedFramework: "Foundation", score: 12),

            // Process info (environment variable spoofing)
            MethodCheck(className: "NSProcessInfo", selector: "environment", expectedFramework: "Foundation", score: 12),

            // URL/Network (SSL pinning bypass)
            MethodCheck(className: "NSURLSession", selector: "dataTaskWithRequest:completionHandler:", expectedFramework: "CFNetwork", score: 10),

            // Bundle (path spoofing)
            MethodCheck(className: "NSBundle", selector: "bundlePath", expectedFramework: "Foundation", score: 10),
        ]

        #if canImport(UIKit)
        checks += [
            // Device info (critical for device spoofing)
            MethodCheck(className: "UIDevice", selector: "model", expectedFramework: "UIKit", score: 12),
            MethodCheck(className: "UIDevice", selector: "systemVersion", expectedFramework: "UIKit", score: 10),
            MethodCheck(className: "UIDevice", selector: "name", expectedFramework: "UIKit", score: 10),
        ]
        #endif

        return checks
    }

    func detect() -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        // 1. ObjC method swizzle detection
        let swizzle = detectMethodSwizzle()
        score += swizzle.score
        methods.append(contentsOf: swizzle.methods)

        // 2. Dispatch queue name scanning
        let queue = detectSuspiciousQueues()
        score += queue.score
        methods.append(contentsOf: queue.methods)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    // MARK: - 1. ObjC Method Swizzle Detection

    private func detectMethodSwizzle() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        for check in methodChecks {
            guard let cls = NSClassFromString(check.className) else { continue }
            let sel = NSSelectorFromString(check.selector)
            guard let method = class_getInstanceMethod(cls, sel) else {
                // Try class method
                guard let classMethod = class_getClassMethod(cls, sel) else { continue }
                let imp = method_getImplementation(classMethod)
                checkIMP(imp, check: check, score: &score, methods: &methods)
                continue
            }
            let imp = method_getImplementation(method)
            checkIMP(imp, check: check, score: &score, methods: &methods)
        }

        return (min(score, 45), methods)
    }

    /// 校验 IMP 是否被劫持
    ///
    /// ## [4.4.8] PAC 旁路支持 (Swift-only)
    /// 在 A12+ (PAC) 设备上，直接解引用 IMP 指针读取机器码会导致 EXC_BAD_ACCESS。
    /// 策略：先用 dladdr 验证 IMP 是否落在已知镜像内（不涉及指针解引用）；
    /// 仅在非 PAC 环境下才进行首条指令的机器码扫描。
    /// - Note: 内联 Hook 检测在 PAC 设备上为 best-effort，主要依赖 dladdr 的镜像归属校验。
    private func checkIMP(_ imp: IMP, check: MethodCheck, score: inout Double, methods: inout [String]) {
        var info = Dl_info()
        let impRaw = unsafeBitCast(imp, to: UnsafeRawPointer.self)
        let found = dladdr(impRaw, &info)

        // 先做 dladdr 校验，避免任何对 IMP 的裸读（PAC 安全）
        if found == 0 {
            // IMP 不在任何已加载镜像中（匿名内存或 PAC 导致 dladdr 失败）— 视为可疑
            score += check.score
            methods.append("objc_swizzle:\(check.className).\(check.selector):anonymous")
            return
        }

        // 仅在非 PAC 环境下进行机器码扫描，否则跳过（防止 EXC_BAD_ACCESS）
        let shouldSkipMachineCodeCheck: Bool
        #if arch(arm64)
        if #available(iOS 14.0, macOS 11.0, *) {
            // M1 Mac 或 iOS 14+：PAC 启用，跳过裸读以防 EXC_BAD_ACCESS
            shouldSkipMachineCodeCheck = true
        } else {
            // iOS < 14：可尝试机器码扫描（A11 及更早设备无 PAC）
            shouldSkipMachineCodeCheck = false
        }
        #else
        shouldSkipMachineCodeCheck = true  // 非 arm64 无 B/BL 指令模式
        #endif

        if !shouldSkipMachineCodeCheck {
            #if arch(arm64)
            var inlineHookDetected = false
            autoreleasepool {
                let impPtr = impRaw.assumingMemoryBound(to: UInt32.self)
                let firstInstruction = impPtr.pointee
                if firstInstruction >= 0x14000000 && firstInstruction <= 0x17FFFFFF {
                    score += 50
                    methods.append("objc_inline_hook_detected:\(check.className).\(check.selector)")
                    inlineHookDetected = true
                }
            }
            if inlineHookDetected { return }
            #endif
        }

        // 校验 IMP 所在镜像是否与预期框架一致
        if let imagePath = info.dli_fname {
            let path = String(cString: imagePath)
            if !path.contains(check.expectedFramework) {
                score += check.score
                methods.append("objc_swizzle:\(check.className).\(check.selector):wrong_image")
            }
        }
    }

    // MARK: - 2. Dispatch Queue Name Scanning

    private func detectSuspiciousQueues() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        var foundLabels: Set<String> = []

        let suspiciousLabels = ["frida", "gum-js", "gmain", "gdbus", "re.frida", "linjector"]

        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0
        let kr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let threads = threadList else { return (0, []) }
        defer {
            vm_deallocate(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: threads)),
                vm_size_t(Int(threadCount) * MemoryLayout<thread_act_t>.size)
            )
        }

        for i in 0..<Int(threadCount) {
            let thread = threads[i]
            let pt = pthread_from_mach_thread_np(thread)
            guard pt != nil else { continue }

            var name = [CChar](repeating: 0, count: 256)
            if pthread_getname_np(pt!, &name, 256) == 0 {
                let threadName = String(cString: name).lowercased()
                if threadName.isEmpty { continue }
                for label in suspiciousLabels {
                    if threadName.contains(label) && !foundLabels.contains(label) {
                        foundLabels.insert(label)
                        score += 12
                        methods.append("suspicious_queue:\(label)")
                        break
                    }
                }
            }
        }

        return (min(score, 25), methods)
    }
}

// MARK: - RiskSignal 转换

extension ObjCSwizzleDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let swizzleMethods = result.methods.filter { $0.hasPrefix("objc_swizzle") }
        if !swizzleMethods.isEmpty {
            signals.append(RiskSignal(
                id: "objc_method_swizzled",
                category: "anti_tamper",
                score: min(Double(swizzleMethods.count) * 12, 30),
                evidence: [
                    "swizzled_methods": swizzleMethods.joined(separator: ","),
                    "count": "\(swizzleMethods.count)"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        let inlineHookMethods = result.methods.filter { $0.hasPrefix("objc_inline_hook_detected") }
        if !inlineHookMethods.isEmpty {
            signals.append(RiskSignal(
                id: "objc_inline_hook_detected",
                category: "anti_tamper",
                score: 50,
                evidence: [
                    "methods": inlineHookMethods.joined(separator: ","),
                    "count": "\(inlineHookMethods.count)"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }

        let queueMethods = result.methods.filter { $0.hasPrefix("suspicious_queue") }
        if !queueMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_dispatch_queue",
                category: "anti_tamper",
                score: min(Double(queueMethods.count) * 10, 20),
                evidence: ["queues": queueMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 70
            ))
        }

        return signals
    }
}
