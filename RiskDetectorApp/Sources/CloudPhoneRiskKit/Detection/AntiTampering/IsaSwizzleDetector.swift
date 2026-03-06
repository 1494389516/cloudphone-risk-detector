import Darwin
import Foundation
import ObjectiveC

/// ObjC Runtime 深度攻击检测
///
/// 检测比 method swizzling 更深层的 ObjC runtime 攻击：
/// 1. isa swizzling — 攻击者通过 object_setClass() 修改对象的类指针，
///    使得消息分发走向攻击者控制的类
/// 2. 消息转发劫持 — 攻击者将方法 IMP 替换为 _objc_msgForward，
///    然后通过 forwardInvocation: 劫持调用
/// 3. 类方法数量异常 — 注入框架通常会给关键类添加大量方法
struct IsaSwizzleDetector: Detector {

    func detect() -> DetectorResult {
        #if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
        #else
        var score: Double = 0
        var methods: [String] = []

        let isa = detectIsaSwizzle()
        score += isa.score
        methods.append(contentsOf: isa.methods)

        let forward = detectMsgForwardHijack()
        score += forward.score
        methods.append(contentsOf: forward.methods)

        let methodCount = detectMethodCountAnomaly()
        score += methodCount.score
        methods.append(contentsOf: methodCount.methods)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    /// Detect isa swizzling on singleton objects
    /// Compare the runtime class of key singletons with their expected class
    private func detectIsaSwizzle() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Check well-known singletons
        let checks: [(AnyObject, String)] = [
            (FileManager.default, "NSFileManager"),
            (ProcessInfo.processInfo, "NSProcessInfo"),
            (Bundle.main, "NSBundle"),
            (NotificationCenter.default, "NSNotificationCenter"),
        ]

        for (obj, expectedPrefix) in checks {
            let actualClass = object_getClass(obj)
            let actualName = actualClass.map { NSStringFromClass($0) } ?? "nil"

            // The actual class name should start with the expected prefix
            // (could be a subclass like _NSConcreteFileManager, that's OK)
            // But if it's something completely different, that's suspicious
            if !actualName.contains(expectedPrefix.replacingOccurrences(of: "NS", with: "")) &&
               !actualName.hasPrefix(expectedPrefix) &&
               !actualName.hasPrefix("_" + expectedPrefix) &&
               !actualName.contains(expectedPrefix) {
                score += 15
                methods.append("isa_swizzle:\(expectedPrefix)→\(actualName)")
            }
        }

        return (min(score, 30), methods)
    }

    /// Detect methods whose IMP is _objc_msgForward
    /// This is a technique where the attacker replaces the IMP with the forwarding trampoline
    /// and then uses forwardInvocation: to intercept calls
    private func detectMsgForwardHijack() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Get the address of _objc_msgForward for comparison
        guard let msgForwardPtr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "_objc_msgForward") else {
            return (0, [])
        }
        let msgForwardAddr = unsafeBitCast(msgForwardPtr, to: IMP.self)

        // Check critical methods for forwarding hijack
        let methodsToCheck: [(String, String)] = [
            ("NSFileManager", "fileExistsAtPath:"),
            ("NSProcessInfo", "environment"),
            ("NSBundle", "bundlePath"),
            ("NSBundle", "executablePath"),
        ]

        for (className, selName) in methodsToCheck {
            guard let cls = NSClassFromString(className) else { continue }
            let sel = NSSelectorFromString(selName)

            // Check instance method
            if let method = class_getInstanceMethod(cls, sel) {
                let imp = method_getImplementation(method)
                if imp == msgForwardAddr {
                    score += 18
                    methods.append("msg_forward:\(className).\(selName)")
                }
            }
        }

        return (min(score, 25), methods)
    }

    /// Detect abnormal method count on critical classes
    /// Hook frameworks often add methods to existing classes
    private func detectMethodCountAnomaly() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Expected method count ranges (approximate for iOS 14+)
        // These are loose ranges; the actual check is for extreme outliers
        let classChecks: [(String, ClosedRange<UInt32>)] = [
            ("NSFileManager", 50...500),
            ("NSProcessInfo", 20...200),
            ("NSBundle", 50...400),
        ]

        for (className, expectedRange) in classChecks {
            guard let cls = NSClassFromString(className) else { continue }
            var count: UInt32 = 0
            if let methodList = class_copyMethodList(cls, &count) {
                free(methodList)

                // Check for abnormally high method count (injection adds methods)
                if count > expectedRange.upperBound {
                    score += 8
                    methods.append("method_count_anomaly:\(className):\(count)")
                }
            }
        }

        return (min(score, 15), methods)
    }
}

extension IsaSwizzleDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let isaMethods = result.methods.filter { $0.hasPrefix("isa_swizzle") }
        if !isaMethods.isEmpty {
            signals.append(RiskSignal(
                id: "isa_swizzle_detected",
                category: "anti_tamper",
                score: min(Double(isaMethods.count) * 15, 30),
                evidence: ["detail": isaMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 82
            ))
        }

        let forwardMethods = result.methods.filter { $0.hasPrefix("msg_forward") }
        if !forwardMethods.isEmpty {
            signals.append(RiskSignal(
                id: "msg_forward_hijack",
                category: "anti_tamper",
                score: min(Double(forwardMethods.count) * 15, 25),
                evidence: ["detail": forwardMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        let countMethods = result.methods.filter { $0.hasPrefix("method_count") }
        if !countMethods.isEmpty {
            signals.append(RiskSignal(
                id: "method_count_anomaly",
                category: "anti_tamper",
                score: min(Double(countMethods.count) * 8, 15),
                evidence: ["detail": countMethods.joined(separator: ",")],
                state: .soft(confidence: 0.5),
                layer: 2,
                weightHint: 50
            ))
        }

        return signals
    }
}
