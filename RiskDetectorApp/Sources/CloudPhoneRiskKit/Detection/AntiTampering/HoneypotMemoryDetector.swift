import Darwin
import Foundation

/// [4.4.9] 蜜罐内存诱饵 (Honeypot Memory)
///
/// 申请一块特殊堆内存，写入虚假的 "AES Key"、"Device ID" 等诱饵字符串，
/// 通过 mprotect 设为 PROT_NONE。当内存 Dump 工具强行扫描该区域时，
/// 触发 SIGBUS，SDK 捕获后上报 memory_dump_attempt_detected。
///
/// 实现：纯 Swift，使用 Darwin.mmap、Darwin.mprotect、sigaction(SA_SIGINFO)。
private let pageSize: Int = Int(vm_page_size)
private let honeypotLock = NSLock()

/// 蜜罐基址与大小（供信号处理器校验 si_addr）
private var honeypotBase: UnsafeMutableRawPointer?
private var honeypotSize: Int = 0

/// 是否曾触发蜜罐访问（由 SIGBUS 处理器设置）
private var honeypotTriggered: Int32 = 0

/// 旧 SIGBUS 处理器（用于非蜜罐地址的故障转发）
private var previousSigbusHandler: sigaction?

/// SIGBUS 处理器：仅当 si_addr 落在蜜罐范围内时标记触发
/// 注意：信号处理器内不可使用锁或分配内存，仅做简单比较与赋值
private let honeypotSigbusHandler: @convention(c) (Int32, UnsafeMutablePointer<siginfo_t>?, UnsafeMutableRawPointer?) -> Void = { sig, info, _ in
    guard sig == SIGBUS, let info = info else { return }
    let addr = info.pointee.si_addr
    guard let addr = addr else { return }

    let base = honeypotBase
    let size = honeypotSize
    guard let base = base, size > 0 else { return }
    let addrValue = UInt(bitPattern: addr)
    let baseValue = UInt(bitPattern: base)
    guard addrValue >= baseValue && addrValue < baseValue + UInt(size) else {
        // 非蜜罐地址，转发给旧处理器
        if let prev = previousSigbusHandler {
            let handler = prev.__sigaction_u.__sa_sigaction
            if let fn = handler {
                fn(sig, info, nil)
            }
        }
        return
    }

    // 蜜罐被访问，标记检测到内存 Dump 尝试
    _ = OSAtomicCompareAndSwap32(0, 1, &honeypotTriggered)
}

struct HoneypotMemoryDetector: Detector {

    static let fakeStrings = [
        "AES-256-Key-CloudPhone-Secure",
        "Device-ID-CloudPhone-Risk-SDK",
        "Session-Token-Internal-Secret",
    ]

    init() {
        Self.armHoneypotIfNeeded()
    }

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["honeypot:unavailable_simulator"])
#else
        let triggered = (OSAtomicAdd32(0, &honeypotTriggered) != 0)
        if triggered {
            return DetectorResult(score: 80, methods: ["memory_dump_attempt_detected"])
        }
        return DetectorResult(score: 0, methods: ["honeypot:clean"])
#endif
    }

    /// 分配蜜罐页、写入诱饵、设为 PROT_NONE，并注册 SIGBUS 处理器
    private static func armHoneypotIfNeeded() {
#if targetEnvironment(simulator)
        return
#else
        honeypotLock.lock()
        defer { honeypotLock.unlock() }
        if honeypotBase != nil { return }

        let size = pageSize
        guard let ptr = mmap(
            nil,
            size,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0
        ), ptr != MAP_FAILED else {
            return
        }

        let mutable = UnsafeMutableRawPointer(ptr)
        var offset = 0
        for s in fakeStrings {
            let utf8 = Array(s.utf8)
            let copyLen = min(utf8.count, size - offset - 1)
            guard copyLen > 0 else { break }
            memcpy(mutable.advanced(by: offset), utf8, copyLen)
            offset += copyLen + 1
        }

        let protResult = mprotect(ptr, size, PROT_NONE)
        guard protResult == 0 else {
            munmap(ptr, size)
            return
        }

        honeypotBase = mutable
        honeypotSize = size

        var newAction = sigaction()
        newAction.__sigaction_u.__sa_sigaction = honeypotSigbusHandler
        newAction.sa_flags = Int32(SA_SIGINFO | SA_NODEFER)
        sigemptyset(&newAction.sa_mask)

        var oldAction = sigaction()
        sigaction(SIGBUS, &newAction, &oldAction)
        previousSigbusHandler = oldAction
#endif
    }
}

extension HoneypotMemoryDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }
        return [
            RiskSignal(
                id: "memory_dump_attempt_detected",
                category: "anti_tamper",
                score: 80,
                evidence: [
                    "reason": "honeypot_page_accessed",
                    "description": "Memory dump or scan touched protected honeypot region"
                ],
                state: .tampered,
                layer: 2,
                weightHint: 95
            )
        ]
    }
}
