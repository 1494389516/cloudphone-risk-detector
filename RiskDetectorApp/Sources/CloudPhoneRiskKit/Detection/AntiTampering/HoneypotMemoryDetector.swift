import Darwin
import Foundation

/// [4.4.9] 蜜罐内存诱饵 (Honeypot Memory) — 加固版
///
/// 在虚拟地址空间中分散分配多块诱饵页（3 个独立 mmap 区域），
/// 写入虚假凭据字符串后设为 PROT_NONE。当内存 Dump 工具强行扫描时，
/// 触发 SIGBUS 并上报 memory_dump_attempt_detected。
///
/// 加固措施：
/// - 多页分散布局：增加攻击者逐一定位并 munmap/mprotect 的成本
/// - 运行时自检：detect() 通过 vm_region_64 验证页保护位仍为 PROT_NONE
/// - Handler 完整性：detect() 验证 SIGBUS handler 未被外部替换
///
/// 纯 Swift，使用 Darwin.mmap / mprotect / sigaction / vm_region_64。

private let pageSize: Int = Int(vm_page_size)
private let honeypotLock = UnfairLock()

// MARK: - 3-page scattered honeypot layout

private var honeypotBase0: UnsafeMutableRawPointer?
private var honeypotSize0: Int = 0
private var honeypotBase1: UnsafeMutableRawPointer?
private var honeypotSize1: Int = 0
private var honeypotBase2: UnsafeMutableRawPointer?
private var honeypotSize2: Int = 0

/// Heap-allocated triggered flag; simple Int32 store is async-signal-safe
/// (POSIX guarantees sig_atomic_t-width writes are atomic in handlers).
/// Replaces deprecated OSAtomicCompareAndSwap32 / OSAtomicAdd32.
private let honeypotTriggeredPtr: UnsafeMutablePointer<Int32> = {
    let p = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
    p.initialize(to: 0)
    return p
}()

private var previousSigbusHandler: sigaction?

// MARK: - SIGBUS handler (async-signal-safe: no locks, no heap alloc)

private let honeypotSigbusHandler: @convention(c) (
    Int32, UnsafeMutablePointer<siginfo_t>?, UnsafeMutableRawPointer?
) -> Void = { sig, info, ctx in
    guard sig == SIGBUS, let info = info, let addr = info.pointee.si_addr else { return }
    let a = UInt(bitPattern: addr)

    var matched = false
    if let b = honeypotBase0, honeypotSize0 > 0 {
        let bv = UInt(bitPattern: b)
        if a >= bv, a < bv &+ UInt(honeypotSize0) { matched = true }
    }
    if !matched, let b = honeypotBase1, honeypotSize1 > 0 {
        let bv = UInt(bitPattern: b)
        if a >= bv, a < bv &+ UInt(honeypotSize1) { matched = true }
    }
    if !matched, let b = honeypotBase2, honeypotSize2 > 0 {
        let bv = UInt(bitPattern: b)
        if a >= bv, a < bv &+ UInt(honeypotSize2) { matched = true }
    }

    if matched {
        honeypotTriggeredPtr.pointee = 1
        /* Advance PC past the faulting instruction (4 bytes on ARM64) to prevent
           an infinite SIGBUS loop. The handler runs in the context of the faulting
           thread, so modifying the saved PC in ucontext_t is async-signal-safe. */
        #if arch(arm64)
        if let ctx = ctx {
            let uctx = ctx.assumingMemoryBound(to: ucontext_t.self)
            uctx.pointee.uc_mcontext.pointee.__ss.__pc &+= 4
        }
        #endif
        return
    }

    if let prev = previousSigbusHandler, let fn = prev.__sigaction_u.__sa_sigaction {
        fn(sig, info, ctx)
    }
}

// MARK: - Detector

struct HoneypotMemoryDetector: Detector {

    static let baitSets: [[String]] = [
        ["AES-256-Key-CloudPhone-Secure", "MasterKey-RSA-4096-Internal"],
        ["Device-ID-CloudPhone-Risk-SDK", "Session-Token-Internal-Secret"],
        ["PrivateKey-EC-P256-Signing", "Certificate-Chain-Root-CA-Prod"],
    ]

    init() {
        Self.armHoneypotIfNeeded()
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["honeypot:unavailable_simulator"])
#else
        var methods: [String] = []
        var score: Double = 0

        if honeypotTriggeredPtr.pointee != 0 {
            methods.append("memory_dump_attempt_detected")
            score = max(score, 80)
        }

        if Self.isHandlerReplaced() {
            methods.append("honeypot_handler_replaced")
            score = max(score, 90)
        }

        if Self.isProtectionModified() {
            methods.append("honeypot_protection_modified")
            score = max(score, 90)
        }

        if methods.isEmpty {
            methods.append("honeypot:clean")
        }
        return DetectorResult(score: score, methods: methods)
#endif
    }

    // MARK: - Arming

    private static func armHoneypotIfNeeded() {
#if targetEnvironment(simulator)
        return
#else
        honeypotLock.withLock {
            guard honeypotBase0 == nil else { return }

            var bases: [UnsafeMutableRawPointer] = []
            var sizes: [Int] = []

            for baits in baitSets {
                let size = pageSize
                guard let ptr = mmap(
                    nil, size,
                    PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE,
                    -1, 0
                ), ptr != MAP_FAILED else {
                    for (i, b) in bases.enumerated() { munmap(b, sizes[i]) }
                    return
                }

                let mutable = UnsafeMutableRawPointer(ptr)
                var offset = 0
                for s in baits {
                    let utf8 = Array(s.utf8)
                    let copyLen = min(utf8.count, size - offset - 1)
                    guard copyLen > 0 else { break }
                    memcpy(mutable.advanced(by: offset), utf8, copyLen)
                    offset += copyLen + 1
                }

                guard mprotect(ptr, size, PROT_NONE) == 0 else {
                    munmap(ptr, size)
                    for (i, b) in bases.enumerated() { munmap(b, sizes[i]) }
                    return
                }

                bases.append(mutable)
                sizes.append(size)
            }

            guard bases.count >= 3 else {
                for (i, b) in bases.enumerated() { munmap(b, sizes[i]) }
                return
            }
            honeypotBase0 = bases[0]; honeypotSize0 = sizes[0]
            honeypotBase1 = bases[1]; honeypotSize1 = sizes[1]
            honeypotBase2 = bases[2]; honeypotSize2 = sizes[2]

            var newAction = sigaction()
            newAction.__sigaction_u.__sa_sigaction = honeypotSigbusHandler
            newAction.sa_flags = Int32(SA_SIGINFO | SA_NODEFER)
            sigemptyset(&newAction.sa_mask)

            var oldAction = sigaction()
            sigaction(SIGBUS, &newAction, &oldAction)
            previousSigbusHandler = oldAction
        }
#endif
    }

    // MARK: - Runtime integrity checks

    /// Compare current SIGBUS handler pointer against ours.
    private static func isHandlerReplaced() -> Bool {
        guard honeypotBase0 != nil else { return false }

        var current = sigaction()
        sigaction(SIGBUS, nil, &current)

        guard let currentFn = current.__sigaction_u.__sa_sigaction else { return true }
        return unsafeBitCast(currentFn, to: Int.self)
            != unsafeBitCast(honeypotSigbusHandler, to: Int.self)
    }

    /// Walk all honeypot pages with vm_region_64 and verify PROT_NONE.
    private static func isProtectionModified() -> Bool {
        let pages: [(UnsafeMutableRawPointer?, Int)] = [
            (honeypotBase0, honeypotSize0),
            (honeypotBase1, honeypotSize1),
            (honeypotBase2, honeypotSize2),
        ]
        for (base, size) in pages {
            guard let base = base, size > 0 else { continue }
            if !isPageProtNone(base) { return true }
        }
        return false
    }

    private static func isPageProtNone(_ ptr: UnsafeMutableRawPointer) -> Bool {
        var address = vm_address_t(UInt(bitPattern: ptr))
        let expected = address
        var regionSize: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride
                / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: Int32.self, capacity: Int(count)) { raw in
                vm_region_64(
                    mach_task_self_,
                    &address,
                    &regionSize,
                    VM_REGION_BASIC_INFO_64,
                    raw,
                    &count,
                    &objectName
                )
            }
        }

        // Region gone (munmap'd) or starts at a different address → tampered
        guard kr == KERN_SUCCESS, address == expected else { return false }
        return info.protection == VM_PROT_NONE
    }
}

// MARK: - Signal emission

extension HoneypotMemoryDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        for method in result.methods {
            switch method {
            case "memory_dump_attempt_detected":
                signals.append(RiskSignal(
                    id: "memory_dump_attempt_detected",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 80,
                    evidence: [
                        "reason": "honeypot_page_accessed",
                        "description": "Memory dump or scan touched protected honeypot region",
                    ],
                    state: .tampered, layer: 2, weightHint: 95
                ))
            case "honeypot_handler_replaced":
                signals.append(RiskSignal(
                    id: "honeypot_handler_replaced",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 90,
                    evidence: [
                        "reason": "sigbus_handler_tampered",
                        "description": "SIGBUS handler was replaced by external code",
                    ],
                    state: .tampered, layer: 2, weightHint: 98
                ))
            case "honeypot_protection_modified":
                signals.append(RiskSignal(
                    id: "honeypot_protection_modified",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 90,
                    evidence: [
                        "reason": "page_protection_tampered",
                        "description": "Honeypot page protection changed from PROT_NONE",
                    ],
                    state: .tampered, layer: 2, weightHint: 98
                ))
            default:
                break
            }
        }
        return signals
    }
}
