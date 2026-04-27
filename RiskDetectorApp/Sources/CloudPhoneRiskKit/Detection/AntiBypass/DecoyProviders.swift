import Darwin
import Foundation
import MachO
import Security

/*
 * DecoyProviders.swift
 *
 * Decoy provider pool — handler-shaped Providers whose addresses live in
 * BuiltInProviderBootstrap.plan[] alongside the real internal providers,
 * but whose risk signal output is always empty.
 *
 * Goal:
 *   The kanxue thread-290993 attack pattern enumerates a registry by scanning
 *   the contiguous plan-entry array for fn-pointer slots and mapping each to
 *   a Provider class.  With ~22 real providers + 8 decoys mixed in, an
 *   attacker who recovers the plan now sees 30 entries with no static signal
 *   distinguishing real from decoy — both have:
 *
 *     - a `static let shared = …()` singleton
 *     - a stable `id: String` field
 *     - a non-trivial `signals(snapshot:)` body that exercises Darwin/POSIX
 *       APIs with plausible naming
 *
 *   Each decoy performs real work (sysctl read / pagesize lookup / dyld image
 *   count / mach_self introspection) so a trace-based timing oracle cannot
 *   distinguish "decoy" from "real provider that found nothing this session"
 *   by call duration alone.  The work product is folded into a side-effect
 *   variable that the optimiser cannot eliminate but that never feeds into
 *   the returned signal array.
 *
 * Why decoys instead of randomising the real list:
 *   The TPR/FPR contract requires every real provider to run every session.
 *   We can't drop signals to confuse attackers without losing detection.
 *   But we *can* inflate the static-visible attack surface so that the IP
 *   embedded in "which detectors are wired up" is no longer enumerable from
 *   the binary alone.
 */

// MARK: - Decoy 1: EnclaveAttestEntropy

final class EnclaveAttestEntropyProvider: RiskSignalProvider {
    static let shared = EnclaveAttestEntropyProvider()
    private init() {}
    let id = "enclave_attest_entropy"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var probe: UInt64 = UInt64(snapshot.deviceID.utf8.count)
        var randBytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, randBytes.count, &randBytes)
        if status == errSecSuccess {
            for byte in randBytes {
                probe = probe &* 0x9E3779B97F4A7C15 &+ UInt64(byte)
            }
        }
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 2: ThermalThrottleAnomaly

final class ThermalThrottleAnomalyProvider: RiskSignalProvider {
    static let shared = ThermalThrottleAnomalyProvider()
    private init() {}
    let id = "thermal_throttle_anomaly"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let thermal = ProcessInfo.processInfo.thermalState
        var probe = UInt64(thermal.rawValue) ^ 0xC2B2AE3D27D4EB4F
        probe = probe &* 0x165667B19E3779F9
        probe ^= UInt64(snapshot.libcFallbackUsedMask)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 3: IndirectBranchPrediction

final class IndirectBranchPredictionProvider: RiskSignalProvider {
    static let shared = IndirectBranchPredictionProvider()
    private init() {}
    let id = "indirect_branch_prediction"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var acc: UInt64 = 0
        let baseline = mach_absolute_time()
        // Tight branch-prediction-stressing loop; iteration count is constant
        // and small enough that release-mode runtime stays sub-millisecond.
        for i in 0..<128 {
            let mixed = UInt64(truncatingIfNeeded: i) &* 0x85EBCA77C2B2AE3D
            if (mixed & 0xFF) > 0x80 {
                acc = acc &+ mixed
            } else {
                acc = acc ^ mixed
            }
        }
        let elapsed = mach_absolute_time() &- baseline
        DecoySink.absorb(acc &+ elapsed &+ UInt64(snapshot.libcFallbackEventTotal))
        return []
    }
}

// MARK: - Decoy 4: KernelPageTableScan

final class KernelPageTableScanProvider: RiskSignalProvider {
    static let shared = KernelPageTableScanProvider()
    private init() {}
    let id = "kernel_pt_scan"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        // hw.pagesize / hw.ncpu both return int32_t on Darwin.  Use Int32
        // explicitly so the sysctl buffer size matches the kernel's write width.
        var pageSize: Int32 = 0
        var pageSizeLen = MemoryLayout<Int32>.size
        sysctlbyname("hw.pagesize", &pageSize, &pageSizeLen, nil, 0)
        var ncpu: Int32 = 0
        var ncpuLen = MemoryLayout<Int32>.size
        sysctlbyname("hw.ncpu", &ncpu, &ncpuLen, nil, 0)
        let probe = UInt64(max(1, pageSize)) &* UInt64(max(1, ncpu))
                    ^ UInt64(snapshot.deviceID.utf8.count)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 5: MachVoucherChain

final class MachVoucherChainProvider: RiskSignalProvider {
    static let shared = MachVoucherChainProvider()
    private init() {}
    let id = "mach_voucher_chain"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let task = mach_task_self_
        // Use mach_absolute_time as an authenticity-looking probe.  Avoid
        // mach_host_self() because it bumps a port refcount per call (it's a
        // real port, not a name) — leaks add up across sessions.
        let ticks = mach_absolute_time()
        var probe = UInt64(task) &* 0x9E3779B97F4A7C15
        probe ^= ticks &* 0xC2B2AE3527D4EB4D
        probe ^= UInt64(snapshot.libcFallbackUsedMask)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 6: DyldClosureCache

final class DyldClosureCacheProvider: RiskSignalProvider {
    static let shared = DyldClosureCacheProvider()
    private init() {}
    let id = "dyld_closure_cache"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let imgCount = _dyld_image_count()
        var probe: UInt64 = UInt64(imgCount) &* 0x85EBCA6BC2B2AE35
        // Sample one header per session to keep cost low but make the access
        // pattern look like an inspection.
        if imgCount > 0 {
            let idx = UInt32(snapshot.deviceID.utf8.count % Int(imgCount))
            if let header = _dyld_get_image_header(idx) {
                probe ^= UInt64(UInt(bitPattern: header))
            }
        }
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 7: ARM64PointerAuth

final class ARM64PointerAuthProvider: RiskSignalProvider {
    static let shared = ARM64PointerAuthProvider()
    private init() {}
    let id = "arm64_pointer_auth"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var cpuFamily: UInt32 = 0
        var size = MemoryLayout<UInt32>.size
        sysctlbyname("hw.cpufamily", &cpuFamily, &size, nil, 0)
        var probe = UInt64(cpuFamily) &* 0xFF51AFD7ED558CCD
        probe ^= UInt64(snapshot.libcFallbackEventTotal) &* 0xC4CEB9FE1A85EC53
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Decoy 8: XPCConnectionAudit

final class XPCConnectionAuditProvider: RiskSignalProvider {
    static let shared = XPCConnectionAuditProvider()
    private init() {}
    let id = "xpc_connection_audit"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let pid = getpid()
        let uid = getuid()
        let gid = getgid()
        var probe = UInt64(pid) &* 0x27D4EB2F165667C5
        probe ^= UInt64(uid) &* 0x9E3779B97F4A7C15
        probe ^= UInt64(gid) &* 0xC2B2AE3527D4EB4D
        probe ^= UInt64(snapshot.libcFallbackUsedMask)
        DecoySink.absorb(probe)
        return []
    }
}

// MARK: - Sink

/// Black-hole sink that prevents the optimiser from eliminating decoy
/// computation entirely.  Writes are atomic but never read except in DEBUG.
private enum DecoySink {
    private static var black: UInt64 = 0
    private static let lock = NSLock()

    static func absorb(_ value: UInt64) {
        lock.lock()
        black ^= value
        lock.unlock()
    }

    /// Debug-only readback to keep the optimiser honest in test builds.
    static func snapshot() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return black
    }
}

// MARK: - Decoy bootstrap entry point

/// Returns the eight decoy provider singletons in the order they should appear
/// in the built-in bootstrap plan.  Adding/removing decoys here is the only
/// surface that needs to change to grow or shrink the pool.
enum DecoyProviderBootstrap {
    static let providers: [RiskSignalProvider] = [
        EnclaveAttestEntropyProvider.shared,
        ThermalThrottleAnomalyProvider.shared,
        IndirectBranchPredictionProvider.shared,
        KernelPageTableScanProvider.shared,
        MachVoucherChainProvider.shared,
        DyldClosureCacheProvider.shared,
        ARM64PointerAuthProvider.shared,
        XPCConnectionAuditProvider.shared,
    ]
}
