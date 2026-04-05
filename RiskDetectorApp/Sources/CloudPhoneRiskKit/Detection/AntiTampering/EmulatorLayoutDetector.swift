import CRiskCore
import Darwin
import Foundation

/// Detects unidbg / Unicorn-engine emulation environments by probing memory
/// layout invariants that hold on real iOS devices but not on Linux-hosted
/// ARM64 emulators.
///
/// ## Threat model
/// unidbg runs on a Linux host and emulates an ARM64 user-space process.
/// Key structural differences from a real iOS device:
///
/// 1. **No dyld shared cache** — iOS merges all system frameworks into a
///    single mapped file at a fixed high address (~0x18x_xxx_xxxx on arm64).
///    unidbg has no shared cache; system library addresses are absent or
///    mapped at arbitrary low addresses.
///
/// 2. **No ASLR slide consistency** — On real devices the slide is a single
///    value derived from the kernel; all image bases are offset by the same
///    amount.  unidbg loads each module independently with no coordinated
///    slide, so the delta between two known symbol addresses diverges from
///    the expected constant.
///
/// 3. **mach_timebase_info ratio** — iOS arm64 devices always report
///    numer=125 / denom=3 (A-series) or numer=1 / denom=1 (M-series).
///    unidbg returns 1/1 uniformly regardless of the emulated chip model.
///    Combined with the absence of GPU timing entropy this is a weak signal.
///
/// 4. **Thread stack layout** — On real iOS the main-thread stack is placed
///    at a very high virtual address (near the top of user space, typically
///    >0x16_xxxx_0000).  Unicorn maps stacks at low addresses by default.
///
/// 5. **vm_region count anomaly** — A minimal unidbg process has far fewer
///    vm_region entries than a real iOS app (no shared cache mappings,
///    no dyld trampoline pages, no IOKit mappings).
///
/// Each signal contributes a partial score; the composite score is capped at
/// 60 to act as one factor among several in the overall risk assessment.
struct EmulatorLayoutDetector: Detector {
    private static let vmRegionBasicInfoCount64 = mach_msg_type_number_t(
        MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
    )

    // MARK: - Score constants

    private enum Score {
        static let noDyldSharedCache: Double    = 22
        static let slackVMRegionCount: Double   = 12
        static let stackAddressLow: Double      = 14
        static let timbaseRatioFlat: Double     = 8
        static let imageBaseAnomalous: Double   = 10
        static let max: Double                  = 60
    }

    // MARK: - Detector

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["emulator_layout:unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        // ── 1. dyld shared cache presence ──────────────────────────────────
        // On a real device _dyld_shared_cache_contains_path returns true for
        // any system framework.  unidbg does not provide a shared cache.
        let sharedCacheResult = probeDyldSharedCache()
        if !sharedCacheResult.present {
            score += Score.noDyldSharedCache
            methods.append("emulator_layout:no_shared_cache")
        } else {
            methods.append("emulator_layout:shared_cache_ok(\(sharedCacheResult.detail))")
        }

        // ── 2. vm_region count (sparse process map) ──────────────────────
        let regionCount = countVMRegions()
        // Real iOS apps typically have 200-800 regions (shared cache alone
        // adds hundreds of mappings).  unidbg processes have <30.
        if regionCount < 40 {
            score += Score.slackVMRegionCount
            methods.append("emulator_layout:sparse_vm_regions(\(regionCount))")
        } else {
            methods.append("emulator_layout:vm_regions_ok(\(regionCount))")
        }

        // ── 3. Main-thread stack address ────────────────────────────────
        // On arm64 iOS the main-thread stack top is >0x16_0000_0000.
        // Unicorn maps stacks at much lower addresses.
        let stackAddr = currentStackAddress()
        if stackAddr < 0x0001_0000_0000 {   // below 4 GB → emulator range
            score += Score.stackAddressLow
            methods.append("emulator_layout:stack_low(0x\(String(stackAddr, radix: 16)))")
        } else {
            methods.append("emulator_layout:stack_ok(0x\(String(stackAddr, radix: 16)))")
        }

        // ── 4. mach_timebase_info ratio ─────────────────────────────────
        // unidbg hardcodes 1/1.  Real A-series: 125/3, M-series: 1/1 but
        // paired with real GPU timing, so we gate on both.
        var tbinfo = mach_timebase_info_data_t()
        mach_timebase_info(&tbinfo)
        let isFlat = (tbinfo.numer == 1 && tbinfo.denom == 1)
        // Only flag flat ratio if combined with the shared-cache miss (avoid
        // false positives on M-series Macs running iOS apps via Rosetta).
        if isFlat && !sharedCacheResult.present {
            score += Score.timbaseRatioFlat
            methods.append("emulator_layout:timebase_flat_no_cache")
        }

        // ── 5. Image base address sanity ─────────────────────────────────
        // System framework images on real devices are loaded from the shared
        // cache at high addresses (>0x180000000).  On unidbg they are either
        // absent or loaded at low stub addresses.
        let imageBaseOK = probeSystemImageBases()
        if !imageBaseOK {
            score += Score.imageBaseAnomalous
            methods.append("emulator_layout:image_base_anomalous")
        } else {
            methods.append("emulator_layout:image_base_ok")
        }

        let finalScore = min(score, Score.max)
        return DetectorResult(score: finalScore, methods: methods)
#endif
    }

    // MARK: - Private probes

    private struct SharedCacheResult {
        let present: Bool
        let detail: String
    }

    private func probeDyldSharedCache() -> SharedCacheResult {
        // Probe a path that is always in the shared cache on real devices.
        // Use an obfuscated string to avoid trivial string-scan detection.
        let parts: [UInt8] = [
            // "/usr/lib/libobjc.A.dylib" XOR 0x37
            0x1E, 0x44, 0x43, 0x1E, 0x5B, 0x59, 0x4B, 0x1E,
            0x5B, 0x59, 0x4B, 0x5C, 0x48, 0x4A, 0x5E, 0x1E,
            0x5C, 0x0B, 0x1E, 0x47, 0x44, 0x5B, 0x59, 0x4B
        ]
        let path = String(parts.map { Character(UnicodeScalar($0 ^ 0x37)) })
        let inCache = _dyld_shared_cache_contains_path(path)
        return SharedCacheResult(
            present: inCache,
            detail: inCache ? "libobjc_found" : "libobjc_absent"
        )
    }

    private func countVMRegions() -> Int {
        var address: vm_address_t = 0
        var count = 0
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var infoCount = Self.vmRegionBasicInfoCount64
        var objectName: mach_port_t = 0

        let maxIterations = 2000
        var iterations = 0

        while iterations < maxIterations {
            infoCount = Self.vmRegionBasicInfoCount64
            let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
                infoPtr.withMemoryRebound(to: Int32.self, capacity: Int(Self.vmRegionBasicInfoCount64)) { rawPtr in
                    vm_region_64(
                        mach_task_self_,
                        &address,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        rawPtr,
                        &infoCount,
                        &objectName
                    )
                }
            }
            guard kr == KERN_SUCCESS else { break }
            count += 1
            address += vm_address_t(size)
            iterations += 1
        }
        return count
    }

    private func currentStackAddress() -> UInt64 {
        // Read the stack pointer via a local variable address.
        var local: UInt8 = 0
        return UInt64(UInt(bitPattern: withUnsafePointer(to: &local) { $0 }))
    }

    private func probeSystemImageBases() -> Bool {
        // On real iOS devices, system images loaded from the shared cache
        // reside at addresses above 0x180000000 (6 GB mark).
        // unidbg either doesn't load them or puts them at <0x100000000.
        let threshold: UInt64 = 0x0001_8000_0000
        let imageCount = _dyld_image_count()
        guard imageCount > 0 else { return false }

        var highAddressCount = 0
        let checkCount = min(Int(imageCount), 80)

        for i in 0..<checkCount {
            guard let header = _dyld_get_image_header(UInt32(i)) else { continue }
            let addr = UInt64(UInt(bitPattern: header))
            if addr >= threshold {
                highAddressCount += 1
            }
        }
        // Expect at least 5 system images above 6 GB on a real device.
        return highAddressCount >= 5
    }
}
