import CRiskCore
import Darwin
import Foundation
import MachO

private let maxLayoutIterations = 600
private let anonymousUserTagSet: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// 64 KB alignment constant used by frida-agent's internal mmap calls.
/// System dylibs and standard malloc regions use 4 KB (16 KB on arm64) page alignment.
/// Frida's GLib and V8 allocator frequently requests 64 KB-aligned blocks via mmap,
/// leaving a detectable alignment signature in the virtual memory layout.
private let fridaMmapAlignment: UInt64 = 64 * 1024

/// Minimum total anonymous non-image region size (bytes) to trigger a score contribution.
/// frida-agent with V8 engine typically maps 5-30+ MB of anonymous memory; normal apps
/// rarely exceed a few hundred KB of truly anonymous (non-image) executable regions.
private let anonRegionSizeThreshold5MB: UInt64 = 5 * 1024 * 1024

/// Minimum total anonymous non-image region size (bytes) for the higher-confidence tier.
/// V8 heap + frida-agent code + Stalker JIT pages often total 15+ MB.
private let anonRegionSizeThreshold15MB: UInt64 = 15 * 1024 * 1024

/// Describes a single virtual memory region collected during the layout scan.
private struct MemoryRegion {
    let address: vm_address_t
    let size: vm_size_t
    let protection: vm_prot_t
    let isAnonymous: Bool
    let isInImage: Bool
    let userTag: UInt32
}

/// Frida memory layout fingerprint detector.
///
/// Analyzes the process virtual memory layout to detect frida-agent's presence
/// through statistical characteristics of memory regions rather than content matching.
/// This approach is orthogonal to `FridaModuleDetector` (which searches for strings/symbols)
/// and `FridaHeapDetector` (which focuses on large RW heaps and small JIT pages).
///
/// Detection heuristics:
/// - **Anonymous RX region count and total size**: frida-agent code + Gum Stalker JIT pages
/// - **Anonymous RW region count and total size**: frida-agent data + V8 heap
/// - **Consecutive anonymous RX+RW region pairs**: frida-agent's code-data segment layout
/// - **64 KB-aligned anonymous regions**: frida-agent uses 64 KB mmap alignment
/// - **RX regions not belonging to any dyld image**: injected code without backing image
///
/// False positive mitigation:
/// - Excludes regions belonging to known dyld images (via `cprisk_addr_in_any_image`)
/// - Excludes JavaScriptCore/WebKit JIT regions by checking if the address falls in
///   any loaded image (JSC JIT pages are tracked by the dyld image list)
/// - Metal/OpenGL GPU buffers are RW-only (no RX component), so they don't trigger
///   the RX+RW pair heuristic
struct FridaMemoryLayoutDetector: Detector {

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaUnavailableSimulator])
#else
        return detectKernel()
#endif
    }

    /// Keep the VMP-targeted `detect()` entry narrow and stable in optimized builds.
    @inline(never)
    private func detectKernel() -> DetectorResult {
        let regions = collectMemoryRegions()
        let metrics = computeMetrics(from: regions)

        var score: Double = 0
        var methods: [String] = []

        // Heuristic 1: Anonymous RX regions not in any image.
        // frida-agent loads as an anonymous mmap (not in dyld image list) with RX protection
        // for its __TEXT segment. Stalker also creates additional small RX JIT pages.
        // Normal apps have very few anonymous RX regions (perhaps a few from system JIT).
        if metrics.anonRXNotInImageCount >= 3 {
            score += 15
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_rx_not_in_image:\(metrics.anonRXNotInImageCount)")
        }

        // Heuristic 2: Consecutive anonymous RX+RW region pairs.
        // frida-agent maps its code (RX) and data (RW) segments as adjacent regions.
        // The pattern of [RX][RW] appearing consecutively in the address space is a
        // strong indicator of a Mach-O loaded via mmap rather than dyld.
        if metrics.consecutiveRXRWPairCount >= 2 {
            score += 12
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)consecutive_rxrw_pairs:\(metrics.consecutiveRXRWPairCount)")
        }

        // Heuristic 3: 64 KB-aligned anonymous regions.
        // frida-agent's internal allocators (GLib slice allocator, V8 page allocator)
        // use mmap with 64 KB alignment, while system dylibs use 4 KB (arm64: 16 KB)
        // page-aligned segments. A cluster of 64 KB-aligned anonymous regions is unusual.
        if metrics.aligned64KBAnonCount >= 3 {
            score += 8
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)aligned_64kb_anon:\(metrics.aligned64KBAnonCount)")
        }

        // Heuristic 4: Total size of anonymous regions not in any image exceeds threshold.
        // frida-agent with V8 typically maps 5-30 MB of anonymous memory for code + data + JIT.
        // The higher the total, the more confident we are that it's a full agent injection.
        if metrics.anonNotInImageTotalSize > anonRegionSizeThreshold15MB {
            score += 18
            let sizeMB = metrics.anonNotInImageTotalSize / (1024 * 1024)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_not_in_image_size:\(sizeMB)MB")
        } else if metrics.anonNotInImageTotalSize > anonRegionSizeThreshold5MB {
            score += 10
            let sizeMB = metrics.anonNotInImageTotalSize / (1024 * 1024)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_not_in_image_size:\(sizeMB)MB")
        }

        // Heuristic 5: Anonymous RW regions not in any image (V8/QuickJS heap + frida data).
        // frida-agent's V8 engine allocates large anonymous RW regions for its heap.
        // The combination with anonymous RX regions amplifies confidence.
        if metrics.anonRWNotInImageCount >= 3 && metrics.anonNotInImageTotalSize > anonRegionSizeThreshold5MB {
            score += 5
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)anon_rw_not_in_image:\(metrics.anonRWNotInImageCount)")
        }

        // Combination bonus: multiple heuristics firing simultaneously strongly suggests
        // frida-agent rather than any individual false positive source.
        let activeHeuristics = methods.count
        if activeHeuristics >= 3 {
            score += 10
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)multi_heuristic_combo:\(activeHeuristics)")
        } else if activeHeuristics == 2 {
            score += 4
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemoryLayout)dual_heuristic_combo")
        }

        if methods.isEmpty {
            return DetectorResult(score: 0, methods: [ObfuscatedConstants.methodFridaClean])
        }

        // Cap score at 70 -- this is a layout-based heuristic, not a definitive detection.
        // The score should contribute to but not independently determine the final risk level.
        return DetectorResult(score: min(score, 70), methods: methods)
    }

    // MARK: - Memory Region Collection

    /// Iterates through all virtual memory regions of the current task using `vm_region_64`
    /// and collects those with relevant protection flags (RX, RW, RWX).
    ///
    /// The iteration uses `VM_REGION_BASIC_INFO_64` for protection flags and region size,
    /// then `VM_REGION_EXTENDED_INFO` for the `user_tag` field to determine anonymity.
    /// The `cprisk_addr_in_any_image` C function checks whether each region's start address
    /// falls within any known dyld loaded image, which is resistant to `dladdr` hooking.
    private func collectMemoryRegions() -> [MemoryRegion] {
#if targetEnvironment(simulator)
        return []
#else
        var regions: [MemoryRegion] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < maxLayoutIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &address,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        rebound,
                        &basicCount,
                        &objectName
                    )
                }
            }

            guard basicResult == KERN_SUCCESS else { break }

            let prot = basicInfo.protection
            let isReadable = (prot & VM_PROT_READ) != 0
            let isWritable = (prot & VM_PROT_WRITE) != 0
            let isExecutable = (prot & VM_PROT_EXECUTE) != 0

            // Only collect regions with at least read + one other permission.
            // Pure RO regions and inaccessible regions are not relevant for Frida detection.
            let isRelevant = isReadable && (isWritable || isExecutable)
            guard isRelevant else {
                if size == 0 { break }
                let (next, overflow) = address.addingReportingOverflow(size)
                if overflow { break }
                address = next
                iteration += 1
                continue
            }

            // Query extended info for user_tag (anonymity detection).
            var isAnonymous = false
            var userTag: UInt32 = 0
            var extInfo = vm_region_extended_info_data_t()
            var extCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
            )
            var extAddress = address
            var extSize: vm_size_t = 0

            let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &extAddress,
                        &extSize,
                        VM_REGION_EXTENDED_INFO,
                        rebound,
                        &extCount,
                        &objectName
                    )
                }
            }
            if extResult == KERN_SUCCESS {
                userTag = UInt32(extInfo.user_tag)
                isAnonymous = anonymousUserTagSet.contains(userTag)
            }

            // Check if the region belongs to any known dyld image.
            // Uses cprisk_addr_in_any_image which walks dyld_all_image_infos --
            // resistant to dladdr hooking that Frida might employ to hide itself.
            var isInImage = false
            if address != 0, let ptr = UnsafeRawPointer(bitPattern: UInt(address)) {
                isInImage = cprisk_addr_in_any_image(ptr) != 0
            }

            regions.append(MemoryRegion(
                address: address,
                size: size,
                protection: prot,
                isAnonymous: isAnonymous,
                isInImage: isInImage,
                userTag: userTag
            ))

            if size == 0 { break }
            let (next, overflow) = address.addingReportingOverflow(size)
            if overflow { break }
            address = next
            iteration += 1
        }

        return regions
#endif
    }

    // MARK: - Metric Computation

    /// Aggregate layout metrics computed from the collected memory regions.
    ///
    /// These metrics capture statistical fingerprints of frida-agent's memory layout:
    /// - Counts of anonymous regions with specific protection flags
    /// - Consecutive RX+RW pairs (frida-agent segment layout pattern)
    /// - 64 KB alignment frequency (frida-agent mmap alignment)
    /// - Total size of non-image anonymous regions
    private struct LayoutMetrics {
        /// Number of anonymous RX (read+execute, no write) regions not in any dyld image.
        var anonRXNotInImageCount: Int = 0
        /// Number of anonymous RW (read+write, no execute) regions not in any dyld image.
        var anonRWNotInImageCount: Int = 0
        /// Number of consecutive region pairs where the first is anonymous RX and the second
        /// is anonymous RW. frida-agent loads its __TEXT (RX) and __DATA (RW) as adjacent
        /// anonymous mmap regions.
        var consecutiveRXRWPairCount: Int = 0
        /// Number of anonymous regions whose start address is aligned to 64 KB.
        /// frida-agent uses 64 KB alignment in its mmap calls, unlike system dylibs
        /// which use the platform page size (4 KB or 16 KB).
        var aligned64KBAnonCount: Int = 0
        /// Total combined size (bytes) of all anonymous regions not belonging to any
        /// known dyld image. frida-agent typically maps 5-30+ MB.
        var anonNotInImageTotalSize: UInt64 = 0
    }

    /// Computes layout metrics from the sorted list of memory regions.
    ///
    /// The consecutive RX+RW pair detection works by iterating regions in address order
    /// and checking if region[i] is anonymous RX and region[i+1] is anonymous RW with
    /// adjacent addresses (region[i].address + region[i].size == region[i+1].address).
    private func computeMetrics(from regions: [MemoryRegion]) -> LayoutMetrics {
        var metrics = LayoutMetrics()

        // Sort by address to detect consecutive pairs.
        let sorted = regions.sorted { $0.address < $1.address }

        for (index, region) in sorted.enumerated() {
            guard region.isAnonymous else { continue }

            let prot = region.protection
            let isRX = (prot & VM_PROT_READ) != 0 &&
                       (prot & VM_PROT_EXECUTE) != 0 &&
                       (prot & VM_PROT_WRITE) == 0
            let isRW = (prot & VM_PROT_READ) != 0 &&
                       (prot & VM_PROT_WRITE) != 0 &&
                       (prot & VM_PROT_EXECUTE) == 0

            if isRX && !region.isInImage {
                metrics.anonRXNotInImageCount += 1
                metrics.anonNotInImageTotalSize += UInt64(region.size)
            }

            if isRW && !region.isInImage {
                metrics.anonRWNotInImageCount += 1
                metrics.anonNotInImageTotalSize += UInt64(region.size)
            }

            // Check 64 KB alignment on anonymous regions.
            // frida-agent's mmap calls use MAP_ALIGNED(64KB) or equivalent.
            if UInt64(region.address) % fridaMmapAlignment == 0 {
                metrics.aligned64KBAnonCount += 1
            }

            // Detect consecutive anonymous RX -> RW pairs.
            // frida-agent maps __TEXT (RX) immediately followed by __DATA (RW).
            // The next region's address should be exactly current address + size.
            if isRX && !region.isInImage {
                let nextIndex = index + 1
                if nextIndex < sorted.count {
                    let next = sorted[nextIndex]
                    let expectedNextAddress = region.address + region.size
                    let nextIsRW = (next.protection & VM_PROT_READ) != 0 &&
                                  (next.protection & VM_PROT_WRITE) != 0 &&
                                  (next.protection & VM_PROT_EXECUTE) == 0
                    if next.address == expectedNextAddress &&
                       next.isAnonymous &&
                       nextIsRW &&
                       !next.isInImage {
                        metrics.consecutiveRXRWPairCount += 1
                    }
                }
            }
        }

        return metrics
    }
}

// MARK: - Signal Conversion

extension FridaMemoryLayoutDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        // Compute confidence from the number of distinct heuristics that fired.
        // More heuristics = higher confidence. Maximum 0.85 since this is layout-based
        // and not a definitive content signature.
        let heuristicCount = result.methods.filter {
            $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaMemoryLayout)
        }.count
        let confidence = min(0.45 + Double(heuristicCount) * 0.12, 0.85)

        var evidence: [String: String] = [
            "detail": result.methods.joined(separator: ","),
        ]
        if heuristicCount >= 3 {
            evidence["multi_heuristic"] = "true"
        }

        return [
            RiskSignal(
                id: ObfuscatedConstants.signalFridaMemoryLayoutAnomaly,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: result.score,
                evidence: evidence,
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 65
            ),
        ]
    }
}
