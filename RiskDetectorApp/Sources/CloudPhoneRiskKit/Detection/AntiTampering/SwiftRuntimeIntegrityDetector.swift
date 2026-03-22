import Darwin
import Foundation

struct SwiftRuntimeIntegrityDetector: Detector {
    static let detectorID = "swift_runtime_integrity"
    static let metadataSignalID = "swift_metadata_integrity"
    static let witnessSignalID = "swift_protocol_witness_integrity"
    static let closureSignalID = "swift_closure_context_integrity"
    static let existentialSignalID = "swift_existential_container_integrity"

    struct Snapshot {
        let metadata: MetadataSnapshot
        let witness: WitnessSnapshot
        let closure: ClosureSnapshot
        let existential: ExistentialSnapshot
    }

    struct MetadataSnapshot {
        let inspectedTypeCount: Int
        let reflectionMismatchCount: Int
        let suspiciousPointerCount: Int
        let pointerLocalityBuckets: [String: Int]
    }

    struct WitnessSnapshot {
        let sampleCount: Int
        let dispatchMismatchCount: Int
        let suspiciousPointerCount: Int
        let nonImageExecutablePointerCount: Int
        let pointerLocalityBuckets: [String: Int]
    }

    struct ClosureSnapshot {
        let sampleCount: Int
        let canaryMismatchCount: Int
        let layoutAnomalyCount: Int
        let unstableAddressCount: Int
        let functionPointerLocality: String
        let contextPointerLocality: String
    }

    struct ExistentialSnapshot {
        let sampleCount: Int
        let dynamicTypeMismatchCount: Int
        let pointerAnomalyCount: Int
        let pointerLocalityBuckets: [String: Int]
    }

    struct Assessment {
        let score: Double
        let metadataScore: Double
        let witnessScore: Double
        let closureScore: Double
        let existentialScore: Double
        let methods: [String]
    }

    private let snapshotOverride: Snapshot?

    init(snapshotOverride: Snapshot? = nil) {
        self.snapshotOverride = snapshotOverride
    }

    func detect() throws -> DetectorResult {
        let snapshot = resolvedSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
    }

    func asSignals() -> [RiskSignal] {
        let snapshot = resolvedSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        if assessment.metadataScore > 0 {
            let anomalyCount = snapshot.metadata.reflectionMismatchCount + snapshot.metadata.suspiciousPointerCount
            signals.append(RiskSignal(
                id: Self.metadataSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.metadataScore,
                evidence: [
                    "mechanism": "swift_metadata_consistency",
                    "anomaly_count": "\(anomalyCount)",
                    "reflection_mismatch_count": "\(snapshot.metadata.reflectionMismatchCount)",
                    "suspicious_pointer_count": "\(snapshot.metadata.suspiciousPointerCount)",
                    "pointer_locality": formatBuckets(snapshot.metadata.pointerLocalityBuckets),
                    "inspected_type_count": "\(snapshot.metadata.inspectedTypeCount)",
                ],
                state: assessment.metadataScore >= 40 ? .tampered : .soft(confidence: 0.62),
                layer: 2,
                weightHint: min(assessment.metadataScore + 20, 90)
            ))
        }

        if assessment.witnessScore > 0 {
            let anomalyCount = snapshot.witness.dispatchMismatchCount
                + snapshot.witness.suspiciousPointerCount
                + snapshot.witness.nonImageExecutablePointerCount
            signals.append(RiskSignal(
                id: Self.witnessSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.witnessScore,
                evidence: [
                    "mechanism": "swift_protocol_witness_consistency",
                    "anomaly_count": "\(anomalyCount)",
                    "dispatch_mismatch_count": "\(snapshot.witness.dispatchMismatchCount)",
                    "suspicious_pointer_count": "\(snapshot.witness.suspiciousPointerCount)",
                    "non_image_executable_pointer_count": "\(snapshot.witness.nonImageExecutablePointerCount)",
                    "pointer_locality": formatBuckets(snapshot.witness.pointerLocalityBuckets),
                    "sample_count": "\(snapshot.witness.sampleCount)",
                ],
                state: assessment.witnessScore >= 45 ? .tampered : .soft(confidence: 0.66),
                layer: 2,
                weightHint: min(assessment.witnessScore + 22, 92)
            ))
        }

        if assessment.closureScore > 0 {
            let anomalyCount = snapshot.closure.canaryMismatchCount
                + snapshot.closure.layoutAnomalyCount
                + snapshot.closure.unstableAddressCount
            signals.append(RiskSignal(
                id: Self.closureSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.closureScore,
                evidence: [
                    "mechanism": "swift_closure_context_integrity",
                    "anomaly_count": "\(anomalyCount)",
                    "canary_mismatch_count": "\(snapshot.closure.canaryMismatchCount)",
                    "layout_anomaly_count": "\(snapshot.closure.layoutAnomalyCount)",
                    "unstable_address_count": "\(snapshot.closure.unstableAddressCount)",
                    "pointer_locality": "function=\(snapshot.closure.functionPointerLocality),context=\(snapshot.closure.contextPointerLocality)",
                    "sample_count": "\(snapshot.closure.sampleCount)",
                ],
                state: assessment.closureScore >= 40 ? .tampered : .soft(confidence: 0.64),
                layer: 2,
                weightHint: min(assessment.closureScore + 20, 88)
            ))
        }

        if assessment.existentialScore > 0 {
            let anomalyCount = snapshot.existential.dynamicTypeMismatchCount
                + snapshot.existential.pointerAnomalyCount
            signals.append(RiskSignal(
                id: Self.existentialSignalID,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.existentialScore,
                evidence: [
                    "mechanism": "swift_existential_container_sanity",
                    "anomaly_count": "\(anomalyCount)",
                    "dynamic_type_mismatch_count": "\(snapshot.existential.dynamicTypeMismatchCount)",
                    "pointer_anomaly_count": "\(snapshot.existential.pointerAnomalyCount)",
                    "pointer_locality": formatBuckets(snapshot.existential.pointerLocalityBuckets),
                    "sample_count": "\(snapshot.existential.sampleCount)",
                ],
                state: assessment.existentialScore >= 38 ? .tampered : .soft(confidence: 0.63),
                layer: 2,
                weightHint: min(assessment.existentialScore + 18, 84)
            ))
        }

        return signals
    }

    private func resolvedSnapshot() -> Snapshot {
        if let override = snapshotOverride {
            return override
        }
        return collectSnapshot()
    }

    func assess(snapshot: Snapshot) -> Assessment {
        var methods: [String] = []
        var metadataScore: Double = 0
        var witnessScore: Double = 0
        var closureScore: Double = 0
        var existentialScore: Double = 0

        if snapshot.metadata.reflectionMismatchCount > 0 {
            metadataScore += min(18 + Double(snapshot.metadata.reflectionMismatchCount) * 12, 44)
            methods.append("swift_runtime:metadata:reflection_mismatch:\(snapshot.metadata.reflectionMismatchCount)")
        }
        if snapshot.metadata.suspiciousPointerCount > 0 {
            metadataScore += min(10 + Double(snapshot.metadata.suspiciousPointerCount) * 8, 26)
            methods.append("swift_runtime:metadata:pointer_suspicious:\(snapshot.metadata.suspiciousPointerCount)")
        }

        if snapshot.witness.dispatchMismatchCount > 0 {
            witnessScore += min(20 + Double(snapshot.witness.dispatchMismatchCount) * 14, 52)
            methods.append("swift_runtime:witness:dispatch_mismatch:\(snapshot.witness.dispatchMismatchCount)")
        }
        if snapshot.witness.suspiciousPointerCount > 0 {
            witnessScore += min(10 + Double(snapshot.witness.suspiciousPointerCount) * 10, 34)
            methods.append("swift_runtime:witness:pointer_suspicious:\(snapshot.witness.suspiciousPointerCount)")
        }
        if snapshot.witness.nonImageExecutablePointerCount > 0 {
            witnessScore += min(8 + Double(snapshot.witness.nonImageExecutablePointerCount) * 9, 28)
            methods.append("swift_runtime:witness:pointer_non_image_exec:\(snapshot.witness.nonImageExecutablePointerCount)")
        }

        if snapshot.closure.canaryMismatchCount > 0 {
            closureScore += min(24 + Double(snapshot.closure.canaryMismatchCount) * 14, 54)
            methods.append("swift_runtime:closure:canary_mismatch:\(snapshot.closure.canaryMismatchCount)")
        }
        if snapshot.closure.layoutAnomalyCount > 0 {
            closureScore += min(12 + Double(snapshot.closure.layoutAnomalyCount) * 10, 28)
            methods.append("swift_runtime:closure:layout_anomaly:\(snapshot.closure.layoutAnomalyCount)")
        }
        if snapshot.closure.unstableAddressCount > 0 {
            closureScore += min(10 + Double(snapshot.closure.unstableAddressCount) * 8, 24)
            methods.append("swift_runtime:closure:address_unstable:\(snapshot.closure.unstableAddressCount)")
        }

        if snapshot.closure.functionPointerLocality != PointerLocality.imageExecutable.rawValue {
            closureScore += 6
            methods.append("swift_runtime:closure:function_pointer_locality:\(snapshot.closure.functionPointerLocality)")
        }
        if snapshot.closure.contextPointerLocality == PointerLocality.anonymousExecutable.rawValue
            || snapshot.closure.contextPointerLocality == PointerLocality.unknown.rawValue {
            closureScore += 8
            methods.append("swift_runtime:closure:context_pointer_locality:\(snapshot.closure.contextPointerLocality)")
        }

        if snapshot.existential.dynamicTypeMismatchCount > 0 {
            existentialScore += min(18 + Double(snapshot.existential.dynamicTypeMismatchCount) * 12, 46)
            methods.append("swift_runtime:existential:dynamic_type_mismatch:\(snapshot.existential.dynamicTypeMismatchCount)")
        }
        if snapshot.existential.pointerAnomalyCount > 0 {
            existentialScore += min(10 + Double(snapshot.existential.pointerAnomalyCount) * 8, 28)
            methods.append("swift_runtime:existential:pointer_anomaly:\(snapshot.existential.pointerAnomalyCount)")
        }

        let total = min(metadataScore + witnessScore + closureScore + existentialScore, 95)
        return Assessment(
            score: total,
            metadataScore: min(metadataScore, 48),
            witnessScore: min(witnessScore, 56),
            closureScore: min(closureScore, 56),
            existentialScore: min(existentialScore, 48),
            methods: methods
        )
    }

    private func collectSnapshot() -> Snapshot {
        Snapshot(
            metadata: collectMetadataSnapshot(),
            witness: collectWitnessSnapshot(),
            closure: collectClosureSnapshot(),
            existential: collectExistentialSnapshot()
        )
    }

    private func collectMetadataSnapshot() -> MetadataSnapshot {
        let sentinel = MetadataSentinel(counter: 7, label: "runtime")
        let erased: Any = sentinel
        var reflectionMismatchCount = 0
        if Mirror(reflecting: sentinel).children.count != Mirror(reflecting: erased).children.count {
            reflectionMismatchCount += 1
        }
        if Mirror(reflecting: (sentinel.counter, sentinel.label)).children.count != 2 {
            reflectionMismatchCount += 1
        }

        let types: [Any.Type] = [
            MetadataSentinel.self,
            WitnessProbeImpl.self,
            ClosureCanaryBox.self,
        ]
        var suspiciousPointerCount = 0
        var pointerLocalityBuckets: [String: Int] = [:]
        for item in types {
            let pointer = unsafeBitCast(item, to: UnsafeRawPointer.self)
            let locality = classifyPointer(pointer)
            pointerLocalityBuckets[locality.rawValue, default: 0] += 1
            if locality == .unknown || locality == .anonymousExecutable {
                suspiciousPointerCount += 1
            }
        }

        return MetadataSnapshot(
            inspectedTypeCount: types.count,
            reflectionMismatchCount: reflectionMismatchCount,
            suspiciousPointerCount: suspiciousPointerCount,
            pointerLocalityBuckets: pointerLocalityBuckets
        )
    }

    private func collectWitnessSnapshot() -> WitnessSnapshot {
        let impl = WitnessProbeImpl(base: 0x5A17_C3D2)
        let existential: any RuntimeWitnessProbe = impl
        let seeds: [UInt64] = [1, 7, 19, 37, 61]
        var dispatchMismatchCount = 0

        for seed in seeds {
            let direct = impl.dispatchFingerprint(seed: seed)
            let generic = dispatchThroughGeneric(impl, seed: seed)
            let protocolCall = existential.dispatchFingerprint(seed: seed)
            if direct != generic || direct != protocolCall {
                dispatchMismatchCount += 1
            }
        }

        let pointerWords = witnessCandidatePointers(from: existential)
        var suspiciousPointerCount = 0
        var nonImageExecutablePointerCount = 0
        var pointerLocalityBuckets: [String: Int] = [:]
        for pointer in pointerWords {
            let locality = classifyPointer(pointer)
            pointerLocalityBuckets[locality.rawValue, default: 0] += 1
            if locality == .unknown || locality == .anonymousExecutable || locality == .anonymousData {
                suspiciousPointerCount += 1
            }
            if locality == .anonymousExecutable || locality == .unknown {
                nonImageExecutablePointerCount += 1
            }
        }

        return WitnessSnapshot(
            sampleCount: seeds.count,
            dispatchMismatchCount: dispatchMismatchCount,
            suspiciousPointerCount: suspiciousPointerCount,
            nonImageExecutablePointerCount: nonImageExecutablePointerCount,
            pointerLocalityBuckets: pointerLocalityBuckets
        )
    }

    private func collectExistentialSnapshot() -> ExistentialSnapshot {
        let concrete = ExistentialProbeImpl(seed: 0xD55E_A1B2_3319_7744)
        let existential: any RuntimeExistentialProbe = concrete
        let seeds: [UInt64] = [3, 9, 27, 81]

        var dynamicTypeMismatchCount = 0
        if String(reflecting: type(of: existential)) != String(reflecting: ExistentialProbeImpl.self) {
            dynamicTypeMismatchCount += 1
        }
        for seed in seeds {
            if existential.stableMarker(seed: seed) != concrete.stableMarker(seed: seed) {
                dynamicTypeMismatchCount += 1
            }
        }

        let pointerWords: [UnsafeRawPointer] = withUnsafeBytes(of: existential) { raw in
            let words = raw.bindMemory(to: UInt.self)
            guard words.count >= 2 else { return [] }
            return [words[words.count - 2], words[words.count - 1]].compactMap { value in
                guard value > 0x1000 else { return nil }
                return UnsafeRawPointer(bitPattern: value)
            }
        }

        var pointerAnomalyCount = 0
        var pointerLocalityBuckets: [String: Int] = [:]
        for pointer in pointerWords {
            let locality = classifyPointer(pointer)
            pointerLocalityBuckets[locality.rawValue, default: 0] += 1
            if locality == .unknown || locality == .anonymousExecutable {
                pointerAnomalyCount += 1
            }
        }

        return ExistentialSnapshot(
            sampleCount: seeds.count,
            dynamicTypeMismatchCount: dynamicTypeMismatchCount,
            pointerAnomalyCount: pointerAnomalyCount,
            pointerLocalityBuckets: pointerLocalityBuckets
        )
    }

    private func collectClosureSnapshot() -> ClosureSnapshot {
        let box = ClosureCanaryBox(canary: 0xA91C_D35F_7123_44EF, vector: [3, 5, 8, 13, 21])
        let closure: (UInt64) -> UInt64 = { [box] seed in
            Self.closureDigest(canary: box.canary, vector: box.vector, seed: seed)
        }
        let closureCopyA = closure
        let closureCopyB = closure

        let functionPointer = closureWord(closure, index: 0)
        let contextPointers = [
            closureWord(closure, index: 1),
            closureWord(closureCopyA, index: 1),
            closureWord(closureCopyB, index: 1),
        ]
        let nonNilContextPointers = contextPointers.compactMap { $0 }

        var canaryMismatchCount = 0
        let seeds: [UInt64] = [2, 11, 23, 47]
        for seed in seeds {
            let actual = closure(seed)
            let expected = Self.closureDigest(canary: box.canary, vector: box.vector, seed: seed)
            if actual != expected {
                canaryMismatchCount += 1
            }
        }

        var layoutAnomalyCount = 0
        if functionPointer == nil { layoutAnomalyCount += 1 }
        if nonNilContextPointers.count != contextPointers.count { layoutAnomalyCount += 1 }

        let unstableAddressCount = Set(nonNilContextPointers.map { UInt(bitPattern: $0) }).count > 1 ? 1 : 0

        let functionPointerLocality = classifyPointer(functionPointer).rawValue
        let contextPointerLocality = classifyPointer(nonNilContextPointers.first).rawValue

        return ClosureSnapshot(
            sampleCount: seeds.count,
            canaryMismatchCount: canaryMismatchCount,
            layoutAnomalyCount: layoutAnomalyCount,
            unstableAddressCount: unstableAddressCount,
            functionPointerLocality: functionPointerLocality,
            contextPointerLocality: contextPointerLocality
        )
    }

    private func witnessCandidatePointers(from value: any RuntimeWitnessProbe) -> [UnsafeRawPointer] {
        withUnsafeBytes(of: value) { raw in
            let words = raw.bindMemory(to: UInt.self)
            guard words.count >= 2 else { return [] }
            let indices = [words.count - 2, words.count - 1]
            return indices.compactMap { index in
                let candidate = words[index]
                guard candidate > 0x1000 else { return nil }
                return UnsafeRawPointer(bitPattern: candidate)
            }
        }
    }

    private func closureWord(_ closure: @escaping (UInt64) -> UInt64, index: Int) -> UnsafeRawPointer? {
        withUnsafeBytes(of: closure) { raw in
            let words = raw.bindMemory(to: UInt.self)
            guard index >= 0, index < words.count else { return nil }
            let value = words[index]
            guard value > 0x1000 else { return nil }
            return UnsafeRawPointer(bitPattern: value)
        }
    }

    private func dispatchThroughGeneric<T: RuntimeWitnessProbe>(_ probe: T, seed: UInt64) -> UInt64 {
        probe.dispatchFingerprint(seed: seed)
    }

    private static func closureDigest(canary: UInt64, vector: [UInt64], seed: UInt64) -> UInt64 {
        var acc = seed ^ canary
        for item in vector {
            acc = acc &* 1099511628211
            acc ^= item &+ 0x9E37_79B9_7F4A_7C15
        }
        return acc
    }

    private enum PointerLocality: String {
        case imageExecutable = "image_exec"
        case imageData = "image_data"
        case anonymousExecutable = "anon_exec"
        case anonymousData = "anon_data"
        case unknown = "unknown"
    }

    private func classifyPointer(_ pointer: UnsafeRawPointer?) -> PointerLocality {
        guard let pointer else { return .unknown }

        var info = Dl_info()
        let hasImage = dladdr(pointer, &info) != 0 && info.dli_fname != nil

        var address = vm_address_t(UInt(bitPattern: pointer))
        var size: vm_size_t = 0
        var basicInfo = vm_region_basic_info_data_64_t()
        var basicCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        let basicKr = withUnsafeMutablePointer(to: &basicInfo) { pointerInfo in
            pointerInfo.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
            }
        }
        guard basicKr == KERN_SUCCESS else {
            return .unknown
        }

        let executable = (basicInfo.protection & VM_PROT_EXECUTE) != 0

        if hasImage && executable {
            return .imageExecutable
        }
        if hasImage {
            return .imageData
        }
        if executable {
            return .anonymousExecutable
        }
        return .anonymousData
    }

    private func formatBuckets(_ buckets: [String: Int]) -> String {
        buckets
            .sorted { lhs, rhs in lhs.key < rhs.key }
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",")
    }
}

private protocol RuntimeWitnessProbe {
    func dispatchFingerprint(seed: UInt64) -> UInt64
}

private protocol RuntimeExistentialProbe {
    func stableMarker(seed: UInt64) -> UInt64
}

private struct WitnessProbeImpl: RuntimeWitnessProbe {
    let base: UInt64

    func dispatchFingerprint(seed: UInt64) -> UInt64 {
        let mixed = seed &* 0x9E37_79B9_7F4A_7C15
        return (mixed ^ base) &+ 0xA24B_AED4_963E_E407
    }
}

private struct ExistentialProbeImpl: RuntimeExistentialProbe {
    let seed: UInt64

    func stableMarker(seed input: UInt64) -> UInt64 {
        (seed &+ input) ^ 0x6A09E667F3BCC909
    }
}

private struct MetadataSentinel {
    let counter: Int
    let label: String
}

private final class ClosureCanaryBox {
    let canary: UInt64
    let vector: [UInt64]

    init(canary: UInt64, vector: [UInt64]) {
        self.canary = canary
        self.vector = vector
    }
}
