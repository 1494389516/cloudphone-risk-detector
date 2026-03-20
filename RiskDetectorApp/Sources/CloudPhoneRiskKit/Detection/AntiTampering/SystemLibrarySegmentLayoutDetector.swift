import Darwin
import Foundation
import MachO

private let segmentLayoutAnonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]
private let maxRegionIterationsPerImage = 128

struct SystemLibrarySegmentLayoutDetector: Detector {
    enum TargetKind {
        case mainApp
        case systemLibrary
    }

    struct SegmentDescriptor {
        let name: String
        let range: Range<UInt64>
        let initProtection: vm_prot_t
    }

    struct ImageLayoutSnapshot {
        let id: String
        let displayName: String
        let path: String
        let kind: TargetKind
        let declaredSegmentCount: Int
        let executableSegmentCount: Int
        let runtimeRegionCount: Int
        let executableRegionCount: Int
        let readOnlyRegionCount: Int
        let readWriteRegionCount: Int
        let writableExecutableRegionCount: Int
        let anonymousExecutableRegionCount: Int
        let textWritableRegionCount: Int
        let dataExecutableRegionCount: Int
    }

    private struct TargetImage {
        let id: String
        let displayName: String
        let path: String
        let kind: TargetKind
        let header: UnsafeRawPointer
    }

    private struct Evaluation {
        let score: Double
        let methods: [String]
        let snapshots: [ImageLayoutSnapshot]
    }

    private static let targetSuffixes: [(id: String, display: String, suffix: String)] = [
        ("dyld", "dyld", "/usr/lib/dyld"),
        ("libsystem_kernel", "libsystem_kernel", "/usr/lib/system/libsystem_kernel.dylib"),
        ("libsystem_c", "libsystem_c", "/usr/lib/libsystem_c.dylib"),
        ("libobjc", "libobjc", "/usr/lib/libobjc.A.dylib"),
        ("libcxx", "libc++", "/usr/lib/libc++.1.dylib"),
        ("foundation", "Foundation", "Foundation.framework/Foundation"),
        ("corefoundation", "CoreFoundation", "CoreFoundation.framework/CoreFoundation"),
    ]

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["segment_layout:unavailable_simulator"])
#else
        let evaluation = evaluate()
        return DetectorResult(score: evaluation.score, methods: evaluation.methods)
#endif
    }

    func asSignals() throws -> [RiskSignal] {
#if targetEnvironment(simulator)
        return []
#else
        let evaluation = evaluate()
        guard !evaluation.snapshots.isEmpty else { return [] }

        var signals: [RiskSignal] = []
        let systemSnapshots = evaluation.snapshots.filter { $0.kind == .systemLibrary }
        let appSnapshots = evaluation.snapshots.filter { $0.kind == .mainApp }

        let wxSystem = systemSnapshots.filter {
            $0.writableExecutableRegionCount > 0 ||
            $0.textWritableRegionCount > 0 ||
            $0.dataExecutableRegionCount > 0
        }
        if !wxSystem.isEmpty {
            signals.append(RiskSignal(
                id: "system_library_wx_mapping",
                category: "anti_tamper",
                score: 85,
                evidence: ["detail": wxSystem.map(Self.snapshotSummary).joined(separator: ";")],
                state: .tampered,
                layer: 2,
                weightHint: 94
            ))
        }

        let anonymousExecSystem = systemSnapshots.filter { $0.anonymousExecutableRegionCount > 0 }
        if !anonymousExecSystem.isEmpty {
            signals.append(RiskSignal(
                id: "system_library_anonymous_exec_region",
                category: "anti_tamper",
                score: 82,
                evidence: ["detail": anonymousExecSystem.map(Self.snapshotSummary).joined(separator: ";")],
                state: .tampered,
                layer: 2,
                weightHint: 92
            ))
        }

        let driftSystem = systemSnapshots.filter {
            Self.isRegionCountDriftSuspicious($0) || Self.isExecutableDistributionSuspicious($0)
        }
        if !driftSystem.isEmpty {
            signals.append(RiskSignal(
                id: "system_library_segment_count_drift",
                category: "anti_tamper",
                score: min(Double(driftSystem.count) * 18, 45),
                evidence: ["detail": driftSystem.map(Self.snapshotSummary).joined(separator: ";")],
                state: .soft(confidence: 0.72),
                layer: 2,
                weightHint: 68
            ))
        }

        let appAnomalies = appSnapshots.filter {
            Self.hasCriticalPermissionAnomaly($0) ||
            Self.isRegionCountDriftSuspicious($0) ||
            Self.isExecutableDistributionSuspicious($0)
        }
        if !appAnomalies.isEmpty {
            let hasCritical = appAnomalies.contains(where: Self.hasCriticalPermissionAnomaly)
            signals.append(RiskSignal(
                id: "app_image_segment_layout_anomaly",
                category: "anti_tamper",
                score: hasCritical ? 70 : 35,
                evidence: ["detail": appAnomalies.map(Self.snapshotSummary).joined(separator: ";")],
                state: hasCritical ? .tampered : .soft(confidence: 0.7),
                layer: 2,
                weightHint: hasCritical ? 85 : 72
            ))
        }

        return signals
#endif
    }
}

extension SystemLibrarySegmentLayoutDetector {
    static func hasCriticalPermissionAnomaly(_ snapshot: ImageLayoutSnapshot) -> Bool {
        snapshot.writableExecutableRegionCount > 0 ||
        snapshot.textWritableRegionCount > 0 ||
        snapshot.dataExecutableRegionCount > 0 ||
        snapshot.anonymousExecutableRegionCount > 0
    }

    static func isRegionCountDriftSuspicious(_ snapshot: ImageLayoutSnapshot) -> Bool {
        guard snapshot.declaredSegmentCount > 0 else { return false }
        let threshold = max(snapshot.declaredSegmentCount * 3, snapshot.declaredSegmentCount + 4)
        return snapshot.runtimeRegionCount >= threshold
    }

    static func isExecutableDistributionSuspicious(_ snapshot: ImageLayoutSnapshot) -> Bool {
        guard snapshot.executableSegmentCount > 0 else { return false }
        let threshold = max(snapshot.executableSegmentCount * 3, snapshot.executableSegmentCount + 3)
        return snapshot.executableRegionCount >= threshold
    }
}

private extension SystemLibrarySegmentLayoutDetector {
    private func evaluate() -> Evaluation {
        let snapshots = collectSnapshots()
        guard !snapshots.isEmpty else {
            return Evaluation(score: 0, methods: ["segment_layout:clean"], snapshots: [])
        }

        var score: Double = 0
        var methods: [String] = []

        for snapshot in snapshots {
            if snapshot.writableExecutableRegionCount > 0 {
                score += 35
                methods.append("segment_layout:wx:\(snapshot.id):count=\(snapshot.writableExecutableRegionCount)")
            }
            if snapshot.textWritableRegionCount > 0 {
                score += 25
                methods.append("segment_layout:text_writable:\(snapshot.id):count=\(snapshot.textWritableRegionCount)")
            }
            if snapshot.dataExecutableRegionCount > 0 {
                score += 25
                methods.append("segment_layout:data_executable:\(snapshot.id):count=\(snapshot.dataExecutableRegionCount)")
            }
            if snapshot.anonymousExecutableRegionCount > 0 {
                score += 30
                methods.append("segment_layout:anonymous_exec:\(snapshot.id):count=\(snapshot.anonymousExecutableRegionCount)")
            }
            if Self.isRegionCountDriftSuspicious(snapshot) {
                score += 12
                methods.append("segment_layout:drift:\(snapshot.id):declared=\(snapshot.declaredSegmentCount):runtime=\(snapshot.runtimeRegionCount)")
            }
            if Self.isExecutableDistributionSuspicious(snapshot) {
                score += 10
                methods.append("segment_layout:exec_distribution:\(snapshot.id):segments=\(snapshot.executableSegmentCount):regions=\(snapshot.executableRegionCount)")
            }
        }

        return Evaluation(score: min(score, 95), methods: methods, snapshots: snapshots)
    }

    private func collectSnapshots() -> [ImageLayoutSnapshot] {
        enumerateTargetImages().compactMap(makeSnapshot(for:))
    }

    private func enumerateTargetImages() -> [TargetImage] {
        var targets: [TargetImage] = []
        var seen = Set<String>()

        if let header = _dyld_get_image_header(0) {
            let path = _dyld_get_image_name(0).map { String(cString: $0) } ?? "main_app"
            targets.append(TargetImage(
                id: "main_app",
                displayName: "main_app",
                path: path,
                kind: .mainApp,
                header: UnsafeRawPointer(header)
            ))
            seen.insert("main_app")
        }

        let count = _dyld_image_count()
        for i in 0..<count {
            guard let rawPath = _dyld_get_image_name(i), let header = _dyld_get_image_header(i) else {
                continue
            }
            let path = String(cString: rawPath)
            for item in Self.targetSuffixes where path.hasSuffix(item.suffix) {
                guard !seen.contains(item.id) else { break }
                targets.append(TargetImage(
                    id: item.id,
                    displayName: item.display,
                    path: path,
                    kind: .systemLibrary,
                    header: UnsafeRawPointer(header)
                ))
                seen.insert(item.id)
                break
            }
        }

        return targets
    }

    private func makeSnapshot(for target: TargetImage) -> ImageLayoutSnapshot? {
        let segments = parseSegments(header: target.header)
        guard !segments.isEmpty else { return nil }

        let imageStart = segments.map { $0.range.lowerBound }.min() ?? 0
        let imageEnd = segments.map { $0.range.upperBound }.max() ?? 0
        guard imageEnd > imageStart else { return nil }

        var runtimeRegionCount = 0
        var executableRegionCount = 0
        var readOnlyRegionCount = 0
        var readWriteRegionCount = 0
        var writableExecutableRegionCount = 0
        var anonymousExecutableRegionCount = 0
        var textWritableRegionCount = 0
        var dataExecutableRegionCount = 0

        var address = vm_address_t(imageStart)
        var iteration = 0

        while UInt64(address) < imageEnd && iteration < maxRegionIterationsPerImage {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0
            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
                }
            }

            guard basicResult == KERN_SUCCESS, size > 0 else { break }

            let regionStart = UInt64(address)
            let regionEnd = regionStart &+ UInt64(size)
            guard regionEnd >= regionStart else { break }
            if regionStart >= imageEnd {
                break
            }

            let overlapStart = max(regionStart, imageStart)
            let overlapEnd = min(regionEnd, imageEnd)
            if overlapStart < overlapEnd {
                runtimeRegionCount += 1

                let protection = basicInfo.protection
                let writable = (protection & VM_PROT_WRITE) != 0
                let executable = (protection & VM_PROT_EXECUTE) != 0
                let readable = (protection & VM_PROT_READ) != 0

                if executable { executableRegionCount += 1 }
                if writable && executable {
                    writableExecutableRegionCount += 1
                } else if writable {
                    readWriteRegionCount += 1
                } else if readable {
                    readOnlyRegionCount += 1
                }

                var extInfo = vm_region_extended_info_data_t()
                var extCount = mach_msg_type_number_t(
                    MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
                )
                var extAddress = address
                var extSize: vm_size_t = 0
                let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                    ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                        vm_region_64(mach_task_self_, &extAddress, &extSize, VM_REGION_EXTENDED_INFO, rebound, &extCount, &objectName)
                    }
                }
                if extResult == KERN_SUCCESS, executable,
                   segmentLayoutAnonymousUserTags.contains(UInt32(extInfo.user_tag)) {
                    anonymousExecutableRegionCount += 1
                }

                let overlappingSegments = segments.filter { rangesOverlap($0.range, overlapStart..<overlapEnd) }
                if writable && overlappingSegments.contains(where: { $0.name == "__TEXT" }) {
                    textWritableRegionCount += 1
                }
                if executable && overlappingSegments.contains(where: { $0.name.hasPrefix("__DATA") }) {
                    dataExecutableRegionCount += 1
                }
            }

            let nextAddress = UInt64(address) &+ UInt64(size)
            if nextAddress <= UInt64(address) {
                break
            }
            address = vm_address_t(nextAddress)
            iteration += 1
        }

        return ImageLayoutSnapshot(
            id: target.id,
            displayName: target.displayName,
            path: target.path,
            kind: target.kind,
            declaredSegmentCount: segments.count,
            executableSegmentCount: segments.filter { ($0.initProtection & VM_PROT_EXECUTE) != 0 }.count,
            runtimeRegionCount: runtimeRegionCount,
            executableRegionCount: executableRegionCount,
            readOnlyRegionCount: readOnlyRegionCount,
            readWriteRegionCount: readWriteRegionCount,
            writableExecutableRegionCount: writableExecutableRegionCount,
            anonymousExecutableRegionCount: anonymousExecutableRegionCount,
            textWritableRegionCount: textWritableRegionCount,
            dataExecutableRegionCount: dataExecutableRegionCount
        )
    }

    private func parseSegments(header: UnsafeRawPointer) -> [SegmentDescriptor] {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return []
        }

        var command = header.advanced(by: MemoryLayout<mach_header_64>.size)
        let commandLimit = command.advanced(by: Int(ptr.pointee.sizeofcmds))
        var slide: UInt64 = 0
        var foundText = false

        for _ in 0..<ptr.pointee.ncmds {
            guard command < commandLimit else { break }
            let load = command.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize > 0 else { break }
            if load.cmd == LC_SEGMENT_64 {
                let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
                let name = Self.segmentName(segment.segname)
                if name == "__TEXT" {
                    let runtimeHeader = UInt64(bitPattern: Int64(Int(bitPattern: header)))
                    slide = runtimeHeader &- segment.vmaddr
                    foundText = true
                    break
                }
            }
            command = command.advanced(by: Int(load.cmdsize))
        }

        guard foundText else { return [] }

        var segments: [SegmentDescriptor] = []
        command = header.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<ptr.pointee.ncmds {
            guard command < commandLimit else { break }
            let load = command.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize > 0 else { break }
            if load.cmd == LC_SEGMENT_64 {
                let segment = command.assumingMemoryBound(to: segment_command_64.self).pointee
                guard segment.vmsize > 0 else {
                    command = command.advanced(by: Int(load.cmdsize))
                    continue
                }
                let start = segment.vmaddr &+ slide
                let end = start &+ segment.vmsize
                if end > start {
                    segments.append(SegmentDescriptor(
                        name: Self.segmentName(segment.segname),
                        range: start..<end,
                        initProtection: segment.initprot
                    ))
                }
            }
            command = command.advanced(by: Int(load.cmdsize))
        }

        return segments
    }

    private static func segmentName<T>(_ tuple: T) -> String {
        withUnsafePointer(to: tuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
                let count = strnlen(cPtr, MemoryLayout<T>.size)
                let raw = UnsafeRawPointer(cPtr).assumingMemoryBound(to: UInt8.self)
                return String(decoding: UnsafeBufferPointer(start: raw, count: count), as: UTF8.self)
            }
        }
    }

    private func rangesOverlap(_ lhs: Range<UInt64>, _ rhs: Range<UInt64>) -> Bool {
        lhs.lowerBound < rhs.upperBound && rhs.lowerBound < lhs.upperBound
    }

    private static func snapshotSummary(_ snapshot: ImageLayoutSnapshot) -> String {
        "\(snapshot.displayName){declared=\(snapshot.declaredSegmentCount),runtime=\(snapshot.runtimeRegionCount),rx=\(snapshot.executableRegionCount),ro=\(snapshot.readOnlyRegionCount),rw=\(snapshot.readWriteRegionCount),wx=\(snapshot.writableExecutableRegionCount),anonExec=\(snapshot.anonymousExecutableRegionCount),textW=\(snapshot.textWritableRegionCount),dataX=\(snapshot.dataExecutableRegionCount)}"
    }
}
