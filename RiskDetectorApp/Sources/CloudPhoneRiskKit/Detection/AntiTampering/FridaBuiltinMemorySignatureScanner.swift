import Darwin
import Foundation

/// 进程内 RX / RW 映射上的 Frida/Gum 字符串特征扫描（节流 + 可关闭）。
/// 与 `FridaDetector` 的端口/文件/环境检测互补；误报控制依赖较长 marker 与区域/页数预算。
enum FridaBuiltinMemorySignatureScanner {
    private static let stateLock = NSLock()
    private static var lastScanMonotonicNs: UInt64 = 0

    #if DEBUG
    /// 仅用于测试：确认在关闭配置时不会进入 `performScan`。
    private(set) static var debugPerformScanCount: Int = 0

    static func resetDebugCountersForTests() {
        debugPerformScanCount = 0
    }

    static func resetThrottleStateForTests() {
        stateLock.lock()
        lastScanMonotonicNs = 0
        stateLock.unlock()
    }
    #endif

    /// 内置扫描是否启用（`CPRISK_FRIDA_MEMSIG_BUILTIN` 缺省为开启；显式 `0/false/off` 关闭）。
    internal static func isBuiltinEnabled() -> Bool {
        Configuration.current().enabled
    }

    /// 单元测试：在内存块中匹配与运行时扫描相同的 needle 集合（不访问 `vm_region`）。
    internal static func firstMatchInBufferForTesting(_ data: Data) -> String? {
        let needles = Self.compiledNeedleTable()
        return Self.firstMatch(in: data, needles: needles)
    }

    /// 节流后的内置扫描入口；模拟器上恒为 nil（与 `FridaDetector` 一致）。
    static func scanIfNeeded() -> String? {
#if targetEnvironment(simulator)
        return nil
#else
        let configuration = Configuration.current()
        guard configuration.enabled else { return nil }

        stateLock.lock()
        defer { stateLock.unlock() }

        let now = monotonicNanoseconds()
        if lastScanMonotonicNs != 0 {
            let delta = now &- lastScanMonotonicNs
            if delta < configuration.minIntervalNs {
                return nil
            }
        }

        let hit = performScan(configuration: configuration)
        lastScanMonotonicNs = monotonicNanoseconds()
        return hit
#endif
    }

    // MARK: - Scan core

    private static func performScan(configuration: Configuration) -> String? {
        #if DEBUG
        debugPerformScanCount += 1
        #endif

        let needles = compiledNeedleTable()
        guard !needles.isEmpty else { return nil }

        let pageSize = vm_size_t(getpagesize())
        var pagesBudget = configuration.maxPagesPerScan

        var address: vm_address_t = 0
        var iteration = 0

        while iteration < configuration.maxRegionIterations && pagesBudget > 0 {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0
            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let kr = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }
            if size == 0 { break }

            let regionStart = address
            defer {
                address = regionStart + size
                iteration += 1
            }

            let prot = basicInfo.protection
            let read = (prot & VM_PROT_READ) != 0
            let exec = (prot & VM_PROT_EXECUTE) != 0
            let write = (prot & VM_PROT_WRITE) != 0
            guard read && (exec || write) else { continue }

            if UInt64(size) > configuration.maxRegionBytes { continue }

            var offset: vm_size_t = 0
            while offset < size && pagesBudget > 0 {
                let remaining = size - offset
                let chunk = min(configuration.maxChunkBytes, remaining)
                if chunk == 0 { break }

                let pagesInChunk = Int((chunk + pageSize - 1) / pageSize)
                if pagesInChunk > pagesBudget {
                    let allowedBytes = vm_size_t(pagesBudget) * pageSize
                    if allowedBytes == 0 { break }
                    let cappedChunk = min(remaining, allowedBytes)
                    if cappedChunk == 0 { break }
                    if let hit = readAndMatch(
                        regionBase: regionStart,
                        offset: offset,
                        chunkSize: cappedChunk,
                        needles: needles
                    ) {
                        return hit
                    }
                    pagesBudget = 0
                    break
                }

                if let hit = readAndMatch(
                    regionBase: regionStart,
                    offset: offset,
                    chunkSize: chunk,
                    needles: needles
                ) {
                    return hit
                }

                pagesBudget -= pagesInChunk
                offset += chunk
            }
        }

        return nil
    }

    private static func readAndMatch(
        regionBase: vm_address_t,
        offset: vm_size_t,
        chunkSize: vm_size_t,
        needles: [(String, Data)]
    ) -> String? {
        var buffer = [UInt8](repeating: 0, count: Int(chunkSize))
        var outSize: vm_size_t = 0
        let readAddr = vm_address_t(UInt64(regionBase) + UInt64(offset))
        let kr = buffer.withUnsafeMutableBytes { rawBuf in
            vm_read_overwrite(
                mach_task_self_,
                readAddr,
                vm_size_t(chunkSize),
                vm_address_t(UInt(bitPattern: rawBuf.baseAddress)),
                &outSize
            )
        }
        guard kr == KERN_SUCCESS, outSize > 0 else { return nil }
        let data = Data(buffer.prefix(Int(outSize)))
        return firstMatch(in: data, needles: needles)
    }

    private static func firstMatch(in data: Data, needles: [(String, Data)]) -> String? {
        for (label, needle) in needles {
            if needle.isEmpty { continue }
            if data.range(of: needle) != nil {
                return label
            }
        }
        return nil
    }

    private static func compiledNeedleTable() -> [(String, Data)] {
        var rows: [(String, Data)] = []
        for marker in ObfuscatedConstants.fridaStringMarkers {
            // 过短子串误报率高；与 FridaModuleDetector 的 string 维度对齐，仅保留较长特征
            guard marker.utf8.count >= 8 else { continue }
            rows.append((marker, Data(marker.utf8)))
        }
        return rows
    }

    private static func monotonicNanoseconds() -> UInt64 {
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        let ticks = mach_absolute_time()
        return ticks * UInt64(timebase.numer) / UInt64(timebase.denom)
    }

    // MARK: - Configuration (env)

    private struct Configuration {
        let enabled: Bool
        let minIntervalNs: UInt64
        let maxPagesPerScan: Int
        let maxRegionBytes: UInt64
        let maxChunkBytes: vm_size_t
        let maxRegionIterations: Int

        static func current() -> Configuration {
            let enabled = envBool(key: "CPRISK_FRIDA_MEMSIG_BUILTIN", defaultIfUnset: true)
            let intervalMs = envInt(key: "CPRISK_FRIDA_MEMSIG_INTERVAL_MS", defaultValue: 90_000)
            let maxPages = envInt(key: "CPRISK_FRIDA_MEMSIG_MAX_PAGES", defaultValue: 64)
            let maxRegionBytes = envUInt64(key: "CPRISK_FRIDA_MEMSIG_MAX_REGION_BYTES", defaultValue: 64 * 1024 * 1024)
            let chunkBytes = envInt(key: "CPRISK_FRIDA_MEMSIG_CHUNK_BYTES", defaultValue: 16 * 1024)
            let maxIter = envInt(key: "CPRISK_FRIDA_MEMSIG_MAX_REGION_ITER", defaultValue: 4096)

            return Configuration(
                enabled: enabled,
                minIntervalNs: UInt64(max(0, intervalMs)) * 1_000_000,
                maxPagesPerScan: max(1, maxPages),
                maxRegionBytes: max(1024 * 1024, maxRegionBytes),
                maxChunkBytes: vm_size_t(max(4096, chunkBytes)),
                maxRegionIterations: max(64, maxIter)
            )
        }
    }

    private static func envBool(key: String, defaultIfUnset: Bool) -> Bool {
        guard let raw = ProcessInfo.processInfo.environment[key]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(), !raw.isEmpty else {
            return defaultIfUnset
        }
        if raw == "0" || raw == "false" || raw == "no" || raw == "off" {
            return false
        }
        if raw == "1" || raw == "true" || raw == "yes" || raw == "on" {
            return true
        }
        return defaultIfUnset
    }

    private static func envInt(key: String, defaultValue: Int) -> Int {
        guard let raw = ProcessInfo.processInfo.environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = Int(raw) else {
            return defaultValue
        }
        return parsed
    }

    private static func envUInt64(key: String, defaultValue: UInt64) -> UInt64 {
        guard let raw = ProcessInfo.processInfo.environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = UInt64(raw) else {
            return defaultValue
        }
        return parsed
    }
}
