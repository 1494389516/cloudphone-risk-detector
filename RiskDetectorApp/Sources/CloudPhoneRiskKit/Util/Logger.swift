import Foundation

// MARK: - 结构化日志系统
//
// 替代原有 4 行 Logger：
// - 支持日志级别（debug/info/warn/error/critical）
// - Release 下保留 warn/error/critical（可选）
// - 支持结构化元数据（key-value）
// - 支持自定义日志输出目标（LogDestination 协议）
// - 支持审计追踪（决策日志）
// - 线程安全

/// 日志级别
public enum LogLevel: Int, Comparable, Sendable {
    case debug = 0
    case info = 1
    case warn = 2
    case error = 3
    case critical = 4

    public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var label: String {
        switch self {
        case .debug: return "DEBUG"
        case .info: return "INFO"
        case .warn: return "WARN"
        case .error: return "ERROR"
        case .critical: return "CRITICAL"
        }
    }
}

/// 结构化日志条目
public struct LogEntry: Sendable {
    public let timestamp: Date
    public let level: LogLevel
    public let message: String
    public let metadata: [String: String]
    public let file: String
    public let function: String
    public let line: UInt
}

/// 日志输出目标协议 — 实现此协议可自定义日志输出（文件、网络、第三方 SDK 等）
public protocol LogDestination: Sendable {
    func write(_ entry: LogEntry)
}

/// 默认控制台输出
struct ConsoleLogDestination: LogDestination {
    private static let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        return f
    }()

    func write(_ entry: LogEntry) {
        let ts = Self.dateFormatter.string(from: entry.timestamp)
        var line = "[\(ts)] [\(entry.level.label)] [CloudPhoneRiskKit] \(entry.message)"
        if !entry.metadata.isEmpty {
            let meta = entry.metadata.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
            line += " | \(meta)"
        }
        print(line)
    }
}

/// 审计日志条目 — 记录决策过程的关键步骤
public struct AuditEntry: Sendable {
    public let timestamp: Date
    public let action: String
    public let details: [String: String]
}

public enum Logger {
    // MARK: - Thread-safe configuration

    private struct Config {
        var isEnabled: Bool
        var releaseLoggingEnabled: Bool
        var minimumLevel: LogLevel
    }

    private static let configLock = UnfairLock()
#if DEBUG
    private static var _config = Config(isEnabled: true, releaseLoggingEnabled: false, minimumLevel: .debug)
#else
    private static var _config = Config(isEnabled: false, releaseLoggingEnabled: false, minimumLevel: .debug)
#endif

    public static var isEnabled: Bool {
        get { configLock.withLock { _config.isEnabled } }
        set { configLock.withLock { _config.isEnabled = newValue } }
    }

    /// Release 下是否保留 warn 及以上级别日志
    public static var releaseLoggingEnabled: Bool {
        get { configLock.withLock { _config.releaseLoggingEnabled } }
        set { configLock.withLock { _config.releaseLoggingEnabled = newValue } }
    }

    /// 最低日志级别
    public static var minimumLevel: LogLevel {
        get { configLock.withLock { _config.minimumLevel } }
        set { configLock.withLock { _config.minimumLevel = newValue } }
    }

    /// 自定义日志输出目标
    private(set) static var destinations: [LogDestination] = []
    private static let destinationLock = UnfairLock()

    /// 审计追踪（环形缓冲区，保留最近 200 条决策日志）
    private static var auditTrail: [AuditEntry] = []
    private static let auditLock = UnfairLock()
    private static let maxAuditEntries = 200

    // MARK: - 基础日志（兼容原有接口）

    public static func log(_ message: @autoclosure () -> String) {
        emit(level: .info, message: message())
    }

    // MARK: - 分级日志

    public static func debug(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                             file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .debug, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func info(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                            file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .info, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func warn(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                            file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .warn, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func error(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                             file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .error, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    public static func critical(_ message: @autoclosure () -> String, metadata: [String: String] = [:],
                                file: String = #fileID, function: String = #function, line: UInt = #line) {
        emit(level: .critical, message: message(), metadata: metadata, file: file, function: function, line: line)
    }

    // MARK: - 审计追踪

    /// 记录决策审计条目（评估原因、分数计算、阈值匹配等）
    public static func audit(action: String, details: [String: String] = [:]) {
        let entry = AuditEntry(timestamp: Date(), action: action, details: details)
        auditLock.withLock {
            auditTrail.append(entry)
            if auditTrail.count > maxAuditEntries {
                auditTrail.removeFirst(auditTrail.count - maxAuditEntries)
            }
        }

        emit(level: .info, message: "AUDIT: \(action)", metadata: details)
    }

    /// 获取审计追踪快照
    public static func auditSnapshot() -> [AuditEntry] {
        auditLock.withLock { auditTrail }
    }

    /// 清除审计追踪
    public static func clearAuditTrail() {
        auditLock.withLock { auditTrail.removeAll() }
    }

    // MARK: - 目标管理

    /// 添加自定义日志输出目标
    public static func addDestination(_ destination: LogDestination) {
        destinationLock.withLock { destinations.append(destination) }
    }

    /// 移除所有自定义日志输出目标
    public static func removeAllDestinations() {
        destinationLock.withLock { destinations.removeAll() }
    }

    // MARK: - 评估性能度量

    /// 测量闭包执行时间并记录
    @discardableResult
    public static func measure<T>(_ label: String, _ work: () throws -> T) rethrows -> T {
        let start = ProcessInfo.processInfo.systemUptime
        let result = try work()
        let elapsed = ProcessInfo.processInfo.systemUptime - start
        debug("\(label) completed", metadata: ["duration_ms": String(format: "%.1f", elapsed * 1000)])
        return result
    }

    // MARK: - Internal

    private static func emit(level: LogLevel, message: String, metadata: [String: String] = [:],
                             file: String = #fileID, function: String = #function, line: UInt = #line) {
        // Snapshot config atomically to avoid multiple lock acquisitions per log call
        let cfg = configLock.withLock { _config }
        guard level >= cfg.minimumLevel else { return }

        let shouldLog: Bool
        #if DEBUG
        shouldLog = cfg.isEnabled
        #else
        shouldLog = cfg.releaseLoggingEnabled && level >= .warn
        #endif

        guard shouldLog else { return }

        let entry = LogEntry(
            timestamp: Date(),
            level: level,
            message: message,
            metadata: metadata,
            file: file,
            function: function,
            line: line
        )

        // 输出到控制台（DEBUG only）
        #if DEBUG
        ConsoleLogDestination().write(entry)
        #endif

        // 输出到自定义目标（Release 也可用）
        let dests = destinationLock.withLock { destinations }
        for dest in dests {
            dest.write(entry)
        }
    }
}
