import Foundation
import os

/// 轻量级自旋锁包装，用于替换热路径上的 NSLock。
///
/// `os_unfair_lock` 比 NSLock 快约 2-3 倍（无 Objective-C 消息派发开销），
/// 适用于临界区极短（<10μs）的高频访问场景，如配置读取和状态查询。
///
/// 注意事项：
/// - 不可递归持有（与 NSLock 行为一致）
/// - 持锁期间不可执行可能阻塞的操作（如 I/O、网络）
/// - 适用于读多写少的快速状态访问
final class UnfairLock: @unchecked Sendable {
    private let _lock: os_unfair_lock_t

    init() {
        _lock = .allocate(capacity: 1)
        _lock.initialize(to: os_unfair_lock())
    }

    deinit {
        _lock.deinitialize(count: 1)
        _lock.deallocate()
    }

    @inline(__always)
    func lock() {
        os_unfair_lock_lock(_lock)
    }

    @inline(__always)
    func unlock() {
        os_unfair_lock_unlock(_lock)
    }

    /// 在锁保护下执行闭包并返回结果
    @inline(__always)
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}
