import Darwin

/// Thread-safe value container using `os_unfair_lock`.
///
/// Replaces scattered `NSLock` + manual lock/unlock with scoped access.
/// `os_unfair_lock` is faster than `NSLock` and avoids priority inversion.
///
/// Usage:
/// ```swift
/// private let state = Mutex(MyState())
/// func read() -> Int { state.withLock { $0.value } }
/// func write(_ v: Int) { state.withLock { $0.value = v } }
/// ```
final class Mutex<Value>: @unchecked Sendable {
    private let _lock: os_unfair_lock_t
    private var _value: Value

    init(_ value: Value) {
        _lock = .allocate(capacity: 1)
        _lock.initialize(to: os_unfair_lock())
        _value = value
    }

    deinit {
        _lock.deinitialize(count: 1)
        _lock.deallocate()
    }

    /// Execute a closure with exclusive access to the protected value.
    @discardableResult
    func withLock<T>(_ body: (inout Value) throws -> T) rethrows -> T {
        os_unfair_lock_lock(_lock)
        defer { os_unfair_lock_unlock(_lock) }
        return try body(&_value)
    }
}

// UnfairLock is defined in UnfairLock.swift
