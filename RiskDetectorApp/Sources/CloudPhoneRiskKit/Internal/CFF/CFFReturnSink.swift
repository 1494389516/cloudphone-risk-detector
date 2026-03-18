import Foundation

internal struct CFFReturnSink<Value> {
    private enum Storage {
        case pending
        case value(Value)
        case poisoned
    }

    private var storage: Storage = .pending

    internal var isResolved: Bool {
        switch storage {
        case .value:
            return true
        case .pending, .poisoned:
            return false
        }
    }

    internal var isPoisoned: Bool {
        if case .poisoned = storage {
            return true
        }
        return false
    }

    internal mutating func store(_ value: Value) {
        storage = .value(value)
    }

    internal mutating func poison() {
        storage = .poisoned
    }

    internal func resolve(or fallback: @autoclosure () -> Value) -> Value {
        switch storage {
        case .value(let value):
            return value
        case .pending, .poisoned:
            return fallback()
        }
    }
}
