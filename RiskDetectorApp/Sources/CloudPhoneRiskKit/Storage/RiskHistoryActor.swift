import Foundation

// MARK: - Actor-based Risk History Access
//
// Provides async/await access to RiskHistoryStore.
// Async callers use this actor; sync callers continue using RiskHistoryStore directly.

/// Actor-based facade for risk history operations.
@available(iOS 13.0, macOS 10.15, *)
public actor RiskHistoryActor {

    public static let shared = RiskHistoryActor()

    private let store: RiskHistoryStore

    init(store: RiskHistoryStore = .shared) {
        self.store = store
    }

    /// Append a risk event to the history.
    public func append(_ event: RiskHistoryEvent) {
        store.append(event)
    }

    /// Compute time pattern for the last 24 hours.
    public func pattern(now: TimeInterval = Date().timeIntervalSince1970) -> TimePattern {
        store.pattern(now: now)
    }
}
