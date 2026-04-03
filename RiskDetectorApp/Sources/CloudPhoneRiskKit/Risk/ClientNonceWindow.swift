import Foundation

// MARK: - Client-Side Nonce Deduplication Window

/// Thread-safe rolling window of recently-emitted client-side nonces.
///
/// Since nonces are UUID v4 (122 bits of entropy) collision probability is
/// astronomically small; however this window provides a defence-in-depth layer
/// against two practical threats:
///
/// - **Logic bugs in calling code** – e.g. an accidental loop that serialises
///   the same envelope object twice without calling `create()` again.
/// - **UUID-generator tampering** – a rooted device or emulator that patches
///   `UUID()` to return a deterministic value; the window catches the repeat on
///   the second attempt within the expiry interval.
///
/// The window is keyed on `nonce` only (not session-token), because the
/// envelope's own nonce is globally unique by design.  Entries are lazily
/// evicted once they fall outside the `windowMillis` expiry horizon.
internal final class ClientNonceWindow: @unchecked Sendable {

    // MARK: Shared instance

    /// Process-global singleton.  All `ReportEnvelope.create()` calls share
    /// this window so that cross-session duplicates are also detected.
    static let shared = ClientNonceWindow()

    // MARK: State

    private var entries: [String: Int64] = [:]   // nonce → ts at registration
    private let lock = NSLock()
    private let windowMillis: Int64

    // MARK: Init

    init(windowMillis: Int64 = 300_000) {
        self.windowMillis = windowMillis
    }

    // MARK: API

    /// Attempts to register `nonce` with the given timestamp.
    ///
    /// - Returns: `true` if the nonce had not been seen before and was
    ///   successfully registered; `false` if it was already present within the
    ///   active window (duplicate detected).
    func registerIfNew(_ nonce: String, ts: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        evictExpired(now: ts)
        guard entries[nonce] == nil else { return false }
        entries[nonce] = ts
        return true
    }

    // MARK: Private

    private func evictExpired(now: Int64) {
        let cutoff = now - windowMillis
        entries = entries.filter { $0.value > cutoff }
    }
}
