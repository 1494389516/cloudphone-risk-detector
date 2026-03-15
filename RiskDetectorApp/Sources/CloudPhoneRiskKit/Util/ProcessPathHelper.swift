import Darwin
import Foundation

/// Resolves process executable path or name for a given PID.
///
/// - **macOS**: Uses `proc_pidpath(3)` to return full executable path.
/// - **iOS/tvOS/watchOS**: `proc_pidpath` is not available. Falls back to `sysctl(KERN_PROC_PID)`
///   to obtain `p_comm` (process name, up to 16 chars). Callers should handle the shorter
///   identifier for matching (e.g. "lldb", "frida" still match).
///
/// - Parameter pid: Process ID to resolve.
/// - Returns: Full path on macOS; process name on iOS; `nil` on failure.
func processPath(for pid: pid_t) -> String? {
#if os(macOS)
    var pathBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    let result = proc_pidpath(pid, &pathBuffer, UInt32(PATH_MAX))
    guard result > 0 else { return nil }
    return String(cString: pathBuffer)
#else
    // iOS: proc_pidpath is not available. Use sysctl(KERN_PROC_PID) to get p_comm.
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size
    guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
    let bytes = withUnsafeBytes(of: info.kp_proc.p_comm) { raw in
        Array(raw.prefix { $0 != 0 })
    }
    return String(decoding: bytes, as: UTF8.self)
#endif
}
