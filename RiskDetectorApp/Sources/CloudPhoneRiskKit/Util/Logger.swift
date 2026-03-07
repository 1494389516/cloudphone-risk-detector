import Foundation

public enum Logger {
#if DEBUG
    public static var isEnabled = true
#else
    public static var isEnabled = false
#endif

    public static func log(_ message: @autoclosure () -> String) {
        guard isEnabled else { return }
#if DEBUG
        print("[CloudPhoneRiskKit] \(message())")
#endif
    }
}
