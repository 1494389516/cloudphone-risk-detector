import Foundation

public enum Logger {
    public static var isEnabled = false

    public static func log(_ message: @autoclosure () -> String) {
        guard isEnabled else { return }
        print("[CloudPhoneRiskKit] \(message())")
    }
}
