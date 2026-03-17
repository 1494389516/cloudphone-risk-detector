import SwiftUI
import CloudPhoneRiskAppCore

@main
struct RiskDetectorAppApp: App {
    init() {
        RiskDetectionService.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
