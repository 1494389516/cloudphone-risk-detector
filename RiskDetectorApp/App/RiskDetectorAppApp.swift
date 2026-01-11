import SwiftUI
import CloudPhoneRiskAppCore

@main
struct RiskDetectorAppApp: App {
    @StateObject private var detectionVM = DetectionViewModel()
    @StateObject private var historyVM = HistoryViewModel()
    @StateObject private var settingsVM = SettingsViewModel()

    init() {
        // 启动采集（触摸 + 传感器）
        RiskDetectionService.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(detectionVM)
                .environmentObject(historyVM)
                .environmentObject(settingsVM)
        }
    }
}
