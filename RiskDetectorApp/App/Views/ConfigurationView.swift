import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

/// 配置管理界面
///
/// **主流程接入**：已接入主流程。入口：设置 Tab → 高级 → 配置管理（NavigationLink）。
/// 决策：保留在主流程中，作为高级配置的次级页面。
///
/// 功能：
/// 1. 检测开关配置
/// 2. 阈值设置
/// 3. 预设场景切换
/// 4. 高级选项
struct ConfigurationView: View {
    @EnvironmentObject var settingsVM: SettingsViewModel
    @State private var showResetAlert = false
    @State private var showExportSheet = false
    
    var body: some View {
        Form {
            // 预设场景
            presetSection
            
            // 检测开关
            detectionTogglesSection
            
            // 阈值设置
            thresholdSection
            
            // 越狱检测配置
            jailbreakSection
            
            // 远程配置
            remoteConfigSection
            
            // 操作
            actionsSection
        }
        .navigationTitle("配置管理")
        .navigationBarTitleDisplayMode(.large)
        .alert(isPresented: $showResetAlert) {
            Alert(
                title: Text("重置配置"),
                message: Text("确定要将所有配置重置为默认值吗？"),
                primaryButton: .cancel(),
                secondaryButton: .destructive(Text("重置")) { resetToDefault() }
            )
        }
        .sheet(isPresented: $showExportSheet) {
            exportSheet
        }
        .onDisappear {
            settingsVM.save()
        }
    }
    
    // MARK: - 预设场景
    
    private var presetSection: some View {
        Section(header: Text("检测场景")) {
            Picker("检测场景", selection: $settingsVM.selectedPreset) {
                Text("默认模式").tag(PresetMode.default)
                Text("严格模式").tag(PresetMode.strict)
                Text("宽松模式").tag(PresetMode.relaxed)
                Text("自定义").tag(PresetMode.custom)
            }
            .onChange(of: settingsVM.selectedPreset) { newValue in
                settingsVM.applyPreset(newValue)
            }
            
            if settingsVM.selectedPreset != .custom {
                presetDescription(settingsVM.selectedPreset)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
    
    @ViewBuilder
    private func presetDescription(_ preset: PresetMode) -> some View {
        switch preset {
        case .default:
            Text("平衡的检测策略，适合大多数场景")
        case .strict:
            Text("更敏感的检测，降低漏报率")
        case .relaxed:
            Text("更宽松的检测，降低误报率")
        case .custom:
            EmptyView()
        }
    }
    
    // MARK: - 检测开关
    
    private var detectionTogglesSection: some View {
        Section(header: Text("检测模块")) {
            Toggle("行为分析", isOn: $settingsVM.enableBehaviorDetect)
            Toggle("网络信号", isOn: $settingsVM.enableNetworkSignals)
            
            if settingsVM.enableBehaviorDetect {
                Toggle("触摸分析", isOn: $settingsVM.enableTouchAnalysis)
                Toggle("运动分析", isOn: $settingsVM.enableMotionAnalysis)
            }
        }
    }
    
    // MARK: - 阈值设置
    
    private var thresholdSection: some View {
        Section(header: Text("风险阈值")) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("高风险阈值")
                    Spacer()
                    Text("\(Int(settingsVM.threshold))")
                        .font(.system(size: 17, weight: .semibold, design: .rounded))
                        .foregroundColor(.blue)
                }
                
                Slider(value: $settingsVM.threshold, in: 30...90, step: 5)
                HStack {
                    Text("30")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    Text("90")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                thresholdDescription(settingsVM.threshold)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.vertical, 8)
        }
    }
    
    @ViewBuilder
    private func thresholdDescription(_ threshold: Double) -> some View {
        switch threshold {
        case 30..<50:
            Text("严格：轻微异常即触发")
        case 50..<70:
            Text("标准：平衡误报与漏报")
        case 70...90:
            Text("宽松：仅严重风险触发")
        default:
            EmptyView()
        }
    }
    
    // MARK: - 越狱检测配置
    
    private var jailbreakSection: some View {
        Section(header: Text("越狱检测")) {
            Toggle("文件检测", isOn: $settingsVM.jailbreakEnableFileDetect)
            Toggle("Dyld 检测", isOn: $settingsVM.jailbreakEnableDyldDetect)
            Toggle("环境检测", isOn: $settingsVM.jailbreakEnableEnvDetect)
            Toggle("系统调用检测", isOn: $settingsVM.jailbreakEnableSysctlDetect)
            Toggle("URL Scheme 检测", isOn: $settingsVM.jailbreakEnableSchemeDetect)
            Toggle("Hook 检测", isOn: $settingsVM.jailbreakEnableHookDetect)
            
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("越狱判定阈值")
                    Spacer()
                    Text("\(Int(settingsVM.jailbreakThreshold))")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(.blue)
                }
                
                Slider(value: $settingsVM.jailbreakThreshold, in: 20...80, step: 5)
            }
            .padding(.vertical, 4)
        }
    }
    
    // MARK: - 远程配置
    
    private var remoteConfigSection: some View {
        Section(header: Text("远程配置")) {
            HStack {
                Text("配置版本")
                Spacer()
                Text(settingsVM.remoteConfigVersion)
                    .foregroundColor(.secondary)
            }
            
            HStack {
                Text("上次更新")
                Spacer()
                Text(settingsVM.remoteConfigLastUpdate)
                    .foregroundColor(.secondary)
            }
            
            Button {
                Task {
                    await settingsVM.fetchRemoteConfig()
                }
            } label: {
                HStack {
                    Image(systemName: "arrow.clockwise")
                    Text("检查更新")
                    Spacer()
                    if settingsVM.isFetchingConfig {
                        ProgressView()
                    }
                }
                .foregroundColor(.blue)
            }
            .disabled(settingsVM.isFetchingConfig)
        }
    }
    
    // MARK: - 操作
    
    private var actionsSection: some View {
        Section(header: Text("操作")) {
            Button {
                showExportSheet = true
            } label: {
                HStack {
                    Image(systemName: "square.and.arrow.up")
                    Text("导出配置")
                }
            }
            
            Button {
                showResetAlert = true
            } label: {
                HStack {
                    Image(systemName: "arrow.counterclockwise")
                    Text("重置为默认")
                        .foregroundColor(.red)
                }
            }
        }
    }
    
    // MARK: - 导出面板
    
    private var exportSheet: some View {
        NavigationView {
            VStack(spacing: 20) {
                Image(systemName: "doc.text.fill")
                    .font(.system(size: 60))
                    .foregroundColor(.blue)
                
                Text("导出配置")
                    .font(.title2)
                    .fontWeight(.bold)
                
                Text("可以导出当前配置为 JSON 格式，便于备份或分享")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                
                configurationPreview
                
                Button {
                    // 导出逻辑
                    exportConfiguration()
                } label: {
                    HStack {
                        Image(systemName: "square.and.arrow.up")
                        Text("导出")
                    }
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .padding(.horizontal)
            }
            .padding()
            .navigationTitle("导出配置")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") {
                        showExportSheet = false
                    }
                }
            }
        }
    }
    
    private var configurationPreview: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("当前配置")
                .font(.caption)
                .foregroundColor(.secondary)
            
            ScrollView {
                Text(configJSONString)
                    .font(.system(size: 12, weight: .regular, design: .monospaced))
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            }
            .frame(height: 150)
        }
        .padding(.horizontal)
    }
    
    private var configJSONString: String {
        """
        {
          "preset": "\(settingsVM.selectedPreset)",
          "threshold": \(Int(settingsVM.threshold)),
          "enableBehaviorDetect": \(settingsVM.enableBehaviorDetect),
          "enableNetworkSignals": \(settingsVM.enableNetworkSignals),
          "jailbreakThreshold": \(Int(settingsVM.jailbreakThreshold))
        }
        """
    }
    
    // MARK: - 辅助方法
    
    private func resetToDefault() {
        settingsVM.applyPreset(.default)
        settingsVM.selectedPreset = .default
    }
    
    private func exportConfiguration() {
        // 实际导出逻辑
        print("导出配置")
        showExportSheet = false
    }
}

// MARK: - Preset Mode

enum PresetMode: String, CaseIterable {
    case `default`
    case strict
    case relaxed
    case custom
    
    var displayName: String {
        switch self {
        case .default: return "默认模式"
        case .strict: return "严格模式"
        case .relaxed: return "宽松模式"
        case .custom: return "自定义"
        }
    }
}

// MARK: - SettingsViewModel Extension

extension SettingsViewModel {
    var selectedPreset: PresetMode {
        get {
            // 根据当前配置判断预设
            let config = currentConfig()
            if config.threshold == 55 && config.jailbreakThreshold == 45 {
                return .strict
            } else if config.threshold == 70 && config.jailbreakThreshold == 60 {
                return .relaxed
            } else if config.threshold == 60 && config.jailbreakThreshold == 50 {
                return .default
            }
            return .custom
        }
        set { applyPreset(newValue) }
    }
    
    func applyPreset(_ preset: PresetMode) {
        switch preset {
        case .default:
            threshold = 60
            jailbreakThreshold = 50
            enableBehaviorDetect = true
            enableNetworkSignals = true
        case .strict:
            threshold = 55
            jailbreakThreshold = 45
            enableBehaviorDetect = true
            enableNetworkSignals = true
        case .relaxed:
            threshold = 70
            jailbreakThreshold = 60
            enableBehaviorDetect = false
            enableNetworkSignals = true
        case .custom:
            break
        }
    }
    
    var remoteConfigVersion: String {
        "1.0.0"
    }
    
    var remoteConfigLastUpdate: String {
        "从未"
    }
    
    var isFetchingConfig: Bool {
        false
    }
    
    func fetchRemoteConfig() async {
        // 模拟远程配置获取
    }
    
    var enableTouchAnalysis: Bool {
        get { true }
        set { }
    }
    
    var enableMotionAnalysis: Bool {
        get { true }
        set { }
    }
}

// MARK: - Preview

#Preview {
    NavigationView {
        ConfigurationView()
            .environmentObject(SettingsViewModel())
    }
}
