import SwiftUI

/// Demo App 主界面：把三个 ViewModel 接入 TabView，做最小可用展示
///（检测状态/结果、历史列表、设置开关），不再只留占位文本。
struct ContentView: View {
    @StateObject private var detection = DetectionViewModel()
    @StateObject private var history = HistoryViewModel()
    @StateObject private var settings = SettingsViewModel()

    var body: some View {
        TabView {
            detectionTab
                .tabItem { Label("检测", systemImage: "shield.checkered") }
            historyTab
                .tabItem { Label("历史", systemImage: "clock.arrow.circlepath") }
            settingsTab
                .tabItem { Label("设置", systemImage: "gearshape") }
        }
        .onAppear {
            detection.startIfNeeded()
            history.reload()
        }
    }

    // MARK: - 检测

    private var detectionTab: some View {
        NavigationView {
            VStack(spacing: 16) {
                switch detection.state {
                case .idle:
                    Text("尚未检测").foregroundColor(.secondary)
                case .detecting:
                    ProgressView("检测中…")
                case .completed:
                    if let dto = detection.lastDTO {
                        resultView(dto: dto)
                    } else {
                        Text("检测完成，但无结果").foregroundColor(.secondary)
                    }
                case .error(let message):
                    Text("检测失败：\(message)").foregroundColor(.red)
                }
                Button("开始检测") {
                    detection.detect(config: settings.currentConfig())
                }
                .buttonStyle(.borderedProminent)
                .disabled(detection.isDetecting)
                if detection.lastDTO != nil {
                    Button("保存报告") {
                        if detection.save(config: settings.currentConfig()) != nil {
                            history.reload()
                        }
                    }
                    .buttonStyle(.bordered)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("风险检测")
        }
    }

    private func resultView(dto: RiskReportDTO) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if let level = detection.riskLevel {
                    Image(systemName: level.icon).foregroundColor(level.color)
                    Text(level.rawValue).foregroundColor(level.color).bold()
                }
                Text("分数：\(Int(dto.score))")
                Spacer()
            }
            Text("高风险：\(dto.isHighRisk ? "是" : "否")")
            Text("越狱：\(dto.jailbreak.isJailbroken ? "是" : "否")（置信度 \(Int(dto.jailbreak.confidence))）")
            if !dto.jailbreak.detectedMethods.isEmpty {
                Text("命中：\(dto.jailbreak.detectedMethods.joined(separator: ", "))")
                    .font(.caption).foregroundColor(.secondary)
            }
            Text(dto.summary).font(.caption).foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - 历史

    private var historyTab: some View {
        NavigationView {
            Group {
                if history.isLoading {
                    ProgressView("加载中…")
                } else if history.items.isEmpty {
                    Text("暂无历史报告").foregroundColor(.secondary)
                } else {
                    List {
                        ForEach(history.items) { item in
                            Button {
                                history.loadDetail(for: item)
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(item.filename).font(.subheadline).lineLimit(1)
                                        Text("\(item.formattedDate) · \(item.formattedSize)")
                                            .font(.caption).foregroundColor(.secondary)
                                    }
                                    Spacer()
                                    if let level = item.riskLevel {
                                        Text(level.rawValue).foregroundColor(level.color).font(.caption)
                                    }
                                }
                            }
                        }
                        .onDelete { history.delete(atOffsets: $0) }
                    }
                }
            }
            .navigationTitle("历史报告")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("全部删除") { history.deleteAll() }
                        .disabled(history.items.isEmpty)
                }
            }
            .onAppear { history.reload() }
            .sheet(isPresented: $history.showDetail) {
                if let dto = history.selectedDTO {
                    ScrollView {
                        resultView(dto: dto).padding()
                    }
                    .navigationTitle("报告详情")
                }
            }
        }
    }

    // MARK: - 设置

    private var settingsTab: some View {
        NavigationView {
            Form {
                Section("检测开关") {
                    Toggle("行为检测", isOn: $settings.enableBehaviorDetect)
                    Toggle("网络信号", isOn: $settings.enableNetworkSignals)
                }
                Section("越狱检测") {
                    Toggle("文件检测", isOn: $settings.jailbreakEnableFileDetect)
                    Toggle("dyld 检测", isOn: $settings.jailbreakEnableDyldDetect)
                    Toggle("环境变量检测", isOn: $settings.jailbreakEnableEnvDetect)
                    Toggle("sysctl 检测", isOn: $settings.jailbreakEnableSysctlDetect)
                    Toggle("URL Scheme 检测", isOn: $settings.jailbreakEnableSchemeDetect)
                    Toggle("Hook 检测", isOn: $settings.jailbreakEnableHookDetect)
                }
                Section("阈值") {
                    HStack {
                        Text("风险阈值")
                        Spacer()
                        Text("\(Int(settings.threshold))")
                    }
                    Slider(value: $settings.threshold, in: 0...100, step: 1)
                    HStack {
                        Text("越狱阈值")
                        Spacer()
                        Text("\(Int(settings.jailbreakThreshold))")
                    }
                    Slider(value: $settings.jailbreakThreshold, in: 0...100, step: 1)
                }
                Section("调试") {
                    Toggle("日志", isOn: $settings.logEnabled)
                    Toggle("显示详细信号", isOn: $settings.debugShowDetailedSignals)
                }
                Section {
                    Button("保存设置") { settings.save() }
                    Button("恢复默认") { settings.resetToDefault() }
                }
            }
            .navigationTitle("设置")
            .onDisappear { settings.save() }
        }
    }
}
