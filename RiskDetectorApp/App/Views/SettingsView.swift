import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
#endif

struct SettingsView: View {
    @EnvironmentObject var settingsVM: SettingsViewModel
    @State private var showResetAlert = false
    @State private var appearAnimation = false

    var body: some View {
        NavigationView {
            ZStack {
                Color(.systemGroupedBackground)
                    .ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 20) {
                        // 检测配置
                        detectionConfigSection
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 越狱检测
                        jailbreakSection
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 阈值设置
                        thresholdSection
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 存储设置
                        storageSection
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 调试设置
                        debugSection
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 重置按钮
                        resetButton
                            .opacity(appearAnimation ? 1 : 0)

                        // 关于
                        aboutSection
                            .opacity(appearAnimation ? 1 : 0)

                        Spacer(minLength: 40)
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                }
            }
            .navigationTitle("设置")
            .onAppear {
                withAnimation(.easeOut(duration: 0.5)) {
                    appearAnimation = true
                }
            }
            .onDisappear {
                settingsVM.save()
            }
            .alert(isPresented: $showResetAlert) {
                Alert(
                    title: Text("确认重置"),
                    message: Text("确定要恢复所有设置到默认值吗？"),
                    primaryButton: .destructive(Text("重置")) { settingsVM.resetToDefault() },
                    secondaryButton: .cancel(Text("取消"))
                )
            }
        }
    }

    // MARK: - 检测配置
    private var detectionConfigSection: some View {
        SettingsSection(
            title: "检测配置",
            icon: "gearshape.fill",
            iconColor: .blue,
            footer: "行为采集包括触摸和传感器数据"
        ) {
            SettingsToggleRow(
                title: "行为采集",
                subtitle: "触摸轨迹 + 陀螺仪",
                icon: "hand.tap.fill",
                iconColor: .orange,
                isOn: $settingsVM.enableBehaviorDetect
            )

            Divider().padding(.leading, 52)

            SettingsToggleRow(
                title: "网络信号",
                subtitle: "VPN / 代理检测",
                icon: "network",
                iconColor: .purple,
                isOn: $settingsVM.enableNetworkSignals
            )
        }
    }

    // MARK: - 越狱检测
    private var jailbreakSection: some View {
        SettingsSection(
            title: "越狱检测",
            icon: "lock.shield.fill",
            iconColor: .red
        ) {
            Group {
                SettingsToggleRow(
                    title: "文件检测",
                    icon: "folder.fill",
                    iconColor: .blue,
                    isOn: $settingsVM.jailbreakEnableFileDetect
                )

                Divider().padding(.leading, 52)

                SettingsToggleRow(
                    title: "dyld 检测",
                    icon: "puzzlepiece.fill",
                    iconColor: .green,
                    isOn: $settingsVM.jailbreakEnableDyldDetect
                )

                Divider().padding(.leading, 52)

                SettingsToggleRow(
                    title: "环境变量检测",
                    icon: "terminal.fill",
                    iconColor: .gray,
                    isOn: $settingsVM.jailbreakEnableEnvDetect
                )

                Divider().padding(.leading, 52)

                SettingsToggleRow(
                    title: "系统调用检测",
                    icon: "cpu.fill",
                    iconColor: .blue,
                    isOn: $settingsVM.jailbreakEnableSysctlDetect
                )

                Divider().padding(.leading, 52)

                SettingsToggleRow(
                    title: "URL Scheme 检测",
                    icon: "link",
                    iconColor: .purple,
                    isOn: $settingsVM.jailbreakEnableSchemeDetect
                )

                Divider().padding(.leading, 52)

                SettingsToggleRow(
                    title: "Hook 检测",
                    icon: "wand.and.rays",
                    iconColor: .pink,
                    isOn: $settingsVM.jailbreakEnableHookDetect
                )
            }
        }
    }

    // MARK: - 阈值设置
    private var thresholdSection: some View {
        SettingsSection(
            title: "阈值设置",
            icon: "slider.horizontal.3",
            iconColor: .orange,
            footer: "分数超过阈值时判定为高风险"
        ) {
            ThresholdSliderRow(
                title: "风险阈值",
                value: $settingsVM.threshold,
                color: riskColor(for: settingsVM.threshold)
            )

            Divider().padding(.leading, 16)

            ThresholdSliderRow(
                title: "越狱阈值",
                value: $settingsVM.jailbreakThreshold,
                color: riskColor(for: settingsVM.jailbreakThreshold)
            )
        }
    }

    private func riskColor(for value: Double) -> Color {
        if value < 40 { return .green }
        else if value < 60 { return .orange }
        else { return .red }
    }

    // MARK: - 存储设置
    private var storageSection: some View {
        SettingsSection(
            title: "存储设置",
            icon: "externaldrive.fill",
            iconColor: .blue,
            footer: "使用 AES-GCM 加密，密钥保存在 Keychain"
        ) {
            SettingsToggleRow(
                title: "加密存储",
                subtitle: "AES-GCM 256-bit",
                icon: "lock.fill",
                iconColor: .green,
                isOn: $settingsVM.storeEncryptionEnabled
            )

            Divider().padding(.leading, 52)

            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.purple.opacity(0.15))
                        .frame(width: 36, height: 36)

                    Image(systemName: "doc.on.doc.fill")
                        .font(.system(size: 16))
                        .foregroundColor(.purple)
                }

                Text("最大文件数")
                    .font(.system(size: 15))

                Spacer()

                Stepper(value: $settingsVM.storeMaxFiles, in: 10...200, step: 10) {
                    Text("\(settingsVM.storeMaxFiles)")
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundColor(.purple)
                        .frame(minWidth: 36)
                }
            }
            .padding(.vertical, 8)
        }
    }

    // MARK: - 调试设置
    private var debugSection: some View {
        SettingsSection(
            title: "调试",
            icon: "ladybug.fill",
            iconColor: .red
        ) {
            SettingsToggleRow(
                title: "日志输出",
                subtitle: "输出调试日志到控制台",
                icon: "text.alignleft",
                iconColor: .gray,
                isOn: Binding(
                    get: { settingsVM.logEnabled },
                    set: { settingsVM.setLogEnabled($0) }
                )
            )

            Divider().padding(.leading, 52)

            SettingsToggleRow(
                title: "详细信号信息",
                subtitle: "结果页显示 method/evidence 详情",
                icon: "doc.text.magnifyingglass",
                iconColor: .blue,
                isOn: $settingsVM.debugShowDetailedSignals
            )

            Divider().padding(.leading, 52)

            SettingsToggleRow(
                title: "模拟云手机信号",
                subtitle: "注入模拟的服务端信号用于测试",
                icon: "server.rack",
                iconColor: .orange,
                isOn: Binding(
                    get: { settingsVM.debugSimulateCloudPhoneSignals },
                    set: { settingsVM.setSimulateCloudPhoneSignals($0) }
                )
            )
        }
    }

    // MARK: - 重置按钮
    private var resetButton: some View {
        Button {
            showResetAlert = true
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "arrow.counterclockwise")
                    .font(.system(size: 14, weight: .semibold))
                Text("恢复默认配置")
                    .font(.system(size: 15, weight: .semibold))
            }
            .foregroundColor(.red)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.red.opacity(0.1))
            )
        }
    }

    // MARK: - 关于
    private var aboutSection: some View {
        SettingsSection(
            title: "关于",
            icon: "info.circle.fill",
            iconColor: .gray
        ) {
            HStack {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.blue.opacity(0.15))
                            .frame(width: 36, height: 36)

                        Image(systemName: "app.badge")
                            .font(.system(size: 16))
                            .foregroundColor(.blue)
                    }

                    Text("版本")
                        .font(.system(size: 15))
                }

                Spacer()

                Text("1.0.0")
                    .font(.system(size: 14, weight: .medium, design: .monospaced))
                    .foregroundColor(.secondary)
            }
            .padding(.vertical, 8)

            Divider().padding(.leading, 52)

            HStack {
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.green.opacity(0.15))
                            .frame(width: 36, height: 36)

                        Image(systemName: "shippingbox.fill")
                            .font(.system(size: 16))
                            .foregroundColor(.green)
                    }

                    Text("CloudPhoneRiskKit")
                        .font(.system(size: 15))
                }

                Spacer()

                #if canImport(CloudPhoneRiskAppCore)
                HStack(spacing: 4) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 12))
                    Text("已集成")
                        .font(.system(size: 13, weight: .medium))
                }
                .foregroundColor(.green)
                #else
                HStack(spacing: 4) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 12))
                    Text("未集成")
                        .font(.system(size: 13, weight: .medium))
                }
                .foregroundColor(.red)
                #endif
            }
            .padding(.vertical, 8)
        }
    }
}

// MARK: - 设置分组
struct SettingsSection<Content: View>: View {
    let title: String
    let icon: String
    let iconColor: Color
    var footer: String? = nil
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // 标题
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(iconColor)

                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.secondary)
                    .textCase(.uppercase)
            }
            .padding(.horizontal, 4)

            // 内容
            VStack(spacing: 0) {
                content
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(Color(.systemBackground))
                    .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 2)
            )

            // 脚注
            if let footer = footer {
                Text(footer)
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 4)
            }
        }
    }
}

// MARK: - 开关行
struct SettingsToggleRow: View {
    let title: String
    var subtitle: String? = nil
    let icon: String
    let iconColor: Color
    @Binding var isOn: Bool

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(iconColor.opacity(0.15))
                    .frame(width: 36, height: 36)

                Image(systemName: icon)
                    .font(.system(size: 16))
                    .foregroundColor(iconColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 15))

                if let subtitle = subtitle {
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            Toggle("", isOn: $isOn)
                .labelsHidden()
        }
        .padding(.vertical, 4)
    }
}

// MARK: - 阈值滑块行
struct ThresholdSliderRow: View {
    let title: String
    @Binding var value: Double
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(title)
                    .font(.system(size: 15))

                Spacer()

                Text("\(Int(value))")
                    .font(.system(size: 18, weight: .bold, design: .rounded))
                    .foregroundColor(color)
                    .frame(minWidth: 36)
            }

            // 自定义滑块
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    // 背景轨道
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.gray.opacity(0.2))
                        .frame(height: 8)

                    // 进度条
                    RoundedRectangle(cornerRadius: 4)
                        .fill(
                            LinearGradient(
                                colors: [color.opacity(0.6), color],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .frame(width: geometry.size.width * CGFloat((value - 20) / 60), height: 8)

                    // 滑块
                    Circle()
                        .fill(Color.white)
                        .frame(width: 24, height: 24)
                        .shadow(color: color.opacity(0.4), radius: 4, x: 0, y: 2)
                        .overlay(
                            Circle()
                                .stroke(color, lineWidth: 2)
                        )
                        .offset(x: geometry.size.width * CGFloat((value - 20) / 60) - 12)
                        .gesture(
                            DragGesture()
                                .onChanged { gesture in
                                    let newValue = gesture.location.x / geometry.size.width * 60 + 20
                                    value = min(max(newValue, 20), 80)
                                    // 步进到5的倍数
                                    value = Double(Int(value / 5) * 5)
                                }
                        )
                }
            }
            .frame(height: 24)
        }
        .padding(.vertical, 8)
    }
}

#Preview {
    SettingsView()
        .environmentObject(SettingsViewModel())
}
