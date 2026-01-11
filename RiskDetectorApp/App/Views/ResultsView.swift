import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

struct ResultsView: View {
    #if canImport(CloudPhoneRiskAppCore)
    let dto: RiskReportDTO
    #else
    let dto: Any
    #endif

    @EnvironmentObject var detectionVM: DetectionViewModel
    @EnvironmentObject var settingsVM: SettingsViewModel
    @Environment(\.presentationMode) private var presentationMode

    @State private var showShareSheet = false
    @State private var showCopyAlert = false
    @State private var showSaveAlert = false
    @State private var savedPath: String?
    @State private var appearAnimation = false

    var body: some View {
        NavigationView {
            #if canImport(CloudPhoneRiskAppCore)
            resultsContent
            #else
            Text("Preview not available")
            #endif
        }
    }

    #if canImport(CloudPhoneRiskAppCore)
    private var resultsContent: some View {
        let level = RiskLevel.from(score: dto.score)

        return ZStack {
            // 渐变背景
            LinearGradient(
                colors: [
                    level.color.opacity(0.05),
                    Color(.systemGroupedBackground),
                    Color(.systemGroupedBackground)
                ],
                startPoint: .top,
                endPoint: .center
            )
            .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 20) {
                    // 顶部分数展示
                    scoreHeader(level: level)
                        .opacity(appearAnimation ? 1 : 0)
                        .offset(y: appearAnimation ? 0 : 20)

                    // 硬信号分组（越狱）- 纯 DTO 驱动
                    hardSignalsSection
                        .opacity(appearAnimation ? 1 : 0)
                        .offset(y: appearAnimation ? 0 : 20)

                    // 软信号分组（网络）- 纯 DTO 驱动
                    networkSignalsSection
                        .opacity(appearAnimation ? 1 : 0)
                        .offset(y: appearAnimation ? 0 : 20)

                    // 软信号分组（云手机/服务端）- 纯 DTO 驱动
                    cloudPhoneSignalsSection
                        .opacity(appearAnimation ? 1 : 0)
                        .offset(y: appearAnimation ? 0 : 20)

                    // JSON 展示（调试模式下展开）
                    JSONTextView(jsonString: jsonString)
                        .opacity(appearAnimation ? 1 : 0)

                    // 操作按钮
                    actionButtons
                        .opacity(appearAnimation ? 1 : 0)

                    Spacer(minLength: 40)
                }
                .padding(.top, 8)
            }
        }
        .navigationTitle("检测结果")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarItems(trailing: Button("完成") {
            presentationMode.wrappedValue.dismiss()
        }
        .font(.system(size: 16, weight: .semibold)))
        .alert(isPresented: $showCopyAlert) {
            Alert(
                title: Text("已复制"),
                message: Text("JSON 已复制到剪贴板"),
                dismissButton: .default(Text("确定"))
            )
        }
        .alert(isPresented: $showSaveAlert) {
            Alert(
                title: Text("已保存"),
                message: Text(savedPath ?? "保存成功"),
                dismissButton: .default(Text("确定"))
            )
        }
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(items: [jsonString])
        }
        .onAppear {
            withAnimation(.easeOut(duration: 0.6)) {
                appearAnimation = true
            }
        }
    }

    private var jsonString: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(dto),
           let str = String(data: data, encoding: .utf8) {
            return str
        }
        return "{}"
    }

    // MARK: - 调试开关
    private var showDetails: Bool {
        settingsVM.debugShowDetailedSignals
    }

    // MARK: - 分数头部
    private func scoreHeader(level: RiskLevel) -> some View {
        VStack(spacing: 0) {
            // 分数展示区
            HStack(alignment: .center, spacing: 20) {
                // 左侧分数
                VStack(alignment: .leading, spacing: 6) {
                    Text("风险分数")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.secondary)

                    HStack(alignment: .firstTextBaseline, spacing: 4) {
                        Text("\(Int(dto.score))")
                            .font(.system(size: 56, weight: .bold, design: .rounded))
                            .foregroundColor(level.color)

                        Text("/ 100")
                            .font(.system(size: 18, weight: .medium))
                            .foregroundColor(.secondary)
                    }
                }

                Spacer()

                // 右侧风险标签
                VStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .fill(level.color.opacity(0.15))
                            .frame(width: 60, height: 60)

                        Image(systemName: level.icon)
                            .font(.system(size: 28))
                            .foregroundColor(level.color)
                    }

                    Text(level.rawValue)
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundColor(level.color)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background(
                            Capsule()
                                .fill(level.color.opacity(0.12))
                        )
                }
            }
            .padding(20)

            Divider()
                .padding(.horizontal, 16)

            // 时间戳和摘要
            HStack {
                Image(systemName: "clock.fill")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                Text(dto.generatedAt)
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundColor(.secondary)
                Spacer()

                // 设备ID预览
                if !dto.deviceID.isEmpty {
                    Text("Device: \(String(dto.deviceID.prefix(8)))...")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)

            // 调试模式指示器
            if showDetails {
                HStack(spacing: 4) {
                    Image(systemName: "ladybug.fill")
                        .font(.system(size: 10))
                    Text("调试模式：点击信号查看详情")
                        .font(.system(size: 11, weight: .medium))
                }
                .foregroundColor(.orange)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(
                    Capsule()
                        .fill(Color.orange.opacity(0.1))
                )
                .padding(.bottom, 12)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
                .shadow(color: level.color.opacity(0.15), radius: 20, x: 0, y: 8)
        )
        .padding(.horizontal, 16)
    }

    // MARK: - 硬信号分组（纯 DTO 驱动）
    private var hardSignalsSection: some View {
        let signals = dto.hardSignals.map { signal in
            SignalDisplayItem(
                id: signal.id,
                title: signal.title,
                detected: signal.detected,
                isHard: signal.kind == .hard,
                confidence: signal.confidence,
                method: signal.method,
                evidence: signal.evidenceSummary
            )
        }

        return VStack(spacing: 0) {
            SignalGroupView(
                title: "越狱检测（硬结论）",
                icon: "lock.shield.fill",
                iconColor: .red,
                signals: signals,
                showDetails: showDetails
            )

            // 越狱方法列表（仅在检测到越狱时显示）
            if !dto.jailbreak.detectedMethods.isEmpty {
                jailbreakMethodsList
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 10, x: 0, y: 4)
        )
        .padding(.horizontal, 16)
    }

    private var jailbreakMethodsList: some View {
        VStack(alignment: .leading, spacing: 0) {
            Divider()
                .padding(.horizontal, 16)

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 12))
                        .foregroundColor(.red)
                    Text("检测到的越狱特征")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.red)
                }
                .padding(.horizontal, 16)
                .padding(.top, 12)

                ForEach(dto.jailbreak.detectedMethods.prefix(showDetails ? 10 : 5), id: \.self) { method in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(Color.red.opacity(0.3))
                            .frame(width: 6, height: 6)
                        Text(formatMethod(method))
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.primary)
                            .lineLimit(showDetails ? nil : 1)
                        Spacer()
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 2)
                }

                // 显示更多提示
                if dto.jailbreak.detectedMethods.count > (showDetails ? 10 : 5) {
                    Text("还有 \(dto.jailbreak.detectedMethods.count - (showDetails ? 10 : 5)) 项...")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 20)
                        .padding(.top, 4)
                }
            }
            .padding(.bottom, 12)
        }
    }

    // MARK: - 网络信号分组（纯 DTO 驱动）
    private var networkSignalsSection: some View {
        let signals = dto.softSignals
            .filter { $0.id == "vpn" || $0.id == "proxy" }
            .map { signal in
                SignalDisplayItem(
                    id: signal.id,
                    title: signal.title,
                    detected: signal.detected,
                    isHard: false,
                    confidence: signal.confidence,
                    method: signal.method,
                    evidence: signal.evidenceSummary
                )
            }

        return VStack(spacing: 0) {
            SignalGroupView(
                title: "网络信号（仅供参考）",
                icon: "network",
                iconColor: .blue,
                signals: signals,
                showDetails: showDetails
            )

            // 提示
            signalHintBar(
                icon: "info.circle.fill",
                text: "网络信号仅供参考，强结论需结合服务端数据",
                color: .blue
            )
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 10, x: 0, y: 4)
        )
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    // MARK: - 云手机信号分组（纯 DTO 驱动）
    private var cloudPhoneSignalsSection: some View {
        let signals = dto.softSignals
            .filter { $0.id.hasPrefix("cloud_") }
            .map { signal in
                SignalDisplayItem(
                    id: signal.id,
                    title: signal.title,
                    detected: signal.detected,
                    isHard: false,
                    confidence: signal.confidence,
                    method: signal.method,
                    evidence: signal.evidenceSummary
                )
            }

        return VStack(spacing: 0) {
            SignalGroupView(
                title: "云手机信号（需服务端）",
                icon: "server.rack",
                iconColor: .purple,
                signals: signals,
                showDetails: showDetails
            )

            signalHintBar(
                icon: "info.circle.fill",
                text: cloudPhoneHintText,
                color: .purple
            )
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 10, x: 0, y: 4)
        )
        .clipShape(RoundedRectangle(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    /// 云手机提示文案（根据是否有服务端数据动态调整）
    private var cloudPhoneHintText: String {
        if dto.server != nil {
            return "已接收服务端信号"
        }
        return "云手机/机房IP/IP聚合度等需服务端提供"
    }

    // MARK: - 通用提示栏
    private func signalHintBar(icon: String, text: String, color: Color) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundColor(color)
            Text(text)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.secondary)
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(color.opacity(0.05))
    }

    // MARK: - 操作按钮
    private var actionButtons: some View {
        HStack(spacing: 12) {
            // 保存按钮
            Button {
                saveReport()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "square.and.arrow.down")
                        .font(.system(size: 14, weight: .semibold))
                    Text("保存")
                        .font(.system(size: 14, weight: .semibold))
                }
                .foregroundColor(.blue)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.blue, lineWidth: 1.5)
                        .background(Color.blue.opacity(0.05).cornerRadius(12))
                )
            }

            // 分享按钮
            Button {
                showShareSheet = true
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "square.and.arrow.up")
                        .font(.system(size: 14, weight: .semibold))
                    Text("分享")
                        .font(.system(size: 14, weight: .semibold))
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(
                            LinearGradient(
                                colors: [Color.blue, Color.blue.opacity(0.8)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                )
                .shadow(color: Color.blue.opacity(0.3), radius: 8, x: 0, y: 4)
            }

            // 复制按钮
            Button {
                copyToClipboard()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "doc.on.doc")
                        .font(.system(size: 14, weight: .semibold))
                    Text("复制")
                        .font(.system(size: 14, weight: .semibold))
                }
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color(.systemGray6))
                )
            }
        }
        .padding(.horizontal, 16)
    }

    // MARK: - Actions
    private func saveReport() {
        savedPath = detectionVM.save(config: settingsVM.currentConfig())
        showSaveAlert = true
    }

    private func copyToClipboard() {
        UIPasteboard.general.string = jsonString
        showCopyAlert = true
    }

    private func formatMethod(_ method: String) -> String {
        if let lastComponent = method.split(separator: "/").last {
            return String(lastComponent)
        }
        return method
    }
    #endif
}

// MARK: - Share Sheet
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    Text("ResultsView Preview")
}
