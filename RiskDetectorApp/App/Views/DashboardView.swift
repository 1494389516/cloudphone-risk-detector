import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
#endif

struct DashboardView: View {
    @EnvironmentObject var detectionVM: DetectionViewModel
    @EnvironmentObject var settingsVM: SettingsViewModel
    @State private var animateGlow = false
    @State private var pulseScale: CGFloat = 1.0

    var body: some View {
        NavigationView {
            ZStack {
                // 渐变背景
                backgroundGradient

                ScrollView {
                    VStack(spacing: 28) {
                        // 仪表盘区域
                        gaugeSection
                            .padding(.top, 16)

                        // 快速状态指示（从 DTO 读取）
                        if let dto = detectionVM.lastDTO {
                            quickStatusSection(dto: dto)
                                .transition(.opacity.combined(with: .scale(scale: 0.95)))
                        }

                        // 检测按钮
                        detectButton
                            .padding(.horizontal, 4)

                        // 上次检测信息
                        if let dto = detectionVM.lastDTO {
                            lastDetectionInfo(dto: dto)
                                .transition(.opacity.combined(with: .move(edge: .bottom)))
                        }

                        Spacer(minLength: 60)
                    }
                    .padding(.horizontal, 20)
                }
            }
            .navigationTitle("风险检测")
            .sheet(isPresented: $detectionVM.showResults) {
                if let dto = detectionVM.lastDTO {
                    ResultsView(dto: dto)
                        .environmentObject(detectionVM)
                        .environmentObject(settingsVM)
                }
            }
            .onAppear {
                detectionVM.startIfNeeded()
                withAnimation(.easeInOut(duration: 2).repeatForever(autoreverses: true)) {
                    animateGlow = true
                }
            }
        }
    }

    // MARK: - 渐变背景
    private var backgroundGradient: some View {
        LinearGradient(
            gradient: Gradient(colors: [
                Color(.systemBackground),
                Color(.systemGroupedBackground),
                Color(.systemBackground).opacity(0.8)
            ]),
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        .ignoresSafeArea()
    }

    // MARK: - 仪表盘
    @ViewBuilder
    private var gaugeSection: some View {
        if let dto = detectionVM.lastDTO, let level = detectionVM.riskLevel {
            ZStack {
                // 外发光效果
                Circle()
                    .fill(level.color.opacity(0.15))
                    .frame(width: 260, height: 260)
                    .blur(radius: animateGlow ? 30 : 20)
                    .scaleEffect(animateGlow ? 1.05 : 0.95)

                RiskGaugeView(
                    score: dto.score,
                    riskLevel: level,
                    size: 220
                )
            }
            .animation(.easeInOut(duration: 2).repeatForever(autoreverses: true), value: animateGlow)
        } else {
            // 未检测状态
            ZStack {
                // 背景光晕
                Circle()
                    .fill(
                        RadialGradient(
                            gradient: Gradient(colors: [
                                Color.blue.opacity(0.1),
                                Color.clear
                            ]),
                            center: .center,
                            startRadius: 60,
                            endRadius: 140
                        )
                    )
                    .frame(width: 280, height: 280)
                    .scaleEffect(pulseScale)
                    .onAppear {
                        withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true)) {
                            pulseScale = 1.1
                        }
                    }

                Circle()
                    .stroke(
                        LinearGradient(
                            colors: [Color.gray.opacity(0.3), Color.gray.opacity(0.1)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 20
                    )
                    .frame(width: 200, height: 200)

                // 内圈装饰
                Circle()
                    .stroke(Color.gray.opacity(0.1), lineWidth: 1)
                    .frame(width: 160, height: 160)

                VStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill(Color.blue.opacity(0.1))
                            .frame(width: 80, height: 80)

                        Image(systemName: "shield.lefthalf.filled")
                            .font(.system(size: 40, weight: .light))
                            .foregroundColor(.blue)
                    }

                    Text("点击检测")
                        .font(.system(size: 16, weight: .medium, design: .rounded))
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - 快速状态（从 DTO 读取 hardSignals/softSignals，支持三态）
    #if canImport(CloudPhoneRiskAppCore)
    private func quickStatusSection(dto: RiskReportDTO) -> some View {
        // 计算云手机信号状态（三态）
        let cloudState: SignalDisplayState = {
            guard let server = dto.server else {
                // 无服务端数据 → 需服务端
                return .needBackend
            }
            // 有服务端数据，判断是否检测到
            if server.isDatacenter == true { return .detected }
            if (server.ipDeviceAgg ?? 0) >= 50 { return .detected }
            if (server.ipAccountAgg ?? 0) >= 100 { return .detected }
            if let tags = server.riskTags, !tags.isEmpty { return .detected }
            return .notDetected
        }()

        // 计算 VPN 状态（三态）
        let vpnState: SignalDisplayState = {
            if dto.network.vpn.method == "unavailable_simulator" {
                return .unavailable
            }
            return dto.network.vpn.detected ? .detected : .notDetected
        }()

        // 计算代理状态（三态）
        let proxyState: SignalDisplayState = {
            if dto.network.proxy.method == "unavailable_simulator" {
                return .unavailable
            }
            return dto.network.proxy.detected ? .detected : .notDetected
        }()

        return VStack(spacing: 16) {
            HStack(spacing: 16) {
                // 越狱状态（硬信号）
                StatusBadge(
                    title: "越狱",
                    isDetected: dto.jailbreak.isJailbroken,
                    isHardSignal: true
                )

                // VPN 状态（软信号，三态）
                StatusBadge(
                    title: "VPN",
                    state: vpnState,
                    isHardSignal: false
                )

                // 代理状态（软信号，三态）
                StatusBadge(
                    title: "代理",
                    state: proxyState,
                    isHardSignal: false
                )

                // 云手机/服务端信号（软信号，三态）
                StatusBadge(
                    title: "云手机",
                    state: cloudState,
                    isHardSignal: false
                )
            }

            // 提示文字
            HStack(spacing: 4) {
                Image(systemName: "info.circle.fill")
                    .font(.caption2)
                Text("VPN/代理/云手机仅作为信号参考")
            }
            .font(.caption2)
            .foregroundColor(.secondary)
        }
        .padding(.vertical, 20)
        .padding(.horizontal, 16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.06), radius: 15, x: 0, y: 5)
        )
    }
    #else
    private func quickStatusSection(dto: Any) -> some View {
        EmptyView()
    }
    #endif

    // MARK: - 检测按钮
    private var detectButton: some View {
        Button {
            #if canImport(CloudPhoneRiskAppCore)
            withAnimation(.spring(response: 0.3, dampingFraction: 0.6)) {
                detectionVM.detect(config: settingsVM.currentConfig())
            }
            #else
            detectionVM.detect()
            #endif
        } label: {
            HStack(spacing: 12) {
                if detectionVM.isDetecting {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    Text("检测中...")
                        .font(.system(size: 17, weight: .semibold, design: .rounded))
                } else {
                    Image(systemName: "play.circle.fill")
                        .font(.system(size: 22))
                    Text("开始检测")
                        .font(.system(size: 17, weight: .semibold, design: .rounded))
                }
            }
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 18)
            .background(
                Group {
                    if detectionVM.isDetecting {
                        LinearGradient(
                            colors: [Color.gray, Color.gray.opacity(0.8)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    } else {
                        LinearGradient(
                            colors: [Color.blue, Color.blue.opacity(0.8)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    }
                }
            )
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .shadow(color: detectionVM.isDetecting ? Color.gray.opacity(0.3) : Color.blue.opacity(0.4), radius: 12, x: 0, y: 6)
        }
        .disabled(detectionVM.isDetecting)
        .scaleEffect(detectionVM.isDetecting ? 0.98 : 1.0)
        .animation(.spring(response: 0.3, dampingFraction: 0.6), value: detectionVM.isDetecting)
    }

    // MARK: - 上次检测信息（从 DTO 读取）
    #if canImport(CloudPhoneRiskAppCore)
    private func lastDetectionInfo(dto: RiskReportDTO) -> some View {
        let level = RiskLevel.from(score: dto.score)
        return HStack(spacing: 16) {
            // 左侧图标
            ZStack {
                Circle()
                    .fill(level.color.opacity(0.1))
                    .frame(width: 44, height: 44)

                Image(systemName: "clock.arrow.circlepath")
                    .font(.system(size: 18))
                    .foregroundColor(level.color)
            }

            // 中间信息
            VStack(alignment: .leading, spacing: 4) {
                Text("最近检测")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.secondary)

                Text(dto.generatedAt)
                    .font(.system(size: 14, weight: .regular, design: .monospaced))
                    .foregroundColor(.primary)
            }

            Spacer()

            // 右侧分数
            VStack(alignment: .trailing, spacing: 2) {
                Text("\(Int(dto.score))")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundColor(level.color)

                Text("分")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.05), radius: 10, x: 0, y: 4)
        )
    }
    #else
    private func lastDetectionInfo(dto: Any) -> some View {
        EmptyView()
    }
    #endif
}

// MARK: - 状态徽章（支持三态）
struct StatusBadge: View {
    let title: String
    let state: SignalDisplayState
    let isHardSignal: Bool

    @State private var isAnimating = false

    // 兼容旧的初始化方法
    init(title: String, isDetected: Bool, isHardSignal: Bool) {
        self.title = title
        self.state = isDetected ? .detected : .notDetected
        self.isHardSignal = isHardSignal
    }

    // 新的三态初始化方法
    init(title: String, state: SignalDisplayState, isHardSignal: Bool) {
        self.title = title
        self.state = state
        self.isHardSignal = isHardSignal
    }

    var body: some View {
        VStack(spacing: 8) {
            ZStack {
                // 背景圆
                Circle()
                    .fill(backgroundColor)
                    .frame(width: 52, height: 52)
                    .shadow(color: shadowColor, radius: state == .detected ? 8 : 4, x: 0, y: 2)

                // 图标
                badgeIcon
            }

            // 标题
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.secondary)

            // 状态文字（仅非硬信号显示）
            if !isHardSignal && (state == .needBackend || state == .unavailable) {
                Text(state.statusText)
                    .font(.system(size: 9, weight: .medium))
                    .foregroundColor(state.statusColor)
            }
        }
        .frame(width: 64)
    }

    @ViewBuilder
    private var badgeIcon: some View {
        if isHardSignal {
            // 硬信号：✓ 或 ✗
            Image(systemName: state == .detected ? "xmark" : "checkmark")
                .font(.system(size: 20, weight: .bold))
                .foregroundColor(iconColor)
        } else {
            // 软信号：根据三态显示不同图标
            switch state {
            case .detected:
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 18, weight: .medium))
                    .foregroundColor(.white)
                    .scaleEffect(isAnimating ? 1.1 : 1.0)
                    .onAppear {
                        withAnimation(.easeInOut(duration: 1).repeatForever(autoreverses: true)) {
                            isAnimating = true
                        }
                    }
            case .notDetected:
                Image(systemName: "minus")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundColor(.gray)
            case .unavailable:
                Image(systemName: "nosign")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundColor(.gray)
            case .needBackend:
                Image(systemName: "server.rack")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundColor(.purple)
            }
        }
    }

    private var backgroundColor: Color {
        if isHardSignal {
            return state == .detected ? Color.red.opacity(0.15) : Color.green.opacity(0.15)
        } else {
            switch state {
            case .detected: return Color.blue
            case .notDetected: return Color.gray.opacity(0.1)
            case .unavailable: return Color.gray.opacity(0.1)
            case .needBackend: return Color.purple.opacity(0.15)
            }
        }
    }

    private var iconColor: Color {
        state == .detected ? .red : .green
    }

    private var shadowColor: Color {
        if isHardSignal {
            return state == .detected ? Color.red.opacity(0.3) : Color.green.opacity(0.2)
        } else {
            switch state {
            case .detected: return Color.blue.opacity(0.4)
            case .needBackend: return Color.purple.opacity(0.3)
            default: return Color.clear
            }
        }
    }
}

#Preview {
    DashboardView()
        .environmentObject(DetectionViewModel())
        .environmentObject(SettingsViewModel())
}
