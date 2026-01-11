import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

// MARK: - Signal Display State (三态)
enum SignalDisplayState {
    case detected           // 检测到（detected=true）
    case notDetected        // 未检测到（detected=false, method为具体方法）
    case unavailable        // 环境不可用（method="unavailable_simulator"）
    case needBackend        // 需要服务端（method="need_backend"）

    var statusText: String {
        switch self {
        case .detected: return "检测到"
        case .notDetected: return "未检测到"
        case .unavailable: return "不可用"
        case .needBackend: return "需服务端"
        }
    }

    var statusIcon: String {
        switch self {
        case .detected: return "exclamationmark.circle.fill"
        case .notDetected: return "checkmark.circle.fill"
        case .unavailable: return "nosign"
        case .needBackend: return "server.rack"
        }
    }

    var statusColor: Color {
        switch self {
        case .detected: return .red
        case .notDetected: return .green
        case .unavailable: return .gray
        case .needBackend: return .purple
        }
    }
}

// MARK: - Signal Display Item (shared model for UI)
struct SignalDisplayItem: Identifiable {
    let id: String
    let title: String
    let detected: Bool
    let isHard: Bool
    #if canImport(CloudPhoneRiskKit)
    let confidence: SignalConfidence?
    #else
    let confidence: String?
    #endif
    let method: String?
    let evidence: String?

    /// 计算三态
    var displayState: SignalDisplayState {
        if let method = method {
            if method == "unavailable_simulator" || method.contains("unavailable") {
                return .unavailable
            }
            if method == "need_backend" || method.contains("need_backend") {
                return .needBackend
            }
        }
        return detected ? .detected : .notDetected
    }

    /// 格式化的方法名（去掉路径）
    var formattedMethod: String? {
        guard let method = method else { return nil }
        if method == "unavailable_simulator" { return "模拟器环境" }
        if method == "need_backend" { return "服务端数据" }
        return method
    }
}

// MARK: - 单个信号行（增强版，支持三态和折叠详情）
struct SignalRowView: View {
    let item: SignalDisplayItem
    let showDetails: Bool  // 是否显示详情（由调试开关控制）
    @State private var isDetailExpanded: Bool = false
    @State private var isAnimating = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 主行
            Button {
                if hasDetails && showDetails {
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                        isDetailExpanded.toggle()
                    }
                }
            } label: {
                mainRow
            }
            .buttonStyle(.plain)
            .disabled(!hasDetails || !showDetails)

            // 详情区域（折叠）
            if isDetailExpanded && showDetails {
                detailsSection
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }

    private var hasDetails: Bool {
        item.method != nil || item.evidence != nil || item.confidence != nil
    }

    private var mainRow: some View {
        HStack(spacing: 12) {
            // 左侧信息
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(item.title)
                        .font(.system(size: 15, weight: .medium))

                    // 显示是否可展开
                    if hasDetails && showDetails {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundColor(.secondary)
                            .rotationEffect(.degrees(isDetailExpanded ? 90 : 0))
                    }
                }

                // 简要信息（非调试模式也显示）
                if !showDetails, let method = item.formattedMethod {
                    Text(method)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            // 右侧状态指示
            statusIndicator
        }
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }

    @ViewBuilder
    private var statusIndicator: some View {
        let state = item.displayState

        if item.isHard {
            // 硬信号：明确的判定
            hardSignalIndicator(state: state)
        } else {
            // 软信号：三态展示
            softSignalIndicator(state: state)
        }
    }

    private func hardSignalIndicator(state: SignalDisplayState) -> some View {
        HStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(state == .detected ? Color.red.opacity(0.15) : Color.green.opacity(0.15))
                    .frame(width: 32, height: 32)

                Image(systemName: state == .detected ? "xmark" : "checkmark")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(state == .detected ? .red : .green)
            }

            Text(state == .detected ? "异常" : "正常")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(state == .detected ? .red : .green)
        }
    }

    private func softSignalIndicator(state: SignalDisplayState) -> some View {
        HStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(indicatorBackgroundColor(state))
                    .frame(width: 28, height: 28)

                Image(systemName: state.statusIcon)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(indicatorIconColor(state))
                    .scaleEffect(state == .detected && isAnimating ? 1.1 : 1.0)
                    .onAppear {
                        if state == .detected {
                            withAnimation(.easeInOut(duration: 1).repeatForever(autoreverses: true)) {
                                isAnimating = true
                            }
                        }
                    }
            }

            VStack(alignment: .leading, spacing: 0) {
                Text(state.statusText)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(state.statusColor)

                if let conf = confidenceText {
                    Text("置信度: \(conf)")
                        .font(.system(size: 9))
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    private func indicatorBackgroundColor(_ state: SignalDisplayState) -> Color {
        switch state {
        case .detected: return Color.red.opacity(0.15)
        case .notDetected: return Color.green.opacity(0.1)
        case .unavailable: return Color.gray.opacity(0.1)
        case .needBackend: return Color.purple.opacity(0.1)
        }
    }

    private func indicatorIconColor(_ state: SignalDisplayState) -> Color {
        state.statusColor
    }

    #if canImport(CloudPhoneRiskKit)
    private var confidenceText: String? {
        guard let conf = item.confidence else { return nil }
        switch conf {
        case .weak: return "弱"
        case .medium: return "中"
        case .strong: return "强"
        }
    }
    #else
    private var confidenceText: String? {
        return item.confidence
    }
    #endif

    // MARK: - 详情区域
    private var detailsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            // 方法
            if let method = item.method {
                DetailRow(icon: "wrench.and.screwdriver", label: "检测方法", value: method)
            }

            // 证据
            if let evidence = item.evidence, !evidence.isEmpty {
                DetailRow(icon: "doc.text.magnifyingglass", label: "证据", value: evidence)
            }

            // 置信度
            if let conf = confidenceText {
                DetailRow(icon: "chart.bar", label: "置信度", value: conf)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(.tertiarySystemBackground))
        )
        .padding(.leading, 4)
        .padding(.trailing, 4)
        .padding(.bottom, 8)
    }
}

// MARK: - 详情行
private struct DetailRow: View {
    let icon: String
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 10))
                .foregroundColor(.secondary)
                .frame(width: 14)

            Text(label + ":")
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)

            Text(value)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.primary)
                .lineLimit(3)

            Spacer()
        }
    }
}

// MARK: - 可折叠的信号分组（增强版）
struct SignalGroupView: View {
    let title: String
    let icon: String
    let iconColor: Color
    let signals: [SignalDisplayItem]
    let showDetails: Bool  // 是否显示详情
    @State private var isExpanded: Bool = true

    init(
        title: String,
        icon: String,
        iconColor: Color = .blue,
        signals: [SignalDisplayItem],
        showDetails: Bool = false
    ) {
        self.title = title
        self.icon = icon
        self.iconColor = iconColor
        self.signals = signals
        self.showDetails = showDetails
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 标题栏
            Button {
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                    isExpanded.toggle()
                }
            } label: {
                headerView
            }
            .buttonStyle(.plain)

            // 展开内容
            if isExpanded {
                signalsList
            }
        }
        .background(Color(.systemBackground))
    }

    private var headerView: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(iconColor.opacity(0.1))
                    .frame(width: 32, height: 32)

                Image(systemName: icon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(iconColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(.primary)

                Text(statusSummary)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }

            Spacer()

            // 状态徽章
            statusBadges

            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
                .rotationEffect(.degrees(isExpanded ? 90 : 0))
        }
        .padding(.vertical, 14)
        .padding(.horizontal, 16)
        .contentShape(Rectangle())
    }

    private var statusSummary: String {
        let total = signals.count
        let detected = signals.filter { $0.displayState == .detected }.count
        let unavailable = signals.filter { $0.displayState == .unavailable || $0.displayState == .needBackend }.count

        if unavailable > 0 {
            return "\(total) 项 · \(detected) 异常 · \(unavailable) 待定"
        }
        return "\(total) 项检测 · \(detected) 异常"
    }

    @ViewBuilder
    private var statusBadges: some View {
        HStack(spacing: 4) {
            // 异常数量
            let detectedCount = signals.filter { $0.displayState == .detected }.count
            if detectedCount > 0 {
                Text("\(detectedCount)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.white)
                    .frame(width: 18, height: 18)
                    .background(Circle().fill(Color.red))
            }

            // 待定数量（need_backend 或 unavailable）
            let pendingCount = signals.filter {
                $0.displayState == .unavailable || $0.displayState == .needBackend
            }.count
            if pendingCount > 0 {
                Text("\(pendingCount)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.white)
                    .frame(width: 18, height: 18)
                    .background(Circle().fill(Color.purple))
            }
        }
    }

    private var signalsList: some View {
        VStack(spacing: 0) {
            ForEach(Array(signals.enumerated()), id: \.element.id) { index, signal in
                VStack(spacing: 0) {
                    if index > 0 {
                        Divider()
                            .padding(.leading, 60)
                    }

                    SignalRowView(item: signal, showDetails: showDetails)
                        .padding(.horizontal, 16)
                        .padding(.leading, 44)
                }
            }
        }
        .padding(.bottom, 8)
    }
}

// MARK: - 兼容旧的初始化方法（保持向后兼容）
extension SignalDisplayItem {
    #if canImport(CloudPhoneRiskKit)
    init(
        title: String,
        detected: Bool,
        isHard: Bool,
        confidence: SignalConfidence?,
        method: String?,
        evidence: String?
    ) {
        self.id = UUID().uuidString
        self.title = title
        self.detected = detected
        self.isHard = isHard
        self.confidence = confidence
        self.method = method
        self.evidence = evidence
    }
    #else
    init(
        title: String,
        detected: Bool,
        isHard: Bool,
        confidence: String?,
        method: String?,
        evidence: String?
    ) {
        self.id = UUID().uuidString
        self.title = title
        self.detected = detected
        self.isHard = isHard
        self.confidence = confidence
        self.method = method
        self.evidence = evidence
    }
    #endif
}

#Preview {
    ScrollView {
        VStack(spacing: 16) {
            SignalGroupView(
                title: "越狱检测",
                icon: "lock.shield.fill",
                iconColor: .red,
                signals: [
                    SignalDisplayItem(
                        title: "越狱状态",
                        detected: true,
                        isHard: true,
                        confidence: nil,
                        method: "JailbreakEngine",
                        evidence: "检测到 Cydia.app"
                    ),
                ],
                showDetails: true
            )
            .cornerRadius(16)

            SignalGroupView(
                title: "网络信号",
                icon: "network",
                iconColor: .blue,
                signals: [
                    SignalDisplayItem(
                        title: "VPN 隧道",
                        detected: true,
                        isHard: false,
                        confidence: nil,
                        method: "ifaddrs_prefix",
                        evidence: "utun0"
                    ),
                    SignalDisplayItem(
                        title: "系统代理",
                        detected: false,
                        isHard: false,
                        confidence: nil,
                        method: "CFNetworkCopySystemProxySettings",
                        evidence: nil
                    ),
                ],
                showDetails: true
            )
            .cornerRadius(16)

            SignalGroupView(
                title: "云手机信号",
                icon: "server.rack",
                iconColor: .purple,
                signals: [
                    SignalDisplayItem(
                        title: "机房 IP",
                        detected: false,
                        isHard: false,
                        confidence: nil,
                        method: "need_backend",
                        evidence: "no_server_signals"
                    ),
                    SignalDisplayItem(
                        title: "模拟器检测",
                        detected: false,
                        isHard: false,
                        confidence: nil,
                        method: "unavailable_simulator",
                        evidence: nil
                    ),
                ],
                showDetails: true
            )
            .cornerRadius(16)
        }
        .padding()
    }
    .background(Color(.systemGroupedBackground))
}
