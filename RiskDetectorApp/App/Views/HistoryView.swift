import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

struct HistoryView: View {
    @EnvironmentObject var historyVM: HistoryViewModel
    @State private var showDeleteAllAlert = false
    @State private var appearAnimation = false

    var body: some View {
        NavigationView {
            ZStack {
                // 背景
                Color(.systemGroupedBackground)
                    .ignoresSafeArea()

                Group {
                    if historyVM.isLoading {
                        loadingView
                    } else if historyVM.items.isEmpty {
                        emptyState
                    } else {
                        historyList
                    }
                }
            }
            .navigationTitle("检测历史")
            .navigationBarItems(trailing: HStack(spacing: 16) {
                if !historyVM.items.isEmpty {
                    Button(action: { showDeleteAllAlert = true }) {
                        Image(systemName: "trash")
                            .font(.system(size: 16))
                            .foregroundColor(.red.opacity(0.8))
                    }
                }
            })
            .onAppear {
                historyVM.reload()
                withAnimation(.easeOut(duration: 0.5)) {
                    appearAnimation = true
                }
            }
            .alert(isPresented: $showDeleteAllAlert) {
                Alert(
                    title: Text("确认删除"),
                    message: Text("确定要删除所有检测记录吗？此操作不可撤销。"),
                    primaryButton: .destructive(Text("删除全部")) { historyVM.deleteAll() },
                    secondaryButton: .cancel(Text("取消"))
                )
            }
            .sheet(isPresented: $historyVM.showDetail) {
                #if canImport(CloudPhoneRiskAppCore)
                if let item = historyVM.selectedItem, let dto = historyVM.selectedDTO {
                    HistoryDetailView(item: item, dto: dto)
                }
                #else
                Text("Detail not available")
                #endif
            }
        }
    }

    // MARK: - 加载状态
    private var loadingView: some View {
        VStack(spacing: 20) {
            ProgressView()
                .scaleEffect(1.2)

            Text("加载中...")
                .font(.system(size: 15, weight: .medium))
                .foregroundColor(.secondary)
        }
    }

    // MARK: - 空状态
    private var emptyState: some View {
        VStack(spacing: 20) {
            ZStack {
                Circle()
                    .fill(Color.gray.opacity(0.1))
                    .frame(width: 120, height: 120)

                Image(systemName: "clock.arrow.circlepath")
                    .font(.system(size: 50, weight: .light))
                    .foregroundColor(.gray)
            }

            VStack(spacing: 8) {
                Text("暂无检测记录")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundColor(.primary)

                Text("完成一次检测后\n记录将显示在这里")
                    .font(.system(size: 14))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .lineSpacing(4)
            }
        }
        .padding()
        .opacity(appearAnimation ? 1 : 0)
        .offset(y: appearAnimation ? 0 : 20)
    }

    // MARK: - 历史列表
    private var historyList: some View {
        ScrollView {
            LazyVStack(spacing: 12) {
                ForEach(Array(historyVM.items.enumerated()), id: \.element.id) { index, item in
                    HistoryRowView(item: item)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                                historyVM.loadDetail(for: item)
                            }
                        }
                        .opacity(appearAnimation ? 1 : 0)
                        .offset(y: appearAnimation ? 0 : 20)
                        .animation(.easeOut(duration: 0.4).delay(Double(index) * 0.05), value: appearAnimation)
                        .contextMenu {
                            Button {
                                if let idx = historyVM.items.firstIndex(where: { $0.id == item.id }) {
                                    historyVM.delete(atOffsets: IndexSet(integer: idx))
                                }
                            } label: {
                                Label("删除", systemImage: "trash")
                                    .foregroundColor(.red)
                            }
                        }
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 8)
            .padding(.bottom, 40)
        }
    }
}

// MARK: - 历史记录行（美化版）
struct HistoryRowView: View {
    let item: HistoryItem
    @State private var isPressed = false

    var body: some View {
        HStack(spacing: 14) {
            // 左侧图标
            ZStack {
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [riskColor.opacity(0.2), riskColor.opacity(0.1)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 50, height: 50)

                Image(systemName: item.isEncrypted ? "lock.shield.fill" : "doc.text.fill")
                    .font(.system(size: 20))
                    .foregroundColor(riskColor)
            }

            // 中间信息
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(formatFilename(item.filename))
                        .font(.system(size: 15, weight: .semibold))
                        .lineLimit(1)

                    Spacer()

                    if let score = item.summary?.score {
                        HStack(spacing: 2) {
                            Text("\(Int(score))")
                                .font(.system(size: 22, weight: .bold, design: .rounded))
                                .foregroundColor(riskColor)

                            Text("分")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }
                    }
                }

                // 时间和大小
                HStack(spacing: 10) {
                    HStack(spacing: 4) {
                        Image(systemName: "calendar")
                            .font(.system(size: 10))
                        Text(item.formattedDate)
                    }
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)

                    HStack(spacing: 4) {
                        Image(systemName: "doc")
                            .font(.system(size: 10))
                        Text(item.formattedSize)
                    }
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)

                    Spacer()
                }

                // 快速状态标签
                if let summary = item.summary {
                    HStack(spacing: 6) {
                        if summary.jailbreakIsJailbroken == true {
                            StatusTag(title: "越狱", icon: "exclamationmark.shield.fill", color: .red)
                        }
                        if summary.vpnDetected == true {
                            StatusTag(title: "VPN", icon: "network", color: .blue)
                        }
                        if summary.proxyDetected == true {
                            StatusTag(title: "代理", icon: "arrow.triangle.branch", color: .purple)
                        }
                        if summary.cloudDetected == true {
                            StatusTag(title: "云手机", icon: "server.rack", color: .orange)
                        }
                        Spacer()
                    }
                }
            }

            // 右侧箭头
            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 2)
        )
        .scaleEffect(isPressed ? 0.98 : 1.0)
        .animation(.spring(response: 0.2, dampingFraction: 0.7), value: isPressed)
    }

    private var riskColor: Color {
        item.riskLevel?.color ?? .gray
    }

    private func formatFilename(_ name: String) -> String {
        // 简化文件名显示
        let cleaned = name
            .replacingOccurrences(of: "risk_", with: "")
            .replacingOccurrences(of: ".enc", with: "")
            .replacingOccurrences(of: ".json", with: "")
        return cleaned.isEmpty ? name : cleaned
    }
}

// MARK: - 状态标签
struct StatusTag: View {
    let title: String
    let icon: String
    let color: Color

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: icon)
                .font(.system(size: 9, weight: .semibold))
            Text(title)
                .font(.system(size: 10, weight: .medium))
        }
        .foregroundColor(color)
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(
            Capsule()
                .fill(color.opacity(0.12))
        )
    }
}

// MARK: - 历史详情页（美化版）
#if canImport(CloudPhoneRiskAppCore)
struct HistoryDetailView: View {
    let item: HistoryItem
    let dto: RiskReportDTO
    @Environment(\.presentationMode) private var presentationMode
    @State private var showCopyAlert = false
    @State private var showShareSheet = false
    @State private var appearAnimation = false

    private var jsonString: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(dto),
           let str = String(data: data, encoding: .utf8) {
            return str
        }
        return "{}"
    }

    var body: some View {
        NavigationView {
            ZStack {
                Color(.systemGroupedBackground)
                    .ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 16) {
                        // 文件信息
                        fileInfoSection
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 分数卡片
                        scoreCard
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // 信号概览
                        signalOverview
                            .opacity(appearAnimation ? 1 : 0)
                            .offset(y: appearAnimation ? 0 : 15)

                        // JSON 内容
                        JSONTextView(jsonString: jsonString)
                            .opacity(appearAnimation ? 1 : 0)

                        // 操作按钮
                        actionButtons
                            .opacity(appearAnimation ? 1 : 0)

                        Spacer(minLength: 40)
                    }
                    .padding(16)
                }
            }
            .navigationTitle("报告详情")
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
            .sheet(isPresented: $showShareSheet) {
                ShareSheet(items: [jsonString])
            }
            .onAppear {
                withAnimation(.easeOut(duration: 0.5)) {
                    appearAnimation = true
                }
            }
        }
    }

    private var fileInfoSection: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(Color.blue.opacity(0.1))
                    .frame(width: 44, height: 44)

                Image(systemName: "doc.text.fill")
                    .font(.system(size: 18))
                    .foregroundColor(.blue)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text(item.filename)
                    .font(.system(size: 15, weight: .semibold))
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text(item.formattedDate)
                    Text("·")
                    Text(item.formattedSize)
                    if item.isEncrypted {
                        Text("·")
                        HStack(spacing: 2) {
                            Image(systemName: "lock.fill")
                            Text("已加密")
                        }
                        .foregroundColor(.green)
                    }
                }
                .font(.system(size: 12))
                .foregroundColor(.secondary)
            }

            Spacer()
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 2)
        )
    }

    private var scoreCard: some View {
        let level = RiskLevel.from(score: dto.score)
        return HStack {
            VStack(alignment: .leading, spacing: 6) {
                Text("风险分数")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.secondary)

                HStack(alignment: .firstTextBaseline, spacing: 4) {
                    Text("\(Int(dto.score))")
                        .font(.system(size: 44, weight: .bold, design: .rounded))
                        .foregroundColor(level.color)

                    Text("/ 100")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            VStack(spacing: 6) {
                ZStack {
                    Circle()
                        .fill(level.color.opacity(0.15))
                        .frame(width: 50, height: 50)

                    Image(systemName: level.icon)
                        .font(.system(size: 22))
                        .foregroundColor(level.color)
                }

                Text(level.rawValue)
                    .font(.system(size: 13, weight: .bold, design: .rounded))
                    .foregroundColor(level.color)
            }
        }
        .padding(18)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: level.color.opacity(0.1), radius: 12, x: 0, y: 4)
        )
    }

    private var signalOverview: some View {
        // 云手机信号状态（三态）
        let cloudState: SignalDisplayState = {
            guard let server = dto.server else {
                return .needBackend
            }
            if server.isDatacenter == true { return .detected }
            if (server.ipDeviceAgg ?? 0) >= 50 { return .detected }
            if (server.ipAccountAgg ?? 0) >= 100 { return .detected }
            if let tags = server.riskTags, !tags.isEmpty { return .detected }
            return .notDetected
        }()

        // VPN 状态（三态）
        let vpnState: SignalDisplayState = {
            if dto.network.vpn.method == "unavailable_simulator" {
                return .unavailable
            }
            return dto.network.vpn.detected ? .detected : .notDetected
        }()

        // 代理状态（三态）
        let proxyState: SignalDisplayState = {
            if dto.network.proxy.method == "unavailable_simulator" {
                return .unavailable
            }
            return dto.network.proxy.detected ? .detected : .notDetected
        }()

        return VStack(alignment: .leading, spacing: 14) {
            Text("信号概览")
                .font(.system(size: 15, weight: .semibold))

            HStack(spacing: 14) {
                SignalBadge(title: "越狱", detected: dto.jailbreak.isJailbroken, isHard: true)
                SignalBadge(title: "VPN", state: vpnState, isHard: false)
                SignalBadge(title: "代理", state: proxyState, isHard: false)
                SignalBadge(title: "云手机", state: cloudState, isHard: false)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 2)
        )
    }

    private var actionButtons: some View {
        HStack(spacing: 12) {
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
        }
    }

    private func copyToClipboard() {
        UIPasteboard.general.string = jsonString
        showCopyAlert = true
    }
}

struct SignalBadge: View {
    let title: String
    let state: SignalDisplayState
    let isHard: Bool

    // 兼容旧的初始化方法
    init(title: String, detected: Bool, isHard: Bool) {
        self.title = title
        self.state = detected ? .detected : .notDetected
        self.isHard = isHard
    }

    // 新的三态初始化方法
    init(title: String, state: SignalDisplayState, isHard: Bool) {
        self.title = title
        self.state = state
        self.isHard = isHard
    }

    var body: some View {
        VStack(spacing: 6) {
            ZStack {
                Circle()
                    .fill(backgroundColor)
                    .frame(width: 44, height: 44)

                badgeIcon
            }

            Text(title)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)

            // 状态文字（仅非硬信号显示）
            if !isHard && (state == .needBackend || state == .unavailable) {
                Text(state.statusText)
                    .font(.system(size: 9, weight: .medium))
                    .foregroundColor(state.statusColor)
            }
        }
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private var badgeIcon: some View {
        if isHard {
            Image(systemName: state == .detected ? "xmark" : "checkmark")
                .font(.system(size: 18, weight: .bold))
                .foregroundColor(state == .detected ? .red : .green)
        } else {
            switch state {
            case .detected:
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 16, weight: .medium))
                    .foregroundColor(.white)
            case .notDetected:
                Image(systemName: "minus")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.gray)
            case .unavailable:
                Image(systemName: "nosign")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.gray)
            case .needBackend:
                Image(systemName: "server.rack")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.purple)
            }
        }
    }

    private var backgroundColor: Color {
        if isHard {
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
}
#endif

#Preview {
    HistoryView()
        .environmentObject(HistoryViewModel())
}
