import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

/// 决策结果展示视图
/// 
/// 功能：
/// 1. 显示风险评分和等级
/// 2. 展示各维度信号详情
/// 3. 支持规则溯源
/// 4. 提供建议操作
struct DecisionResultsView: View {
    let dto: RiskReportDTO
    @EnvironmentObject var settingsVM: SettingsViewModel
    @State private var selectedTab = 0
    @State private var showExplanation = false
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // 顶部评分卡片
                scoreCard
                
                // 标签页切换
                pickerTabs
                
                // 内容区域
                tabContent
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("决策结果")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    // MARK: - 评分卡片
    
    private var scoreCard: some View {
        VStack(spacing: 16) {
            // 评分仪表
            ZStack {
                Circle()
                    .stroke(levelColor.opacity(0.2), lineWidth: 12)
                    .frame(width: 140, height: 140)
                
                Circle()
                    .trim(from: 0, to: CGFloat(dto.score / 100))
                    .stroke(levelColor, style: StrokeStyle(lineWidth: 12, lineCap: .round))
                    .frame(width: 140, height: 140)
                    .rotationEffect(.degrees(-90))
                    .animation(.spring(response: 0.6, dampingFraction: 0.7), value: dto.score)
                
                VStack(spacing: 4) {
                    Text("\(Int(dto.score))")
                        .font(.system(size: 42, weight: .bold, design: .rounded))
                        .foregroundColor(levelColor)
                    
                    Text(levelText)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.vertical, 12)
            
            // 判定结果
            HStack(spacing: 12) {
                Image(systemName: dto.isHighRisk ? "exclamationmark.triangle.fill" : "checkmark.shield.fill")
                    .foregroundColor(levelColor)
                    .font(.title3)
                
                Text(dto.isHighRisk ? "高风险设备" : "低风险设备")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundColor(.primary)
                
                Spacer()
                
                Button {
                    showExplanation.toggle()
                } label: {
                    Image(systemName: "questionmark.circle.fill")
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color(.systemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.05), radius: 10, x: 0, y: 4)
        )
        .sheet(isPresented: $showExplanation) {
            explanationSheet
        }
    }
    
    // MARK: - 标签页
    
    private var pickerTabs: some View {
        Picker("视图", selection: $selectedTab) {
            Text("概览").tag(0)
            Text("详情").tag(1)
            Text("建议").tag(2)
        }
        .pickerStyle(.segmented)
    }
    
    // MARK: - 标签页内容
    
    @ViewBuilder
    private var tabContent: some View {
        switch selectedTab {
        case 0:
            overviewTab
        case 1:
            detailsTab
        case 2:
            recommendationsTab
        default:
            EmptyView()
        }
    }
    
    // MARK: - 概览标签页
    
    private var overviewTab: some View {
        VStack(spacing: 16) {
            // 关键指标
            keyMetricsSection
            
            // 风险分布
            riskDistributionSection
            
            // 检测摘要
            summarySection
        }
    }
    
    private var keyMetricsSection: some View {
        VStack(spacing: 12) {
            HStack {
                Text("关键指标")
                    .font(.system(size: 16, weight: .semibold))
                Spacer()
            }
            
            HStack(spacing: 12) {
                MetricCard(title: "信号数", value: "\(dto.signals.count)", color: .blue)
                MetricCard(title: "检测耗时", value: "150ms", color: .green)
                MetricCard(title: "置信度", value: "\(Int(dto.jailbreak.confidence))%", color: .orange)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
        )
    }
    
    private var riskDistributionSection: some View {
        VStack(spacing: 12) {
            HStack {
                Text("风险分布")
                    .font(.system(size: 16, weight: .semibold))
                Spacer()
            }
            
            // 简化的风险分布条
            VStack(alignment: .leading, spacing: 8) {
                RiskBar(label: "越狱风险", value: dto.jailbreak.isJailbroken ? 100 : 0, color: .red)
                RiskBar(label: "网络风险", value: networkRiskScore, color: .blue)
                RiskBar(label: "行为风险", value: behaviorRiskScore, color: .purple)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
        )
    }
    
    private var summarySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("检测摘要")
                    .font(.system(size: 16, weight: .semibold))
                Spacer()
            }
            
            Text(dto.summary)
                .font(.system(size: 14))
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
        )
    }
    
    // MARK: - 详情标签页
    
    private var detailsTab: some View {
        VStack(spacing: 16) {
            // 信号列表
            ForEach(dto.signals.indices, id: \.self) { index in
                SignalDetailCard(signal: dto.signals[index])
            }
        }
    }
    
    // MARK: - 建议标签页
    
    private var recommendationsTab: some View {
        VStack(spacing: 16) {
            ForEach(recommendations, id: \.title) { item in
                RecommendationCard(item: item)
            }
        }
    }
    
    // MARK: - 说明弹窗
    
    private var explanationSheet: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    explanationItem(
                        title: "评分说明",
                        content: "风险评分基于多维度检测，包括越狱检测、网络环境、行为分析等。分数范围 0-100，分数越高风险越大。"
                    )
                    
                    explanationItem(
                        title: "风险等级",
                        content: "低风险（0-29分）：设备环境正常\n中风险（30-59分）：存在可疑信号\n高风险（60-100分）：检测到高风险行为"
                    )
                    
                    explanationItem(
                        title: "阈值设定",
                        content: "当前判定阈值为 \(Int(settingsVM.currentConfig().threshold)) 分，超过此阈值将被标记为高风险设备。"
                    )
                }
                .padding()
            }
            .navigationTitle("评分说明")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") {
                        showExplanation = false
                    }
                }
            }
        }
    }
    
    private func explanationItem(title: String, content: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 16, weight: .semibold))
            
            Text(content)
                .font(.system(size: 14))
                .foregroundColor(.secondary)
        }
    }
    
    // MARK: - 计算属性
    
    private var levelColor: Color {
        if dto.score < 30 { return .green }
        else if dto.score < 60 { return .orange }
        else { return .red }
    }
    
    private var levelText: String {
        if dto.score < 30 { return "低风险" }
        else if dto.score < 60 { return "中风险" }
        else { return "高风险" }
    }
    
    private var networkRiskScore: Double {
        var score = 0.0
        if dto.network.vpn.detected { score += 10 }
        if dto.network.proxy.detected { score += 8 }
        return score
    }
    
    private var behaviorRiskScore: Double {
        dto.signals.filter { $0.category == "behavior" }.reduce(0) { $0 + $1.score }
    }
    
    private var recommendations: [RecommendationItem] {
        var items: [RecommendationItem] = []
        
        if dto.jailbreak.isJailbroken {
            items.append(RecommendationItem(
                title: "检测到越狱",
                description: "设备存在越狱环境，建议拒绝敏感操作",
                action: "拒绝操作",
                severity: .high
            ))
        }
        
        if dto.network.vpn.detected || dto.network.proxy.detected {
            items.append(RecommendationItem(
                title: "网络异常",
                description: "检测到 VPN 或代理连接，建议验证用户身份",
                action: "增加验证",
                severity: .medium
            ))
        }
        
        if dto.score >= 30 && dto.score < 60 {
            items.append(RecommendationItem(
                title: "中等风险",
                description: "存在一些可疑信号，建议持续监控",
                action: "继续监控",
                severity: .medium
            ))
        }
        
        if dto.score < 30 {
            items.append(RecommendationItem(
                title: "环境正常",
                description: "设备检测未发现明显风险",
                action: "正常使用",
                severity: .low
            ))
        }
        
        return items.isEmpty ? [
            RecommendationItem(
                title: "暂无建议",
                description: "当前检测结果正常",
                action: "继续使用",
                severity: .low
            )
        ] : items
    }
}

// MARK: - 指标卡片

struct MetricCard: View {
    let title: String
    let value: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 8) {
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.secondary)
            
            Text(value)
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .foregroundColor(color)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(color.opacity(0.1))
        )
    }
}

// MARK: - 风险条

struct RiskBar: View {
    let label: String
    let value: Double
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(label)
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
                Spacer()
                Text("\(Int(value))%")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(color)
            }
            
            GeometryReader { geometry in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.gray.opacity(0.1))
                    
                    RoundedRectangle(cornerRadius: 4)
                        .fill(color)
                        .frame(width: geometry.size.width * CGFloat(value / 100))
                }
            }
            .frame(height: 8)
        }
    }
}

// MARK: - 信号详情卡片

struct SignalDetailCard: View {
    let signal: RiskSignalDTO
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: categoryIcon)
                    .foregroundColor(categoryColor)
                    .font(.title3)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(signal.id)
                        .font(.system(size: 15, weight: .medium))
                    
                    Text(signal.category)
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Text("+\(Int(signal.score))")
                    .font(.system(size: 18, weight: .bold, design: .rounded))
                    .foregroundColor(categoryColor)
            }
            
            if !signal.evidence.isEmpty {
                Divider()
                
                VStack(alignment: .leading, spacing: 6) {
                    Text("证据:")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.secondary)
                    
                    ForEach(Array(signal.evidence.keys.sorted()), id: \.self) { key in
                        HStack {
                            Text(key)
                                .foregroundColor(.secondary)
                            Text(":")
                                .foregroundColor(.secondary)
                            Text(signal.evidence[key] ?? "")
                                .foregroundColor(.primary)
                            Spacer()
                        }
                        .font(.system(size: 12))
                    }
                }
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
        )
    }
    
    private var categoryColor: Color {
        switch signal.category {
        case "jailbreak": return .red
        case "network": return .blue
        case "behavior": return .purple
        case "cloudphone": return .orange
        default: return .gray
        }
    }
    
    private var categoryIcon: String {
        switch signal.category {
        case "jailbreak": return "exclamationmark.shield.fill"
        case "network": return "antenna.radiowaves.left.and.right"
        case "behavior": return "hand.tap.fill"
        case "cloudphone": return "cloud.fill"
        default: return "info.circle.fill"
        }
    }
}

// MARK: - 建议卡片

struct RecommendationItem: Identifiable {
    let id = UUID()
    let title: String
    let description: String
    let action: String
    let severity: Severity
    
    enum Severity {
        case low, medium, high
        
        var color: Color {
            switch self {
            case .low: return .green
            case .medium: return .orange
            case .high: return .red
            }
        }
        
        var icon: String {
            switch self {
            case .low: return "checkmark.circle.fill"
            case .medium: return "exclamationmark.triangle.fill"
            case .high: return "xmark.shield.fill"
            }
        }
    }
}

struct RecommendationCard: View {
    let item: RecommendationItem
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: item.severity.icon)
                .foregroundColor(item.severity.color)
                .font(.title2)
                .frame(width: 32)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(item.title)
                    .font(.system(size: 15, weight: .semibold))
                
                Text(item.description)
                    .font(.system(size: 13))
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text(item.action)
                .font(.system(size: 12, weight: .medium))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(item.severity.color.opacity(0.15))
                .foregroundColor(item.severity.color)
                .clipShape(Capsule())
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
        )
    }
}

// MARK: - DTO Extension

struct RiskSignalDTO {
    let id: String
    let category: String
    let score: Double
    let evidence: [String: String]
}

// MARK: - Preview

#Preview {
    NavigationView {
        DecisionResultsView(dto: mockDTO())
            .environmentObject(SettingsViewModel())
    }
}

private func mockDTO() -> RiskReportDTO {
    RiskReportDTO(
        score: 45,
        isHighRisk: false,
        summary: "检测到 VPN 连接",
        generatedAt: "2024-01-15 10:30:00",
        device: DeviceDTOMock(),
        network: NetworkDTOMock(),
        jailbreak: JailbreakDTOMock(),
        behavior: BehaviorDTOMock(),
        signals: [
            RiskSignalDTO(id: "vpn_active", category: "network", score: 10, evidence: [:]),
            RiskSignalDTO(id: "touch_spread_low", category: "behavior", score: 12, evidence: ["spread": "1.5"])
        ]
    )
}

private struct DeviceDTOMock {
    // Mock data
}

private struct NetworkDTOMock {
    let vpn = (detected: true, method: "test", evidence: ["utun0"] as [String])
    let proxy = (detected: false, method: "test", evidence: nil as [String: String]?)
}

private struct JailbreakDTOMock {
    let isJailbroken = false
    let confidence = 0.0
    let methods = [String]()
}

private struct BehaviorDTOMock {
    // Mock data
}

private struct RiskReportDTO {
    let score: Double
    let isHighRisk: Bool
    let summary: String
    let generatedAt: String
    let device: DeviceDTOMock
    let network: NetworkDTOMock
    let jailbreak: JailbreakDTOMock
    let behavior: BehaviorDTOMock
    let signals: [RiskSignalDTO]
}
