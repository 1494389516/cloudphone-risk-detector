import SwiftUI
import Charts

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

/// 时序分析展示视图
/// 
/// 功能：
/// 1. 显示历史风险趋势
/// 2. 展示时序特征
/// 3. 检测异常模式
/// 4. 可视化时间分布
struct TemporalAnalysisView: View {
    @EnvironmentObject var detectionVM: DetectionViewModel
    @State private var selectedTimeRange: TimeRange = .day
    @State private var showAnomaliesOnly = false
    
    // 模拟数据（实际应从 RiskHistoryStore 获取）
    @State private var historyData: [HistoryPoint] = []
    @State private var timePattern: TimePatternData?
    
    enum TimeRange: String, CaseIterable {
        case day = "24小时"
        case week = "7天"
        case month = "30天"
        
        var hours: Int {
            switch self {
            case .day: return 24
            case .week: return 24 * 7
            case .month: return 24 * 30
            }
        }
    }
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // 时间范围选择器
                timeRangePicker
                
                // 时序模式卡片
                if let pattern = timePattern {
                    timePatternCard(pattern: pattern)
                }
                
                // 趋势图表
                trendChart
                
                // 异常检测
                anomalyDetectionSection
                
                // 活动分布
                activityDistributionSection
            }
            .padding(.horizontal, 16)
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle("时序分析")
        .navigationBarTitleDisplayMode(.large)
        .onAppear {
            loadTimePattern()
            loadHistoryData()
        }
    }
    
    // MARK: - 时间范围选择器
    
    private var timeRangePicker: some View {
        Picker("时间范围", selection: $selectedTimeRange) {
            ForEach(TimeRange.allCases, id: \.self) { range in
                Text(range.rawValue).tag(range)
            }
        }
        .pickerStyle(.segmented)
        .onChange(of: selectedTimeRange) { _ in
            loadHistoryData()
        }
    }
    
    // MARK: - 时序模式卡片
    
    private func timePatternCard(pattern: TimePatternData) -> some View {
        VStack(spacing: 16) {
            HStack {
                Text("时序特征")
                    .font(.system(size: 18, weight: .bold))
                Spacer()
                Button {
                    showAnomaliesOnly.toggle()
                } label: {
                    Text(showAnomaliesOnly ? "显示全部" : "仅显示异常")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.blue)
                }
            }
            
            HStack(spacing: 12) {
                PatternMetric(
                    title: "事件��",
                    value: "\(pattern.events24h)",
                    subtitle: "24小时内",
                    color: .blue
                )
                
                PatternMetric(
                    title: "活跃小时",
                    value: "\(pattern.uniqueHours24h)",
                    subtitle: "不同时段",
                    color: .purple
                )
                
                PatternMetric(
                    title: "夜间比例",
                    value: String(format: "%.0f%%", (pattern.nightRatio24h ?? 0) * 100),
                    subtitle: "0-5点活动",
                    color: .indigo
                )
            }
            
            if let avgInterval = pattern.averageIntervalSeconds24h {
                VStack(alignment: .leading, spacing: 4) {
                    Text("平均间隔")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                    
                    HStack {
                        Text("\(Int(avgInterval))秒")
                            .font(.system(size: 20, weight: .semibold))
                        
                        Text(intervalDescription(avgInterval))
                            .font(.system(size: 13))
                            .foregroundColor(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(.systemGray6))
                .clipShape(RoundedRectangle(cornerRadius: 10))
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.05), radius: 10, x: 0, y: 4)
        )
    }
    
    // MARK: - 趋势图表
    
    private var trendChart: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("风险趋势")
                .font(.system(size: 18, weight: .bold))
            
            if #available(iOS 16.0, *) {
                Chart(historyData) { point in
                    LineMark(
                        x: .value("时间", point.date),
                        y: .value("评分", point.score)
                    )
                    .foregroundStyle(point.isHighRisk ? Color.red : Color.blue)
                    .interpolationMethod(.catmullRom)
                    
                    if point.isAnomaly {
                        PointMark(
                            x: .value("时间", point.date),
                            y: .value("评分", point.score)
                        )
                        .annotation(position: .top) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                                .font(.caption)
                        }
                    }
                }
                .frame(height: 200)
                .chartYAxis {
                    AxisMarks(position: .leading)
                }
                .chartXAxis {
                    AxisMarks(position: .bottom, values: .automatic(desiredCount: 6)) { _ in
                        AxisValueLabel(format: .dateTime.hour().minute())
                    }
                }
            } else {
                // iOS 15 降级方案
                fallbackChart
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
        )
    }
    
    private var fallbackChart: some View {
        VStack(spacing: 8) {
            ForEach(historyData) { point in
                HStack {
                    Text(point.date, style: .time)
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .frame(width: 60, alignment: .leading)
                    
                    GeometryReader { geometry in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 4)
                                .fill(Color.gray.opacity(0.1))
                            
                            RoundedRectangle(cornerRadius: 4)
                                .fill(point.isHighRisk ? Color.red : Color.blue)
                                .frame(width: geometry.size.width * CGFloat(point.score / 100))
                        }
                    }
                    .frame(height: 20)
                    
                    Text("\(Int(point.score))")
                        .font(.caption)
                        .frame(width: 30, alignment: .trailing)
                }
            }
        }
        .frame(height: 200)
    }
    
    // MARK: - 异常检测
    
    private var anomalyDetectionSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("异常检测")
                .font(.system(size: 18, weight: .bold))
            
            let anomalies = historyData.filter { $0.isAnomaly }
            
            if anomalies.isEmpty {
                emptyStateView(
                    icon: "checkmark.shield.fill",
                    title: "未检测到异常",
                    description: "历史数据在正常范围内"
                )
            } else {
                VStack(spacing: 8) {
                    ForEach(anomalies.prefix(5)) { anomaly in
                        AnomalyRow(anomaly: anomaly)
                    }
                    
                    if anomalies.count > 5 {
                        Text("还有 \(anomalies.count - 5) 个异常...")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
        )
    }
    
    // MARK: - 活动分布
    
    private var activityDistributionSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("活动分布")
                .font(.system(size: 18, weight: .bold))
            
            if #available(iOS 16.0, *) {
                Chart(historyData) { point in
                    BarMark(
                        x: .value("小时", point.hour),
                        y: .value("次数", point.activityCount)
                    )
                    .foregroundStyle(Color.blue.gradient)
                }
                .frame(height: 150)
                .chartXAxis {
                    AxisMarks(position: .bottom, values: .automatic(desiredCount: 12)) { _ in
                        AxisValueLabel()
                    }
                }
            } else {
                // 简单的柱状图表示
                hourlyDistribution
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
        )
    }
    
    private var hourlyDistribution: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(0..<24) { hour in
                let count = historyData.filter { $0.hour == hour }.reduce(0) { $0 + $1.activityCount }
                let maxCount = historyData.map(\.activityCount).max() ?? 1
                let height = maxCount > 0 ? CGFloat(count) / CGFloat(maxCount) : 0
                
                VStack {
                    Rectangle()
                        .fill(count > 0 ? Color.blue : Color.clear)
                        .frame(height: height * 80)
                    
                    Text("\(hour)")
                        .font(.system(size: 8))
                        .foregroundColor(.secondary)
                }
            }
        }
        .frame(height: 120)
    }
    
    // MARK: - 辅助视图
    
    private func emptyStateView(icon: String, title: String, description: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 40))
                .foregroundColor(.green)
            
            Text(title)
                .font(.system(size: 16, weight: .semibold))
            
            Text(description)
                .font(.system(size: 14))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
    }
    
    // MARK: - 数据加载
    
    private func loadTimePattern() {
        #if canImport(CloudPhoneRiskAppCore)
        let pattern = RiskHistoryStore.shared.pattern()
        timePattern = TimePatternData(
            events24h: pattern.events24h,
            uniqueHours24h: pattern.uniqueHours24h,
            nightRatio24h: pattern.nightRatio24h,
            averageIntervalSeconds24h: pattern.averageIntervalSeconds24h
        )
        #else
        // 模拟数据
        timePattern = TimePatternData(
            events24h: 24,
            uniqueHours24h: 12,
            nightRatio24h: 0.15,
            averageIntervalSeconds24h: 3600
        )
        #endif
    }
    
    private func loadHistoryData() {
        // 模拟历史数据
        let now = Date()
        var data: [HistoryPoint] = []
        
        for i in 0..<24 {
            let date = now.addingTimeInterval(-Double(i * 3600))
            let baseScore = Double.random(in: 10...40)
            let isHighRisk = baseScore > 35
            let isAnomaly = baseScore > 50 || (i > 0 && abs(data.last?.score ?? 0 - baseScore) > 30)
            
            data.append(HistoryPoint(
                date: date,
                score: isAnomaly ? min(baseScore + 20, 80) : baseScore,
                isHighRisk: isHighRisk || isAnomaly,
                isAnomaly: isAnomaly,
                hour: Calendar.current.component(.hour, from: date),
                activityCount: Int.random(in: 1...5)
            ))
        }
        
        historyData = data.reversed()
    }
    
    private func intervalDescription(_ seconds: Double) -> String {
        if seconds < 60 { return "非常频繁" }
        if seconds < 300 { return "频繁" }
        if seconds < 3600 { return "正常" }
        if seconds < 86400 { return "稀疏" }
        return "很少"
    }
}

// MARK: - 数据模型

struct HistoryPoint: Identifiable {
    let id = UUID()
    let date: Date
    let score: Double
    let isHighRisk: Bool
    let isAnomaly: Bool
    let hour: Int
    let activityCount: Int
}

struct TimePatternData {
    let events24h: Int
    let uniqueHours24h: Int
    let nightRatio24h: Double?
    let averageIntervalSeconds24h: Double?
}

// MARK: - 子视图

struct PatternMetric: View {
    let title: String
    let value: String
    let subtitle: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 6) {
            Text(value)
                .font(.system(size: 24, weight: .bold, design: .rounded))
                .foregroundColor(color)
            
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.secondary)
            
            Text(subtitle)
                .font(.system(size: 10))
                .foregroundColor(.secondary.opacity(0.7))
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(color.opacity(0.1))
        )
    }
}

struct AnomalyRow: View {
    let anomaly: HistoryPoint
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.orange)
                .font(.title3)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(anomaly.date, style: .time)
                    .font(.system(size: 14, weight: .medium))
                
                Text("评分: \(Int(anomaly.score))")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
            }
            
            Spacer()
            
            Text("异常")
                .font(.system(size: 11, weight: .medium))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color.orange.opacity(0.15))
                .foregroundColor(.orange)
                .clipShape(Capsule())
        }
        .padding(12)
        .background(Color(.systemGray6))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

// MARK: - Preview

#Preview {
    NavigationView {
        TemporalAnalysisView()
            .environmentObject(DetectionViewModel())
    }
}
