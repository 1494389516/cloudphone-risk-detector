import SwiftUI

/// 风险分数仪表盘 - 美化版
struct RiskGaugeView: View {
    let score: Double
    let riskLevel: RiskLevel
    var size: CGFloat = 200

    @State private var animatedScore: Double = 0
    @State private var showGlow = false

    private var progress: Double {
        animatedScore / 100.0
    }

    private var gradientColors: [Color] {
        switch riskLevel {
        case .low:
            return [Color(hex: "4ADE80"), Color(hex: "22C55E")]
        case .medium:
            return [Color(hex: "FBBF24"), Color(hex: "F59E0B")]
        case .high:
            return [Color(hex: "F87171"), Color(hex: "EF4444")]
        }
    }

    private var glowColor: Color {
        switch riskLevel {
        case .low: return .green
        case .medium: return .orange
        case .high: return .red
        }
    }

    var body: some View {
        ZStack {
            // 最外层发光
            Circle()
                .fill(glowColor.opacity(showGlow ? 0.15 : 0.05))
                .frame(width: size + 40, height: size + 40)
                .blur(radius: 20)

            // 外圈刻度装饰
            ForEach(0..<36) { index in
                Rectangle()
                    .fill(index % 3 == 0 ? Color.gray.opacity(0.3) : Color.gray.opacity(0.15))
                    .frame(width: index % 3 == 0 ? 2 : 1, height: index % 3 == 0 ? 10 : 6)
                    .offset(y: -size / 2 - 8)
                    .rotationEffect(.degrees(Double(index) * 10))
            }

            // 背景圆环（带内阴影效果）
            Circle()
                .stroke(
                    LinearGradient(
                        colors: [Color.gray.opacity(0.15), Color.gray.opacity(0.08)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: size * 0.1
                )
                .frame(width: size, height: size)

            // 内部暗圈（增加深度感）
            Circle()
                .stroke(Color.black.opacity(0.03), lineWidth: size * 0.08)
                .frame(width: size - 4, height: size - 4)

            // 进度圆环
            Circle()
                .trim(from: 0, to: progress)
                .stroke(
                    AngularGradient(
                        gradient: Gradient(colors: gradientColors + [gradientColors[0].opacity(0.8)]),
                        center: .center,
                        startAngle: .degrees(-90),
                        endAngle: .degrees(270)
                    ),
                    style: StrokeStyle(lineWidth: size * 0.1, lineCap: .round)
                )
                .frame(width: size, height: size)
                .rotationEffect(.degrees(-90))
                .shadow(color: glowColor.opacity(0.5), radius: 8, x: 0, y: 0)

            // 进度端点发光球
            Circle()
                .fill(gradientColors[1])
                .frame(width: size * 0.12, height: size * 0.12)
                .shadow(color: glowColor.opacity(0.8), radius: 6, x: 0, y: 0)
                .offset(y: -size / 2)
                .rotationEffect(.degrees(360 * progress - 90))
                .opacity(progress > 0.01 ? 1 : 0)

            // 内圈装饰
            Circle()
                .stroke(
                    LinearGradient(
                        colors: [Color.white.opacity(0.1), Color.clear],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 1
                )
                .frame(width: size * 0.7, height: size * 0.7)

            // 中心内容
            VStack(spacing: 2) {
                // 分数
                Text("\(Int(animatedScore))")
                    .font(.system(size: size * 0.28, weight: .bold, design: .rounded))
                    .foregroundColor(glowColor)
                    .shadow(color: glowColor.opacity(0.3), radius: 4, x: 0, y: 2)

                // 风险等级
                Text(riskLevel.rawValue)
                    .font(.system(size: size * 0.07, weight: .semibold, design: .rounded))
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
                    .background(
                        Capsule()
                            .fill(glowColor.opacity(0.1))
                    )

                // 图标
                Image(systemName: riskLevel.icon)
                    .font(.system(size: size * 0.1))
                    .foregroundColor(glowColor)
                    .padding(.top, 4)
            }
        }
        .frame(width: size + 60, height: size + 60)
        .onAppear {
            // 启动分数动画
            withAnimation(.easeOut(duration: 1.2)) {
                animatedScore = score
            }
            // 发光动画
            withAnimation(.easeInOut(duration: 2).repeatForever(autoreverses: true)) {
                showGlow = true
            }
        }
        .onChange(of: score) { newValue in
            withAnimation(.easeOut(duration: 0.8)) {
                animatedScore = newValue
            }
        }
    }
}

// MARK: - Color Extension for Hex
extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

#Preview {
    VStack(spacing: 40) {
        RiskGaugeView(score: 25, riskLevel: .low)
        RiskGaugeView(score: 55, riskLevel: .medium, size: 160)
        RiskGaugeView(score: 85, riskLevel: .high, size: 140)
    }
    .padding()
    .background(Color(.systemGroupedBackground))
}
