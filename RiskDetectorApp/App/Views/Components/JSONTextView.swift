import SwiftUI

/// JSON 文本展示视图（美化版）
struct JSONTextView: View {
    let jsonString: String
    @State private var isExpanded: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 标题栏
            Button {
                withAnimation(.spring(response: 0.3, dampingFraction: 0.7)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 12) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.purple.opacity(0.1))
                            .frame(width: 36, height: 36)

                        Image(systemName: "curlybraces")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(.purple)
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text("原始 JSON")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundColor(.primary)

                        Text("\(jsonString.count) 字符")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    // 展开/折叠指示
                    HStack(spacing: 4) {
                        Text(isExpanded ? "收起" : "展开")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.purple)

                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(.purple)
                            .rotationEffect(.degrees(isExpanded ? 90 : 0))
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(
                        Capsule()
                            .fill(Color.purple.opacity(0.1))
                    )
                }
                .padding(16)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            // JSON 内容
            if isExpanded {
                VStack(alignment: .leading, spacing: 0) {
                    // 工具栏
                    HStack(spacing: 16) {
                        // 行数统计
                        HStack(spacing: 4) {
                            Image(systemName: "text.alignleft")
                                .font(.system(size: 10))
                            Text("\(jsonString.components(separatedBy: "\n").count) 行")
                                .font(.system(size: 11))
                        }
                        .foregroundColor(.secondary)

                        Spacer()

                        // 复制按钮（小）
                        Button {
                            UIPasteboard.general.string = jsonString
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: "doc.on.doc")
                                    .font(.system(size: 10))
                                Text("复制")
                                    .font(.system(size: 11, weight: .medium))
                            }
                            .foregroundColor(.purple)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(
                                Capsule()
                                    .stroke(Color.purple.opacity(0.3), lineWidth: 1)
                            )
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(Color(.tertiarySystemBackground))

                    // JSON 代码区域
                    ScrollView([.horizontal, .vertical], showsIndicators: true) {
                        Text(jsonString)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.primary)
                            .padding(16)
                            .modifier(TextSelectionIfAvailable())
                    }
                    .frame(maxHeight: 320)
                    .background(
                        // 代码编辑器风格背景
                        ZStack {
                            Color(.secondarySystemBackground)

                            // 行号区域装饰
                            HStack {
                                Rectangle()
                                    .fill(Color.gray.opacity(0.1))
                                    .frame(width: 2)
                                Spacer()
                            }
                        }
                    )
                }
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.gray.opacity(0.1), lineWidth: 1)
                )
                .padding(.horizontal, 16)
                .padding(.bottom, 16)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.systemBackground))
                .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 2)
        )
        .padding(.horizontal, 16)
    }
}

private struct TextSelectionIfAvailable: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 15.0, *) {
            content.textSelection(.enabled)
        } else {
            content
        }
    }
}

/// 操作按钮栏（美化版）
struct ActionButtonBar: View {
    let onSave: () -> Void
    let onShare: () -> Void
    let onCopy: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            ActionButton(
                title: "保存",
                icon: "square.and.arrow.down",
                color: .green,
                action: onSave
            )

            ActionButton(
                title: "分享",
                icon: "square.and.arrow.up",
                color: .blue,
                isPrimary: true,
                action: onShare
            )

            ActionButton(
                title: "复制",
                icon: "doc.on.doc",
                color: .gray,
                action: onCopy
            )
        }
        .padding(.horizontal, 16)
    }
}

struct ActionButton: View {
    let title: String
    let icon: String
    let color: Color
    var isPrimary: Bool = false
    let action: () -> Void

    @State private var isPressed = false

    var body: some View {
        Button(action: {
            action()
        }) {
            VStack(spacing: 6) {
                ZStack {
                    Circle()
                        .fill(isPrimary ? color : color.opacity(0.1))
                        .frame(width: 44, height: 44)

                    Image(systemName: icon)
                        .font(.system(size: 18, weight: .medium))
                        .foregroundColor(isPrimary ? .white : color)
                }

                Text(title)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(isPrimary ? color : .secondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(Color(.systemBackground))
                    .shadow(color: isPrimary ? color.opacity(0.2) : Color.black.opacity(0.04), radius: 8, x: 0, y: 2)
            )
        }
        .buttonStyle(.plain)
        .scaleEffect(isPressed ? 0.96 : 1.0)
        .animation(.spring(response: 0.2, dampingFraction: 0.7), value: isPressed)
    }
}

#Preview {
    ScrollView {
        VStack(spacing: 20) {
            JSONTextView(jsonString: """
            {
              "score": 85,
              "isHighRisk": true,
              "jailbreak": {
                "isJailbroken": true,
                "confidence": 85,
                "detectedMethods": [
                  "file:/Applications/Cydia.app",
                  "dylib:MobileSubstrate"
                ]
              },
              "network": {
                "interfaceType": "wifi",
                "vpn": true,
                "proxy": false
              }
            }
            """)

            ActionButtonBar(
                onSave: { print("Save") },
                onShare: { print("Share") },
                onCopy: { print("Copy") }
            )
        }
        .padding(.vertical, 20)
    }
    .background(Color(.systemGroupedBackground))
}
