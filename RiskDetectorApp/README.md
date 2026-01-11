# RiskDetectorApp

iOS 设备风险检测 App，基于 CloudPhoneRiskKit 框架。

## 功能

- **Dashboard（首页）**：一键检测、风险分数仪表盘展示
- **Results（结果页）**：详细检测结果、JSON 原文展示、分享/保存
- **History（历史页）**：本地检测记录管理、解密查看
- **Settings（设置页）**：检测配置、阈值调节、存储设置

## 项目结构

```
RiskDetectorApp/
├── App/
│   ├── RiskDetectorAppApp.swift    # App 入口
│   ├── ContentView.swift           # TabView 容器
│   ├── Views/
│   │   ├── DashboardView.swift     # 首页
│   │   ├── ResultsView.swift       # 结果页
│   │   ├── HistoryView.swift       # 历史页
│   │   ├── SettingsView.swift      # 设置页
│   │   └── Components/
│   │       ├── RiskGaugeView.swift # 风险仪表盘
│   │       ├── SignalRowView.swift # 信号行组件
│   │       └── JSONTextView.swift  # JSON 展示组件
│   ├── ViewModels/
│   │   ├── DetectionViewModel.swift
│   │   ├── HistoryViewModel.swift
│   │   └── SettingsViewModel.swift
│   ├── Resources/
│   │   └── Assets.xcassets
│   └── Info.plist
├── project.yml                      # XcodeGen 配置
├── Package.swift                    # SwiftPM（CloudPhoneRiskKit + CloudPhoneRiskAppCore）
└── Sources/                         # SDK 源码（两套库都在这）
```

## 接入步骤

### 方式 1：使用 XcodeGen（推荐）

1. 安装 XcodeGen：
   ```bash
   brew install xcodegen
   ```

2. 生成 Xcode 项目：
   ```bash
   cd "/Users/mac/Desktop/云手机检测和越野插件的开发/RiskDetectorApp"
   xcodegen generate
   ```

3. 打开生成的 `RiskDetectorApp.xcodeproj`

### 方式 2：手动创建 Xcode 项目

1. 在 Xcode 中新建 iOS App 项目
2. 将 `RiskDetectorApp/` 目录下的文件拖入项目
3. 添加本地依赖：
   - File → Add Package Dependencies → Add Local...
   - 选择 `RiskDetectorApp` 目录（当前目录，包含 `Package.swift`）
   - 添加 `CloudPhoneRiskKit` 和 `CloudPhoneRiskAppCore` 两个产品

## 依赖

- CloudPhoneRiskKit（越狱检测 + 行为采集）
- CloudPhoneRiskAppCore（App 后端逻辑层）

## 信号分级说明

| 类型 | 展示方式 | 说明 |
|-----|---------|-----|
| 越狱 | ✓/✗ 硬判定 | 本地可做强结论 |
| VPN/代理 | 🔵有信号/⚪无信号 | 仅作为弱信号参考 |
| 行为异常 | 🔵有信号/⚪无信号 | 需结合服务端判定 |

## 配置说明

在 Settings 页面可配置：

- **检测开关**：行为采集、网络信号
- **越狱检测**：文件/dyld/环境变量/系统调用/Scheme/Hook
- **阈值设置**：风险阈值（20-80）、越狱阈值（20-80）
- **存储设置**：加密开关、最大文件数
- **调试**：日志输出开关

## 技术栈

- SwiftUI
- iOS 14+
- MVVM 架构
- AES-GCM 加密存储
