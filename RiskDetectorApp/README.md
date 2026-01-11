<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-orange?style=flat-square" alt="Swift">
  <img src="https://img.shields.io/badge/SwiftUI-✓-green?style=flat-square" alt="SwiftUI">
</p>

# RiskDetectorApp

iOS 设备风险检测应用，用于检测越狱状态、VPN/代理、云手机环境等风险信号。

## 功能特性

- **越狱检测** - 多维度检测：文件探测、dyld 分析、环境变量、系统调用、Hook 检测
- **网络信号** - VPN 隧道检测、系统代理检测
- **云手机识别** - 支持服务端信号接入：机房 IP、IP 聚合度、风险标签
- **行为采集** - 触摸轨迹 + 陀螺仪数据采集
- **安全存储** - AES-GCM 加密存储检测报告
- **美观 UI** - 现代化 SwiftUI 界面，支持信号三态展示

## 页面预览

| Dashboard | Results | History | Settings |
|:---------:|:-------:|:-------:|:--------:|
| 风险仪表盘 | 检测结果 | 历史记录 | 配置管理 |
| 一键检测 | 信号详情 | 加密存储 | 调试开关 |

## 信号分类

### 硬信号（Hard Signals）
本地可独立判定，检测到即可定性：
- 越狱状态

### 软信号（Soft Signals）
仅作为风险参考：
- VPN 检测
- 代理检测
- 云手机信号（需服务端）

### 三态展示
| 状态 | 颜色 | 说明 |
|------|------|------|
| 检测到 | 🔴 红色 | 发现风险信号 |
| 未检测到 | 🟢 绿色 | 正常状态 |
| 不可用 | ⚪ 灰色 | 模拟器环境 |
| 需服务端 | 🟣 紫色 | 等待服务端数据 |

## 快速开始

### 环境要求

- macOS 13.0+
- Xcode 15.0+
- iOS 14.0+

### 方式 1：使用 XcodeGen（推荐）

```bash
# 安装 XcodeGen
brew install xcodegen

# 克隆项目
git clone https://github.com/your-repo/RiskDetectorApp.git
cd RiskDetectorApp

# 生成 Xcode 项目
xcodegen generate

# 打开项目
open RiskDetectorApp.xcodeproj
```

### 方式 2：直接打开

```bash
# 克隆项目
git clone https://github.com/your-repo/RiskDetectorApp.git
cd RiskDetectorApp

# 打开项目
open RiskDetectorApp.xcodeproj
```

### 运行

1. 选择目标设备（推荐真机，模拟器部分检测功能受限）
2. `Cmd + R` 运行

## 项目结构

```
RiskDetectorApp/
├── App/                          # 应用层
│   ├── Views/                    # SwiftUI 视图
│   │   ├── DashboardView.swift   # 主仪表盘
│   │   ├── ResultsView.swift     # 检测结果
│   │   ├── HistoryView.swift     # 历史记录
│   │   ├── SettingsView.swift    # 设置页面
│   │   └── Components/           # 可复用组件
│   └── ViewModels/               # MVVM ViewModel
├── Sources/
│   ├── CloudPhoneRiskKit/        # 核心检测库
│   │   ├── Jailbreak/            # 越狱检测（10+ 检测器）
│   │   ├── Network/              # 网络信号检测
│   │   ├── Behavior/             # 行为数据采集
│   │   └── Util/                 # 工具类（加密等）
│   └── CloudPhoneRiskAppCore/    # 应用核心层
│       ├── RiskDetectionService  # 检测服务
│       └── RiskReportDTO         # 数据传输对象
├── Tests/                        # 单元测试
├── Package.swift                 # SwiftPM 配置
└── project.yml                   # XcodeGen 配置
```

## 核心 API

### 执行检测

```swift
// ViewModel
@MainActor
class DetectionViewModel: ObservableObject {
    @Published var lastDTO: RiskReportDTO?

    func detect(config: RiskAppConfig) {
        // 执行检测并更新 lastDTO
    }
}

// 使用
detectionVM.detect(config: settingsVM.currentConfig())
```

### 检测结果

```swift
public struct RiskReportDTO: Codable {
    var score: Double           // 风险分数 0-100
    var isHighRisk: Bool
    var jailbreak: JailbreakDTO
    var network: NetworkSignals
    var hardSignals: [SignalItemDTO]  // 硬信号
    var softSignals: [SignalItemDTO]  // 软信号
}
```

### 服务端信号注入

```swift
// 注入服务端数据（用于云手机检测等）
RiskDetectionService.shared.setExternalServerSignals(
    publicIP: "203.0.113.10",
    asn: "AS64500",
    asOrg: "Cloud-DC",
    isDatacenter: true,
    ipDeviceAgg: 260,
    ipAccountAgg: 800,
    riskTags: ["cloud_phone"]
)
```

## 配置选项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `enableBehaviorDetect` | `true` | 行为数据采集 |
| `enableNetworkSignals` | `true` | 网络信号检测 |
| `threshold` | `60` | 风险阈值 |
| `storeEncryptionEnabled` | `true` | 加密存储 |
| `debugShowDetailedSignals` | `false` | 显示检测详情 |

## 越狱检测器

| 检测器 | 检测目标 |
|--------|----------|
| FileDetector | Cydia.app、MobileSubstrate 等文件 |
| DyldDetector | 加载的越狱动态库 |
| EnvDetector | DYLD_INSERT_LIBRARIES 等环境变量 |
| SysctlDetector | 进程信息、调试状态 |
| SchemeDetector | cydia://、sileo:// 等 URL Scheme |
| HookDetector | 关键函数 Hook 检测 |
| ObjCIMPDetector | ObjC 方法实现地址验证 |
| PrologueBranchDetector | 函数入口跳转指令检测 |

## 技术栈

- **语言**: Swift 5.9+
- **UI**: SwiftUI
- **架构**: MVVM
- **加密**: CryptoKit (AES-GCM)
- **存储**: Keychain + FileManager
- **包管理**: Swift Package Manager

## 测试

```bash
# 运行单元测试
swift test

# 或在 Xcode 中
Cmd + U
```

## 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 许可证

未指定（内部项目）。

## 免责声明

本项目仅供学习和研究目的。请遵守当地法律法规，不要将本工具用于任何非法用途。

---

<p align="center">
  Made with ❤️ for iOS Security Research
</p>
