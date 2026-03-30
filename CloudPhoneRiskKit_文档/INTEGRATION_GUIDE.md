# CloudPhoneRiskKit 集成指南

> 本文档覆盖 Swift Package Manager、CocoaPods、Carthage 与手动 XCFramework 四种集成方式。

---

## 目录

1. [环境要求](#环境要求)
2. [Swift Package Manager（推荐）](#swift-package-manager推荐)
3. [CocoaPods](#cocoapods)
4. [Carthage](#carthage)
5. [手动 XCFramework](#手动-xcframework)
6. [初始化与基本使用](#初始化与基本使用)
7. [Objective-C 项目集成](#objective-c-项目集成)
8. [隐私清单 (Privacy Manifest)](#隐私清单-privacy-manifest)
9. [常见问题](#常见问题)

---

## 环境要求

| 项目 | 最低要求 |
|------|---------|
| iOS | 14.0+ |
| Xcode | 15.0+ |
| Swift | 5.9+ |
| macOS (开发机) | 14.0+ (Sonoma) |

---

## Swift Package Manager（推荐）

### 方式 A：Git 仓库依赖

在项目的 `Package.swift` 中添加：

```swift
dependencies: [
    .package(
        url: "https://github.com/anthropic/cloudphone-risk-detector.git",
        from: "7.3.0"
    ),
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "CloudPhoneRiskKit", package: "cloudphone-risk-detector"),
        ]
    ),
]
```

或在 Xcode 中：**File → Add Package Dependencies → 输入仓库 URL → 选择版本 → 添加 CloudPhoneRiskKit**。

### 方式 B：Binary Target（预编译 XCFramework）

适用于不想暴露源码的场景：

```swift
dependencies: [],
targets: [
    .binaryTarget(
        name: "CloudPhoneRiskKit",
        url: "https://releases.example.com/CloudPhoneRiskKit-7.3.0.xcframework.zip",
        checksum: "<SHA-256-CHECKSUM>"
    ),
    .target(
        name: "YourApp",
        dependencies: ["CloudPhoneRiskKit"]
    ),
]
```

### 方式 C：本地路径（开发调试）

```swift
dependencies: [
    .package(path: "../cloudphone-risk-detector/RiskDetectorApp"),
],
```

---

## CocoaPods

### 1. 安装 CocoaPods

```bash
gem install cocoapods
# 或 brew install cocoapods
```

### 2. 在 Podfile 中添加依赖

```ruby
platform :ios, '14.0'
use_frameworks! :linkage => :static

target 'YourApp' do
  # 完整版（含 CRiskCore C 层加固，推荐）
  pod 'CloudPhoneRiskKit', '~> 7.3'

  # 或仅核心 Swift 层（不含 C 层加固）
  # pod 'CloudPhoneRiskKit/Core', '~> 7.3'
end
```

### 3. 安装

```bash
pod install
open YourApp.xcworkspace
```

### Subspecs 说明

| Subspec | 内容 | 适用场景 |
|---------|------|---------|
| `Core` | Swift 层全部检测逻辑 | 仅需基础风控，不需要壳保护 |
| `Full`（默认） | Core + CRiskCore C 自保护层 | 生产环境推荐 |

---

## Carthage

> Carthage 支持需配合 XCFramework 分发。

### 1. 在 Cartfile 中添加

```
github "anthropic/cloudphone-risk-detector" ~> 7.3
```

### 2. 构建 XCFramework

```bash
carthage update --use-xcframeworks --platform iOS
```

### 3. 集成

1. 将 `Carthage/Build/CloudPhoneRiskKit.xcframework` 拖入 Xcode 项目
2. 在 **General → Frameworks, Libraries, and Embedded Content** 中设置为 **Do Not Embed**（static library）或 **Embed & Sign**（dynamic framework）

---

## 手动 XCFramework

### 1. 获取 XCFramework

从 [GitHub Releases](https://github.com/anthropic/cloudphone-risk-detector/releases) 下载 `CloudPhoneRiskKit.xcframework.zip`。

### 2. 验证完整性

```bash
shasum -a 256 CloudPhoneRiskKit.xcframework.zip
# 对比 CHECKSUM.txt 中的值
unzip CloudPhoneRiskKit.xcframework.zip
```

### 3. 添加到 Xcode 项目

1. 将 `CloudPhoneRiskKit.xcframework` 拖入 Xcode 项目导航器
2. 确保在 **Target → General → Frameworks, Libraries, and Embedded Content** 中可见
3. 对于 static framework：设置为 **Do Not Embed**
4. 对于 dynamic framework：设置为 **Embed & Sign**

### 4. 配置 Header Search Paths（如需 CRiskCore）

如果手动集成包含 CRiskCore 的版本：

```
$(PROJECT_DIR)/Vendor/CloudPhoneRiskKit.xcframework/*/CloudPhoneRiskKit.framework/Headers
```

---

## 初始化与基本使用

### Swift

```swift
import CloudPhoneRiskKit

// 1. 启动 SDK（建议在 AppDelegate / @main 中尽早调用）
CPRiskKit.shared.start()

// 2. 执行风险评估
let report = CPRiskKit.shared.evaluate()

// 3. 读取结果
print("Risk Score: \(report.score)")
print("Is High Risk: \(report.isHighRisk)")
print("Summary: \(report.summary)")

// 4. 带场景的评估
let paymentReport = CPRiskKit.shared.evaluate(
    config: .default,
    scenario: .payment
)

// 5. 异步评估
CPRiskKit.shared.evaluateAsync { report in
    print("Async result: \(report.score)")
}

// 6. async/await（iOS 13+）
Task {
    let report = await CPRiskKit.shared.evaluateAsync()
    print("Await result: \(report.score)")
}

// 7. 停止
CPRiskKit.shared.stop()
```

### 自定义配置

```swift
let config = CPRiskConfig()
config.enableBehaviorDetect = true
config.enableNetworkSignals = true
config.threshold = 60.0
config.enableAntiTamper = true
config.antiDebugRuntimeMode = .production

CPRiskKit.shared.start(config: config)
```

### 账号绑定（用于图风控联动）

```swift
CPRiskKit.shared.bindAccount("user_12345", scene: "payment")

// 用户登出时解绑
CPRiskKit.shared.unbindAccount()
```

### 获取加密报告（生产推荐）

```swift
let report = CPRiskKit.shared.evaluate()
do {
    let encryptedData = try report.securePayload()
    // 发送 encryptedData 到服务端
} catch {
    print("加密失败: \(error)")
}
```

---

## Objective-C 项目集成

SDK 提供了完整的 `@objc` 桥接层，Objective-C 项目可直接使用：

```objc
@import CloudPhoneRiskKit;
// 或 #import <CloudPhoneRiskKit/CloudPhoneRiskKit-Swift.h>

// 启动
[[CPR_RiskKit shared] start];

// 评估
CPR_RiskReport *report = [[CPR_RiskKit shared] evaluate];
NSLog(@"Score: %f, High Risk: %d", report.score, report.isHighRisk);

// 使用 ObjC 桥接类（如已集成 CPRiskKitObjCBridge）
CPRiskKitObjCBridge *bridge = [[CPRiskKitObjCBridge alloc] init];
[bridge evaluateWithCompletion:^(CPR_RiskReport *report) {
    NSLog(@"Async Score: %f", report.score);
}];
```

---

## 隐私清单 (Privacy Manifest)

SDK 内置 `PrivacyInfo.xcprivacy`，声明了以下 Required Reason API 用途：

| API 类别 | 用途说明 |
|---------|---------|
| `NSPrivacyAccessedAPICategorySystemBootTime` | 系统启动时间用于时序分析 |
| `NSPrivacyAccessedAPICategoryDiskSpace` | 磁盘容量用于设备指纹 |
| `NSPrivacyAccessedAPICategoryUserDefaults` | 用于配置缓存降级 |

**SDK 不采集任何用户内容数据**，不要求网络权限（网络信号为可选）。

---

## 常见问题

### Q: 编译报 "Missing required module 'CRiskCore'"

**解决**：确保使用 `Full` subspec（CocoaPods）或包含 CRiskCore target 的 SPM 配置。如仅使用 `Core` subspec，需去除代码中对 CRiskCore 的直接引用。

### Q: App Store 审核被拒（private API）

**解决**：
1. 使用 `appStoreSafe` 模式：`config.antiDebugRuntimeMode = .appStoreSafe`
2. 确保 Privacy Manifest 中声明了所有 Required Reason API

### Q: 模拟器上检测结果不准确

**说明**：模拟器不具备完整的硬件特征（传感器、DRM、Secure Enclave），部分检测器会返回 `unavailable` 或降级结果。这是预期行为，请以真机测试为准。

### Q: CocoaPods 安装后 Header 找不到

**解决**：
```bash
pod deintegrate
pod install
```
确保 `HEADER_SEARCH_PATHS` 包含 CRiskCore 的 include 目录。

### Q: SPM 编译时间过长

**解决**：CRiskCore 包含大量 C 文件，首次编译可能较慢。后续增量编译会显著加快。可考虑使用 Binary Target 方式跳过源码编译。
