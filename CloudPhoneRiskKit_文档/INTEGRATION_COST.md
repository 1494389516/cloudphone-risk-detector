# CloudPhoneRiskKit 集成成本评估

> 本文档帮助接入方评估集成 CloudPhoneRiskKit 所需的工时、资源与验证步骤。

---

## 目录

1. [集成路径总览](#集成路径总览)
2. [Quick Path — 快速集成 (< 2h)](#quick-path--快速集成--2h)
3. [Standard Path — 标准集成 (< 4h)](#standard-path--标准集成--4h)
4. [Advanced Path — 深度集成 (< 8h)](#advanced-path--深度集成--8h)
5. [环境要求](#环境要求)
6. [常见问题与排查](#常见问题与排查)
7. [测试验证清单](#测试验证清单)

---

## 集成路径总览

| 路径 | 预估工时 | 适用场景 | 产出 |
|------|---------|---------|------|
| **Quick** | < 2 小时 | 快速验证 / PoC / 单场景接入 | 基础风险评估能力 |
| **Standard** | < 4 小时 | 生产环境标准接入 | 多场景评估 + 加密上报 + 远程配置 |
| **Advanced** | < 8 小时 | 深度定制 / 多租户 / 图风控联动 | 全功能 + 自定义策略 + 服务端闭环 |

```
Quick (PoC)          Standard (生产)           Advanced (深度)
─────────────       ─────────────────        ──────────────────
SPM 添加依赖         + CocoaPods/手动集成       + 多租户 Key 管理
start() + evaluate() + 自定义 Config            + 图风控反馈接入
读取 score           + 加密上报                  + 自定义检测策略
                     + 远程配置对接              + 服务端签名验证
                     + 账号绑定                  + Kill Switch 配置
                     + Privacy Manifest 审核     + 性能调优
```

---

## Quick Path — 快速集成 (< 2h)

适用于 PoC 验证、技术评估或仅需单场景基础检测的项目。

### 步骤清单

| # | 步骤 | 预估时间 | 完成标志 |
|---|------|---------|---------|
| 1 | 添加 SPM 依赖 | 10 分钟 | `import CloudPhoneRiskKit` 编译通过 |
| 2 | 在 AppDelegate 中调用 `start()` | 5 分钟 | App 启动无崩溃 |
| 3 | 在业务入口调用 `evaluate()` | 15 分钟 | 获取到 `CPRiskReport` |
| 4 | 读取 score 并做基本决策 | 15 分钟 | `if report.score > 60 { ... }` |
| 5 | 真机验证 | 30 分钟 | 正常设备 score < 30 |
| 6 | 模拟器对比验证 | 15 分钟 | 理解模拟器与真机差异 |

### 代码示例

```swift
// AppDelegate.swift
import CloudPhoneRiskKit

func application(_ application: UIApplication,
                 didFinishLaunchingWithOptions ...) -> Bool {
    CPRiskKit.shared.start()
    return true
}

// 业务代码
let report = CPRiskKit.shared.evaluate()
if report.isHighRisk {
    // 拦截或弹验证
}
```

### Quick Path 交付物

- [x] SDK 依赖集成完成
- [x] 基础 evaluate 调用可用
- [x] 真机上 score 输出合理

---

## Standard Path — 标准集成 (< 4h)

适用于生产环境部署，包含完整的配置、加密上报与账号绑定。

### 步骤清单

| # | 步骤 | 预估时间 | 完成标志 |
|---|------|---------|---------|
| 1 | 依赖集成（SPM / CocoaPods / 手动） | 20 分钟 | 编译通过 |
| 2 | 配置 `CPRiskConfig` | 15 分钟 | 自定义阈值/开关生效 |
| 3 | 在 AppDelegate 中 `start(config:)` | 5 分钟 | 启动无崩溃 |
| 4 | 多场景 evaluate 接入 | 30 分钟 | login/payment/register 场景验证 |
| 5 | 加密上报对接 (`securePayload()`) | 30 分钟 | 服务端能解密 payload |
| 6 | 账号绑定 (`bindAccount`) | 10 分钟 | 报告中包含 accountId |
| 7 | 远程配置端点对接 | 20 分钟 | SDK 能拉取远程配置 |
| 8 | Privacy Manifest 审核 | 15 分钟 | PrivacyInfo.xcprivacy 内容正确 |
| 9 | App Store Safe 模式验证 | 15 分钟 | `appStoreSafe` 模式下审核兼容 |
| 10 | 全链路测试 | 30 分钟 | 正常设备/越狱设备/模拟器三端验证 |

### 配置示例

```swift
let config = CPRiskConfig()
config.enableBehaviorDetect = true
config.enableNetworkSignals = true
config.threshold = 55.0
config.enableAntiTamper = true
config.enableRemoteConfig = true
config.remoteConfigURLString = "https://api.example.com/riskkit/config"

// 审核期间使用
// config.antiDebugRuntimeMode = .appStoreSafe

CPRiskKit.shared.start(config: config)
```

### 加密上报对接

```swift
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
report.bindAccount("user_id_123", scene: "payment")

do {
    let encrypted = try report.securePayload()
    // POST encrypted to your server
    uploadToServer(encrypted)
} catch {
    // Fallback: 使用未加密 payload（仅限测试）
    let json = report.unencryptedPayloadString(prettyPrinted: false)
    uploadToServer(json.data(using: .utf8)!)
}
```

### Standard Path 交付物

- [x] Quick Path 全部完成
- [x] 自定义配置生效
- [x] 多场景评估覆盖
- [x] 加密上报链路打通
- [x] 远程配置可用
- [x] App Store 合规验证

---

## Advanced Path — 深度集成 (< 8h)

适用于需要深度定制、多租户支持或服务端联动的复杂场景。

### 步骤清单

| # | 步骤 | 预估时间 | 完成标志 |
|---|------|---------|---------|
| 1 | Standard Path 全部完成 | — | 前置条件 |
| 2 | 多租户 Key 管理配置 | 30 分钟 | TenantKeyManager 初始化成功 |
| 3 | 图风控反馈接入 | 30 分钟 | GraphRiskFeedback 回调生效 |
| 4 | 服务端签名验证对接 | 30 分钟 | v2a 签名验证通过 |
| 5 | 自定义 ServerRiskPolicy | 20 分钟 | 服务端策略下发生效 |
| 6 | Kill Switch 远程配置 | 15 分钟 | Kill Switch 启用/恢复测试 |
| 7 | 证书固定配置 | 15 分钟 | TLS Pinning 验证 |
| 8 | cprisk-armor 壳保护集成 | 45 分钟 | 加固后 IDA 中 sub_XXXX |
| 9 | 性能调优（Profiling） | 30 分钟 | evaluate P95 < 200ms |
| 10 | 灰度发布策略 | 20 分钟 | ExperimentConfig 分桶验证 |
| 11 | 端到端红蓝对抗测试 | 45 分钟 | 越狱/Hook/云手机检测覆盖 |

### 多租户 Key 管理

```swift
let keyManager = TenantKeyManager(configuration: .init(
    keychainAccessGroup: "group.com.example.riskkit",
    defaultGracePeriod: 3600,
    defaultKeyTTL: 86400 * 90
))

// 注册租户
let key = try keyManager.registerTenant("tenant_A")

// 密钥轮换
let pending = try keyManager.beginRotation(for: "tenant_A")
// ... 等待 grace period ...
let newActive = try keyManager.commitRotation(for: "tenant_A")

// 紧急撤销
try keyManager.revokeAllKeys(for: "tenant_compromised")
```

### 图风控联动

```swift
// 监听图风控反馈
NotificationCenter.default.addObserver(
    forName: CPRiskKit.graphRiskFeedbackDidApplyNotification,
    object: nil,
    queue: .main
) { _ in
    let updatedReport = CPRiskKit.shared.evaluate()
    print("Updated score after graph feedback: \(updatedReport.score)")
}
```

### Advanced Path 交付物

- [x] Standard Path 全部完成
- [x] 多租户密钥管理就绪
- [x] 图风控端侧联动
- [x] 壳保护应用完成
- [x] 性能基线建立
- [x] 红蓝对抗通过

---

## 环境要求

### 开发环境

| 项目 | 要求 |
|------|------|
| macOS | 14.0+ (Sonoma) |
| Xcode | 15.0+ |
| Swift | 5.9+ |
| CocoaPods（如需） | 1.14+ |
| Carthage（如需） | 0.39+ |

### 运行时环境

| 项目 | 要求 |
|------|------|
| iOS | 14.0+ |
| 架构 | arm64 (真机), arm64/x86_64 (模拟器) |
| 网络 | 可选（仅远程配置和服务端信号需要） |
| Keychain | 必需（降级到 UserDefaults 可用） |

### 项目配置

- `SWIFT_VERSION = 5.9`
- `IPHONEOS_DEPLOYMENT_TARGET = 14.0`
- Bitcode: 不需要（Apple 已废弃）
- `Enable Modules (C and Objective-C)`: YES

---

## 常见问题与排查

### 编译阶段

| 问题 | 原因 | 解决 |
|------|------|------|
| `Missing required module 'CRiskCore'` | 使用 Core subspec 但代码引用了 CRiskCore | 切换到 Full subspec 或移除 CRiskCore 引用 |
| `Module compiled with Swift X.Y cannot be imported by the Swift X.Z compiler` | XCFramework 编译器版本不匹配 | 使用 `BUILD_LIBRARY_FOR_DISTRIBUTION=YES` 重建 |
| C 头文件找不到 | Header Search Paths 未配置 | 添加 CRiskCore/include 到搜索路径 |
| 链接时 duplicate symbols | 重复集成（SPM + CocoaPods） | 仅使用一种包管理器 |

### 运行时

| 问题 | 原因 | 解决 |
|------|------|------|
| `start()` 后 evaluate 返回空报告 | SDK 未完成初始化 | 确保 `start()` 在首次 `evaluate()` 之前调用 |
| 正常设备 score 过高 | Debug 模式触发反调试 | 使用 `relaxedDevelopmentQA` 模式 |
| 模拟器上大量 `unavailable` 信号 | 模拟器缺少硬件特征 | 这是预期行为，以真机为准 |
| App Store 审核被拒 | 使用了 private API 或反调试过强 | 切换到 `appStoreSafe` 模式 |
| Keychain 错误 -34018 | App 未配置 Keychain Sharing | 启用 Keychain Sharing capability 或忽略（SDK 自动降级） |

### 性能

| 问题 | 原因 | 解决 |
|------|------|------|
| evaluate() > 500ms | 首次调用含冷启动开销 | 预热：在 `viewDidAppear` 而非 `didFinishLaunching` 中首次 evaluate |
| 内存峰值 > 20MB | 所有 detector 同时初始化 | 使用 RiskConfig.light 减少检测器数量 |
| CPU 占用持续偏高 | MotionSampler 持续运行 | 不需要时调用 `stop()` |

---

## 测试验证清单

### 基础功能验证

- [ ] `start()` 调用成功，无崩溃
- [ ] `evaluate()` 返回有效 `CPRiskReport`
- [ ] `report.score` 在 0-100 范围内
- [ ] `report.signals` 非空
- [ ] `report.deviceID` 非空
- [ ] `stop()` 调用成功

### 正确性验证

- [ ] 正常真机设备：score < 30
- [ ] 越狱设备（如有）：score > 80
- [ ] 模拟器：score 介于 0-50（部分信号 unavailable）
- [ ] 多次 evaluate 结果稳定（score 波动 < 5）

### 场景验证

- [ ] `.login` 场景评估正常
- [ ] `.payment` 场景评估正常
- [ ] `.register` 场景评估正常
- [ ] 不同场景 score 有合理差异

### 安全验证

- [ ] `securePayload()` 返回加密数据
- [ ] 服务端能正确解密并验签
- [ ] Kill Switch 启用后 score=0
- [ ] 远程配置拉取并应用成功

### 兼容性验证

- [ ] iOS 14 最低版本运行正常
- [ ] iOS 18 最新版本运行正常
- [ ] iPhone SE (2nd) 性能达标
- [ ] iPhone 15 Pro 性能达标
- [ ] iPad 运行正常
- [ ] Dark Mode / Light Mode 无影响（SDK 无 UI）

### App Store 提审验证

- [ ] `appStoreSafe` 模式下无审核风险 API
- [ ] Privacy Manifest 内容完整
- [ ] 无 IDFA / AdSupport 引用
- [ ] 无未声明的 Required Reason API
