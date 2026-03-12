# CloudPhoneRiskKit 4.9 使用与构建说明

iOS 端「云手机 / 远程控制 / 越狱」风险本地采集与评分 SDK，输出结构化 JSON 报告，支持场景化决策、App Attest 硬件信任根、可插拔 Provider 扩展。

---

## 1. 环境要求

| 项目 | 最低版本 |
|------|---------|
| macOS | 14.0+ |
| Xcode | 15.0+ |
| iOS 部署目标 | 14.0+ |
| Swift | 5.9+ |

---

## 2. 构建方式

### 2.1 SPM 命令行构建

```bash
cd RiskDetectorApp
swift build
```

### 2.2 XcodeGen 生成工程

```bash
cd RiskDetectorApp
brew install xcodegen   # 如已安装可跳过
xcodegen generate
open RiskDetectorApp.xcodeproj
```

### 2.3 Xcode 直接打开

用 Xcode 打开 `RiskDetectorApp/Package.swift`，Xcode 会自动识别为 SwiftPM 工程并解析依赖。

### 2.4 真机 vs 模拟器

**推荐真机调试。** 模拟器下以下检测器返回 `unavailable`：
- DRM 能力检测（FairPlay）
- 电池熵检测（无真实电池硬件）
- 部分越狱 / 挂载点检测（沙盒行为不同）

模拟器适合做接入验证和 JSON 结构检查；越狱强度回归 & 行为指纹精度测试请用真机。

---

## 3. 接入方式（SwiftPM）

**方式 A — Xcode GUI**

Xcode → Project → Package Dependencies → **Add Local…** → 选择 `RiskDetectorApp` 目录（包含 `Package.swift`）。

**方式 B — Package.swift 声明**

```swift
dependencies: [
    .package(path: "../cloudphone-risk-detector/RiskDetectorApp")
]
// target
.target(name: "YourApp", dependencies: [
    .product(name: "CloudPhoneRiskKit", package: "CloudPhoneRiskKit"),
])
```

---

## 4. 快速上手

```swift
import CloudPhoneRiskKit

// 1) 启动采集（建议在 didFinishLaunching 尽早调用）
CPRiskKit.shared.start()

// 2) 同步评估
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
print(report.score, report.isHighRisk, report.summary)

// 3) 异步评估（completion 回到主线程）
CPRiskKit.shared.evaluateAsync { report in
    print(report.score)
}

// 4) async/await（iOS 13+）
let report = await CPRiskKit.shared.evaluateAsync(config: .default, scenario: .login)

// 5) 停止采集
CPRiskKit.shared.stop()
```

---

## 5. ObjC 兼容

```objc
#import <CloudPhoneRiskKit/CloudPhoneRiskKit-Swift.h>

[[CPRiskKit shared] start];
CPRiskReport *report = [[CPRiskKit shared] evaluateWithConfig:[CPRiskConfig default]
                                                     scenario:[RiskScenario payment]];
NSLog(@"score=%f high=%d", report.score, report.isHighRisk);

[[CPRiskKit shared] evaluateAsyncWithCompletion:^(CPRiskReport *report) {
    NSLog(@"score=%f", report.score);
}];
```

---

## 6. 场景化决策

支持的 `RiskScenario`：

| 场景标识 | 说明 |
|---------|------|
| `.login` | 登录 |
| `.payment` | 支付 |
| `.register` | 注册 |
| `.accountChange` | 账号变更 |
| `.sensitiveAction` | 敏感操作 |
| `.apiAccess` | API 访问 |

```swift
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
// 不同场景有独立的阈值、权重和 combo 规则
```

---

## 7. 服务端配置签名（推荐）

配置 HMAC 签名密钥后，SDK 会验证远程配置的签名完整性，防止中间人篡改：

```swift
CPRiskKit.configureServerSigningKey("your-server-hmac-key")
CPRiskKit.shared.start()
```

---

## 8. App Attest 硬件信任根（4.9 更新）

4.9 新增 `requireAttestation` 参数（默认 `true`），不支持或失败时 **抛错而非静默降级**：

```swift
let envelope = try await CPRiskKit.shared.buildSecureReportEnvelopeWithAttestation(
    report: report,
    sessionToken: sessionToken,
    signingKey: signingKey,
    requireAttestation: true   // 强制硬件信任根，失败即 throw
)
// envelope.hasHardwareAttestation == true 时表示已附加硬件断言
```

- 需在 Xcode → Signing & Capabilities 中开启 **App Attest**。
- `requireAttestation: false` 时允许降级，调用方应检查 `envelope.hasHardwareAttestation`。

---

## 9. 服务端信号注入

将服务端聚合结果（IP / ASN / 聚合度等）回注 SDK，参与本地评分：

```swift
CPRiskKit.setExternalServerSignals(
    publicIP: "1.2.3.4",
    asn: "AS4134",
    asOrg: "CHINANET",
    isDatacenter: 1,
    ipDeviceAgg: 120,
    ipAccountAgg: 500,
    geoCountry: "CN",
    geoRegion: "GD",
    riskTags: ["dc_ip", "ip_shared"]
)
```

---

## 10. 本地加密存储

报告使用 **AES-GCM** 加密 + **HMAC** 完整性保护，密钥存于 Keychain（`ThisDeviceOnly`）。

```swift
// 保存
let path = CPRiskStore.shared.save(report, error: nil)

// 解密读取
let json = CPRiskStore.shared.decryptReport(atPath: path, error: nil)
```

---

## 11. 可插拔 Provider 扩展

实现 `RiskSignalProvider` 协议，注册后每次 `evaluate()` 自动参与评分：

```swift
final class MyProvider: RiskSignalProvider {
    let id = "my_custom"
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        // 基于 snapshot 产出自定义信号
        return []
    }
}

CPRiskKit.register(provider: MyProvider())
```

---

## 12. 配置项速查

`CPRiskConfig` 常用配置：

| 配置项 | 类型 | 默认值 | 说明 |
|-------|------|--------|------|
| `threshold` | `Double` | `60` | 高风险总分阈值 |
| `enableBehaviorDetect` | `Bool` | `true` | 行为指纹采集 |
| `enableNetworkSignals` | `Bool` | `true` | 网络信号采集 |
| `enableAntiTamper` | `Bool` | `true` | 反篡改 / Hook 检测 |
| `enableTemporalAnalysis` | `Bool` | `false` | 时序模式分析 |
| `enableRemoteConfig` | `Bool` | `false` | 远程配置拉取 |
| `defaultScenario` | `RiskScenario` | `.default` | 默认评估场景 |
| `jailbreak.*` | — | — | 越狱检测子开关（file/dyld/sysctl/env/scheme/hook） |

> Release 构建下，核心检测开关（file/dyld/sysctl/hook/behavior/network）由 SDK 强制开启，不可被远程配置或调用方关闭。

---

## 13. 注意事项

1. **模拟器限制**：越狱检测在模拟器无实际意义，DRM / 电池 / 部分挂载点检测返回 `unavailable`。
2. **SchemeDetector**：需在宿主 App 的 `Info.plist` 添加 `LSApplicationQueriesSchemes`（如 `cydia`、`sileo`、`filza` 等），否则 `canOpenURL` 始终返回 `false`。
3. **弱信号原则**：SDK 将不可用 / 无法获取的信号视为弱信号，不会因系统限制直接判定高风险。**强结论建议放在服务端做聚合判断**（IP 聚合、ASN、设备图谱、长连接流量模式等）。
4. **日志开关**：`CPRiskKit.setLogEnabled(true)` 仅在 `DEBUG` 构建下生效。
