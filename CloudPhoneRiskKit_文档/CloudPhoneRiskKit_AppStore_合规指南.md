# CloudPhoneRiskKit iOS SDK 合规接入指南

> 文档类型：技术文档  
> 适用对象：集成 `CloudPhoneRiskKit` 的 iOS 客户端团队、交付团队、法务/隐私同学  
> 适用场景：App Store / TestFlight 分发、源码集成、XCFramework 二进制分发  
> 当前 SDK 事实基础：`CloudPhoneRiskKit` 以 **静态库 / 源码包** 为主，SDK 当前 privacy manifest 已声明 `Device ID`、`UserDefaults`、`SystemBootTime`，并显式声明 `NSPrivacyTracking = false`

---

## 1. 先结论

对接 `CloudPhoneRiskKit` 时，要把责任拆成三层：

1. **SDK 自身声明**：SDK 自己收集什么数据、访问什么 Required Reason API、是否 tracking。
2. **宿主 App 声明**：宿主 App 最终是否把这些数据上传、是否和账号关联、是否触发额外权限申请。
3. **分发方式责任**：如果是静态库或源码集成，宿主 App 要更主动地合并/承接 privacy manifest；如果是二进制 SDK，还要处理签名连续性。

最容易踩坑的不是“manifest 有没有文件”，而是这三件事混在一起：

- 把 SDK manifest 当成宿主 App 的 Privacy Label
- 以为静态库会自动像动态 framework 一样被苹果完整识别
- 文档没把“哪些功能开了才需要哪些声明”说清楚

这份指南就是把这三层彻底拆开。

---

## 2. 写法参考来源

这版指南的结构，主要参考了几类成熟 SDK 的公开文档写法：

- **Sentry**：强调“动态 framework 可自动处理，静态库宿主要自己补 app-level manifest”。
- **Fingerprint Identification SDK**：把 `tracking / collected data / host app responsibility` 讲得非常清楚，尤其适合设备指纹/风控类 SDK。
- **Airship**：强调“隐私范围取决于启用的能力”，即**功能开关决定数据边界**。
- **Apple 官方**：第三方 SDK privacy manifest 与签名要求、Required Reason API 规则。

本指南不照搬这些文档，而是吸收它们的结构优点，改写成适合风控 SDK 的交付版本。

---

## 3. 责任边界：谁负责什么

| 事项 | 责任主体 | 说明 |
|------|----------|------|
| SDK 自身 `PrivacyInfo.xcprivacy` | SDK 提供方 | 描述 SDK 代码本身的 collected data / accessed APIs |
| 宿主 App 的 `PrivacyInfo.xcprivacy` | 宿主 App | 描述 App 自身代码，以及静态集成场景下对 SDK 的合并声明 |
| App Store Connect 的 `App Privacy` 标签 | 宿主 App | 回答“最终这款 App 实际收集并如何使用这些数据” |
| 面向终端用户的隐私政策 | 宿主 App | SDK 文档不能替代 App 的正式隐私政策 |
| XCFramework 二进制签名 | SDK 提供方 | 仅对二进制分发场景成立 |

最重要的一句：

> **SDK 的 privacy manifest 不是宿主 App 的 Privacy Nutrition Label，也不是宿主 App 的隐私政策。**

---

## 4. 当前 SDK 的自声明范围

当前仓库中的 SDK 自带文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Resources/PrivacyInfo.xcprivacy`

当前声明的事实范围如下。

### 4.1 Collected Data

| 数据类型 | Linked | Tracking | Purpose | 说明 |
|----------|--------|----------|---------|------|
| `NSPrivacyCollectedDataTypeDeviceID` | `false` | `false` | `NSPrivacyCollectedDataTypePurposeFraudPrevention` | 用于设备级风险识别、防刷、防模拟器/云手机等风控目的 |

### 4.2 Required Reason APIs

| API 类别 | Reason | SDK 中的实际用途 |
|----------|--------|------------------|
| `NSPrivacyAccessedAPICategoryUserDefaults` | `CA92.1` | 本 App 范围内的缓存、配置、降级状态保存 |
| `NSPrivacyAccessedAPICategorySystemBootTime` | `35F9.1` | 时序基线、反篡改、环境完整性判断 |

### 4.3 明确不做的事

当前 SDK 文档口径应明确写出以下事实：

- **privacy manifest 中显式声明 `NSPrivacyTracking = false`**
- **privacy manifest 中显式声明空的 `NSPrivacyTrackingDomains`**
- **不使用 ATT 语义下的 tracking**
- **不以广告定向为目的收集数据**
- **不把 collected data 用于第三方广告画像**
- **不要求宿主 App 一定上传所有本地信号**

这类“否定性声明”在成熟 SDK 文档里很重要，因为审核和客户法务最先问的常常不是“你收什么”，而是“你是不是在 tracking”。

---

## 5. 为什么这次不声明 `FileTimestamp`

这部分要单独说，因为它很像审计时会被反复追问的点。

苹果公开的 `File Timestamp` approved reasons，核心针对的是：

- App 自己容器里的文件管理
- 用户授权文件的元数据访问
- 向用户展示文件时间/文件属性

而本 SDK 原先使用 `stat/lstat` 的主要目的，是：

- 越狱路径存在性判断
- anti-hook / anti-stalker 时序探针
- 系统环境差异探测

这些用途并不天然落在苹果公开的 `FileTimestamp` approved reasons 上。  
所以本仓库当前采取的是**“改实现，不硬填理由”**的策略：

- 把存在性探针切到 `access()` / `FileManager.fileExists(atPath:)`
- 保留确实有公开合法 reason 的 `UserDefaults` 与 `SystemBootTime`
- 避免对接方拿到一个“表面合规、实则用途不匹配”的 manifest

对于风控 SDK，这比单纯多填一个 reason code 更稳。

---

## 6. 集成方式与合规差异

这部分是参考 Sentry 文档结构后，专门按你这个 SDK 的交付形态改写的。

| 集成方式 | 当前项目适配情况 | 合规要点 |
|----------|------------------|----------|
| Swift Package 源码集成 | **主要方式** | 宿主 App 应准备自己的 app-level `PrivacyInfo.xcprivacy`，不要只依赖 SDK 资源文件 |
| 静态库集成 | **等价于当前主路径** | 宿主 App 对隐私声明承担更高责任，建议显式合并 SDK 的声明项 |
| 动态 framework 集成 | 当前不是主交付形态 | 通常更容易被 Xcode/苹果聚合识别，但仍不能替代宿主 App 的 Privacy Label |
| XCFramework 二进制分发 | 可扩展支持 | 需要二进制签名、manifest 入包校验、版本连续性管理 |

### 6.1 对当前项目最重要的一条

因为 `CloudPhoneRiskKit` 当前是**静态库 / 源码包风格**，所以对接方最稳的做法不是“信任 SDK 自己带的 manifest 就够了”，而是：

1. 以 SDK 的 `PrivacyInfo.xcprivacy` 作为**声明源**
2. 在宿主 App 的 app-level `PrivacyInfo.xcprivacy` 中**显式承接或合并**
3. 再由 Xcode Privacy Report 和 App Store Connect 去完成最终校验

这也是很多成熟 SDK 在静态集成场景下会特别提醒的一点。

---

## 7. 宿主 App 必须补的配置

### 7.1 `Info.plist` 权限说明

| Key | 何时需要 | 建议文案 |
|-----|----------|----------|
| `NSMotionUsageDescription` | 启用行为信号、运动传感器采样时 | `用于识别异常设备行为与环境风险` |
| `NSFaceIDUsageDescription` | 启用生物识别状态探测时 | `用于识别设备生物识别能力与安全状态` |

### 7.2 `LSApplicationQueriesSchemes`

如果启用了以下能力，宿主 App 需要配置 `LSApplicationQueriesSchemes`：

- `SchemeDetector`
- `BasebandIsolationProvider` 的系统 App 可达性探测

建议不要无脑全量声明，而是按功能裁剪：

- 越狱相关：`cydia`、`sileo`、`zbra`、`filza`、`activator`、`undecimus`
- 系统 App 完整性相关：`itms-watch`、`x-apple-health`

### 7.3 Review Notes 建议口径

建议宿主 App 在 `Review Notes` 里主动写明：

```text
This app integrates CloudPhoneRiskKit for device integrity verification and fraud-prevention.

The SDK may collect device-side risk signals such as device identifier, runtime integrity signals,
environment consistency signals, and optional motion or biometric-capability signals when enabled.

These signals are used for security and fraud-prevention purposes only, not for advertising tracking.
Any queried URL schemes are limited to jailbreak or device-integrity checks.
```

如果启用了 scheme 查询，再补一段：

```text
Queried URL schemes are used solely for device integrity verification and compatibility checks.
They are not used to profile installed apps for analytics or advertising.
```

---

## 8. 宿主 App 的 Privacy Label 怎么填

这一部分的写法，我参考了 Fingerprint 那种“把 SDK 收集事实与 App 实际使用拆开讲”的方式。

### 8.1 先按使用模式分两类

#### 模式 A：仅本地评估，不上传风险报告

典型特征：

- 调用 `evaluate()` / `evaluateAsync()`
- 只在端上产出风险结论
- 不把设备标识、行为信号、风险报告上传服务端

这种模式下，宿主 App 在 `App Privacy` 中是否需要声明，取决于 **App 自己有没有让这些数据离开设备**。

#### 模式 B：上传风险报告到服务端

典型特征：

- 调用 `buildSecureReportEnvelope(...)`
- 调用 `toGrpcCompatiblePayload(...)`
- 上传 `deviceId`、payload、signals、graph payload、账号上下文字段

这种模式下，宿主 App 通常就必须把相应数据计入自己的 `App Privacy`。

### 8.2 实务上最常见的填写映射

| SDK 字段或能力 | Apple 标签中优先评估的分类 | 何时建议声明 |
|---------------|----------------------------|--------------|
| `deviceId`、稳定设备标识、`identifierForVendor` | `Device ID` | 只要上传到服务端，或用于设备级长期识别 |
| `accountId`、用户账号标识 | `User ID` | 与风险报告或设备画像一起上传时 |
| 触摸/行为/运动类摘要 | `Product Interaction` 或 `Other Usage Data` | 上传行为分析结果或原始摘要时 |
| 越狱/Hook/系统环境/代理/VPN/设备指纹摘要 | `Other Data Types` | 上传环境风险信号时 |
| 生物识别状态（已录入/不可用） | `Other Data Types` | 上传生物识别状态值时 |

### 8.3 一个判断原则

> **只要某类数据离开设备、进入你们服务端，并参与账号级、设备级、风控级决策，就不要把它视为“未收集”。**

SDK 文档可以给你分类建议，但最终 `App Privacy` 的责任主体始终是宿主 App。

---

## 9. 推荐的宿主 App `PrivacyInfo.xcprivacy` 承接方式

因为你这个 SDK 当前是静态集成主路径，所以最推荐的是：  
宿主 App 自己维护一份 app-level `PrivacyInfo.xcprivacy`，把 SDK 所需项承接进去。

### 9.1 最小承接模板

下面这个片段只表达 **SDK 侧最小事实范围**，宿主 App 还要把自己其他 SDK/代码的声明一并合进去。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyTrackingDomains</key>
    <array/>
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeDeviceID</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <false/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeFraudPrevention</string>
            </array>
        </dict>
    </array>
    <key>NSPrivacyAccessedAPITypes</key>
    <array>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryUserDefaults</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>CA92.1</string>
            </array>
        </dict>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategorySystemBootTime</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>35F9.1</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

### 9.2 什么时候需要扩展这个模板

如果宿主 App 真的把以下数据上传服务端，就需要把 app-level 声明进一步补齐：

- `User ID`
- 行为数据 / 产品交互数据
- 位置相关数据
- 其他环境画像或设备画像字段

也就是说：  
**SDK 提供的是“最低合规基线”，不是“所有宿主都通吃的最终声明”。**

---

## 10. 二进制分发时的签名要求

### 10.1 什么时候需要做

只有当你把 SDK 作为以下形态交付给客户时，这条才会变成刚需：

- `XCFramework`
- 其他二进制依赖

如果只是源码包 / 私有仓库 Swift Package 源码依赖，这条不是当前阻断项。

### 10.2 二进制分发的建议口径

参考 Apple 第三方 SDK 要求，建议你把文档写成下面这种“明确但不过度承诺”的风格：

1. 每个版本使用固定的 `Apple Distribution` 身份签名。
2. 后续版本保持同一发行主体，避免 Xcode 认为供应链来源漂移。
3. `PrivacyInfo.xcprivacy` 必须进入最终二进制交付物。
4. 交付前执行 `codesign --verify` 校验。

### 10.3 手工签名步骤

```bash
codesign --force --sign "Apple Distribution: YOUR COMPANY (TEAMID)" --timestamp "/path/to/CloudPhoneRiskKit.xcframework/ios-arm64/CloudPhoneRiskKit.framework"
codesign --force --sign "Apple Distribution: YOUR COMPANY (TEAMID)" --timestamp "/path/to/CloudPhoneRiskKit.xcframework"
codesign --verify --deep --strict --verbose=2 "/path/to/CloudPhoneRiskKit.xcframework"
codesign -dvv "/path/to/CloudPhoneRiskKit.xcframework"
```

### 10.4 交付前检查清单

- 产物内存在 `PrivacyInfo.xcprivacy`
- 版本号与文档一致
- 对接方已拿到 `Info.plist` 要求
- 对接方已拿到 Privacy Label 说明
- 二进制签名已校验

---

## 11. 常见误区

### 误区 1：SDK 自带 manifest，所以宿主 App 什么都不用做

不对。  
宿主 App 仍然要：

- 决定最终的 `App Privacy` 标签
- 配置权限说明
- 在静态集成场景下承接或合并 manifest

### 误区 2：本地做风控，不上传，就等于完全不算数据收集

不完全对。  
如果数据确实不离开设备，宿主 App 的标签压力会小很多；但 Required Reason API 访问、权限说明、SDK 自身声明依然存在。

### 误区 3：manifest 填上就行，代码实现不重要

不对。  
对于 `FileTimestamp` 这类 API，**用途是否和 approved reason 对得上** 才是关键。  
这也是为什么本仓库选择了“改实现路径”而不是“多填一个不稳的理由码”。

---

## 12. 对外沟通时推荐怎么说

如果你把这份指南发给客户，最适合的一句话是：

> `CloudPhoneRiskKit` 已提供 SDK 级 privacy manifest 与合规说明；由于当前交付形态以静态集成为主，宿主 App 仍需在 app-level privacy manifest、App Privacy 标签、权限说明与审核备注中承接最终责任。

这句话既不会让客户误解成“全自动合规”，也不会显得 SDK 完全没准备。

---

## 13. 相关配套文档

建议与本指南一起放在 `CloudPhoneRiskKit_文档/` 目录中交付：

- `CloudPhoneRiskKit_SDK_隐私声明.md`
- `CloudPhoneRiskKit_使用说明.md`
- SDK 版本变更记录
- 宿主 App 接入 checklist

其中：

- 本指南回答“怎么接入才合规”
- SDK 隐私声明回答“SDK 自己到底收什么、为什么收”

这两份文档应该分开。
