# CloudPhoneRiskKit iOS SDK 合规接入指南

> 文档类型：技术文档  
> 适用对象：集成 `CloudPhoneRiskKit` 的 iOS 客户端团队、交付团队、法务/隐私同学  
> 适用场景：App Store / TestFlight 分发、源码集成、XCFramework 二进制分发  
> 适用版本：SDK 7.3  
> 当前 SDK 事实基础：`CloudPhoneRiskKit` 以 **静态库 / 源码包** 为主，SDK 当前 privacy manifest 已声明 `Device ID`、`UserDefaults`、`SystemBootTime`，并显式声明 `NSPrivacyTracking = false`

---

## 1. 先结论

对接 `CloudPhoneRiskKit` 时，要把责任拆成三层：

1. **SDK 自身声明**：SDK 自己收集什么数据、访问什么 Required Reason API、是否 tracking。
2. **宿主 App 声明**：宿主 App 最终是否把这些数据上传、是否和账号关联、是否触发额外权限申请。
3. **分发方式责任**：如果是静态库或源码集成，宿主 App 要更主动地合并/承接 privacy manifest；如果是二进制 SDK，还要处理签名连续性。

在开始之前，有三个最关键的认知要先对齐：

> **① SDK 不会触发 ATT（广告追踪弹窗）。** `NSPrivacyTracking = false`，也没有声明 `NSPrivacyTrackingDomains`，不请求广告追踪授权。这是集成本 SDK 对宿主 App 合规友好度最高的一点，直接意味着不会因集成本 SDK 而对用户弹出 ATT 权限框。
>
> **② SDK 的 manifest 是你合规的参考基线，不是你的 Privacy Label。** 宿主 App 必须在自己的 app-level `PrivacyInfo.xcprivacy` 中承接 `DeviceID`、`UserDefaults`、`SystemBootTime` 这三项。静态库 / 源码集成下 Xcode 不会自动合并 SDK 的 manifest，这件事必须由宿主 App 手工完成。
>
> **③ 风险报告上传会改变 Privacy Label 的填写要求。** 如果宿主 App 调用 `buildSecureReportEnvelope` 等接口把风险报告上传服务端，App Store Connect 中的 `DeviceID` 条目从"可以不声明"变成**必须声明**。`Linked` 字段取决于是否与账号 ID 一同上传——若是，应填 `true`；若仅关联设备、不关联账号，可填 `false`。

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

### 4.4 7.3 版本升级对合规披露的影响

7.3 在 7.2 基线之上对外版本号与文档对齐；能力侧仍延续并加强**MIE/MTE 安全姿态探测、运行时完整性校验与构建产物可见性收敛能力**，包括：

- `MIEPostureDetector` / `cprisk_mte_guard`：通过 `sysctl` + 本地 snapshot / canary 生成设备安全姿态信号
- Pass 6 扩展为 **符号剥离 + export trie scrub**，阻断静态工具通过导出表恢复函数名
- Release 构建使用 `SWIFT_REFLECTION_METADATA_LEVEL=minimal`，并继续通过 `@objc(CPR_...)` 收敛关键对外类名
- watchdog 引入 Mach port mailbox peer-liveness、PAC bridge 线程入口校验、更多 breakpoint / timeout / exception 维度
- VM region image 白名单差异比对、`user_tag` 精细化扫描、SVC 桩代码页 hash 滚动校验
- 白盒 PRF 与被动完整性信号、runtime material 的耦合进一步加强

这些能力会改变**构建产物的代码形态、运行时完整性检查强度、静态符号可见性和逆向对抗强度**，但**不会新增 privacy manifest 中的数据类别，也不会新增 Required Reason API 类别**。因此，宿主 App 在合规披露上最需要关注的，仍然是：

1. SDK manifest 的三项基础事实：`Device ID`、`UserDefaults`、`SystemBootTime`
2. 宿主 App 是否把风险报告、行为摘要、环境信号上传到服务端
3. 宿主 App 是否启用了 Motion / Face ID / URL Scheme 等需要额外权限说明或审核解释的能力

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

建议宿主 App 在 `Review Notes` 里主动写明。以下提供两种口径，按业务需要选用。

#### 口径 A：完整版（推荐，全量开启 armor 保护时使用）

适用场景：SDK 全量启用 cprisk-armor 构建期 + 运行时保护（字符串加密、数据段加密、完整性校验、符号表 + export trie 清理、Swift 可见性收敛、Mach-O header 擦除、JIT 按页解密、空闲重加密、guard page anti-dump、Pass 7 anti-debug runtime gate、Pass 8 instruction substitution、Pass 9 CFF 控制流编排、Pass 10 import encryption、Pass 11 header encryption、Pass 12 text page encryption、Pass 13 VMProtector / VM interpreter、白盒表 ASLR 绑定、bootstrap mini-VM 等），不做任何裁剪。

```text
This app integrates CloudPhoneRiskKit, a fraud-prevention and device-integrity SDK.

The SDK uses runtime integrity verification techniques — including code-section hash
validation, symbol-table and export-metadata scrubbing for executable builds, minimized Swift
reflection metadata exposure, encrypted string tables with lazy plaintext lifetime control,
protected data segments, anti-debug watchdog probes, guard-page anti-dump traps, on-demand
text-page decryption with idle re-encryption, compile-time anti-debug injection metadata,
conservative equal-length instruction substitution, control-flow flattening (CFF) applied at build
time, and a custom VM interpreter with integrity-checked bytecode execution — to detect jailbreak, hooking, dynamic
instrumentation, and cloud-phone/emulator environments. These techniques
are consistent with banking and financial app security standards (e.g. Promon SHIELD,
Guardsquare iXGuard) and are used exclusively for fraud prevention and runtime tamper
detection, not for hiding functionality from App Review.

The SDK does not use any private APIs. It does not perform advertising tracking
(NSPrivacyTracking = false). Device-side risk signals such as device identifier,
runtime integrity status, environment consistency signals, and optional motion or
biometric-capability signals are collected solely for security purposes.

All runtime protection mechanisms serve a single goal: ensuring that the fraud-prevention
logic has not been tampered with by attackers, so that risk assessments remain trustworthy.
```

如果启用了 scheme 查询，在上面基础上追加：

```text
Queried URL schemes (e.g. cydia, sileo) are used solely for device integrity verification.
They are not used to profile installed apps for analytics or advertising.
```

#### 口径 B：精简版（裁剪部分 armor 能力时使用）

适用场景：App Store 构建关闭了 `cprisk_erase_macho_header` 和 `cprisk_jit_decrypt_page`，同时不启用 text 页加密与 VM 虚拟化，只保留数据段预解密 + 完整性校验 + 符号/导出可见性收敛 + 轻量 anti-debug 链。

```text
This app integrates CloudPhoneRiskKit for device integrity verification and fraud-prevention.

The SDK may collect device-side risk signals such as device identifier, runtime integrity signals,
environment consistency signals, and optional motion or biometric-capability signals when enabled.

These signals are used for security and fraud-prevention purposes only, not for advertising tracking.
Any queried URL schemes are limited to jailbreak or device-integrity checks.
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

### 8.4 一个更实用的披露口诀

为了避免法务、产品和客户端对“是否算收集”理解不一致，可以直接用下面这条内部判断规则：

- **SDK 本地采集但不上报**：重点落在 SDK manifest、权限说明、审核备注，不等同于宿主 App 一定要把所有字段都填进 `App Privacy`
- **SDK 生成报告且宿主 App 上报**：按照“哪些字段离开设备”来填 `App Privacy`
- **宿主 App 把字段与账号、手机号、用户中心 ID 绑定**：除了数据类型本身，还要重新评估 `Linked` 是否应为 `true`
- **7.3 交付中的 runtime gate / text 加密 / VM 保护 / export trie scrub / Swift 可见性收敛 / CPSV 驱动 self-check**（继承 7.2 起引入的能力）：属于安全实现增强，不单独生成新的隐私披露项

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

## 11. cprisk-armor 二进制加固与 App Store 合规

### 11.1 加固目标：宿主 App 二进制，不是 SDK 本身

`cprisk-armor` 是编译后壳保护工具。6.4 起，壳的加固目标是**最终的宿主 App 二进制**（而非 SDK 的 framework / 静态库产物）。

```
SDK 源码 ──编译链接进──→ 宿主 App 二进制 ──cprisk-armor──→ 加固后的 App 二进制 ──提审──→ App Store
```

因此：

- **壳的合规责任最终由宿主 App（提审方）承担**
- SDK 提供方的责任是：提供合规的默认配置、明确告知每个 Pass 的审核风险、在文档中给出 Review Notes 口径

### 11.2 两个构建 Profile

建议向宿主 App 提供两套预设 Profile，由宿主方根据自身 App 类型和审核历史选择。

#### Profile A：Full Armor（全量保护）

```bash
cprisk-armor --input <app_binary> --output <output> --all --key <hex>
```

| Pass | 名称 | 启用 |
|------|------|------|
| Pass 1 | 字符串加密 | 是 |
| Pass 2 | 元数据擦除 | 是 |
| Pass 3 | 数据段加密 | 是 |
| Pass 4 | 完整性锚点 + 白盒 PRF（6.5） | 是 |
| Pass 5 | 结构混淆 | 是 |
| Pass 6 | 符号剥离 + export trie scrub | 是 |
| Pass 7 | AntiDebug 注入计划 + runtime gate | 是 |
| Pass 8 | InstructionSubstitution（1:1 等长指令替换） | 是 |
| Pass 9 | ControlFlowOrchestrator（CFF 控制流平坦化） | 是 |
| Pass 10 | ImportEncryptor（导入表加密） | 是 |
| Pass 11 | HeaderEncryptor（Header 加密） | 是 |
| Pass 12 | TextSegmentEncryptor（`__TEXT.__text` 页级加密） | 是 |
| Pass 13 | VMProtector（关键函数虚拟化） | 是 |

运行时能力全量开启：Mach-O Header 擦除、JIT 按页解密、空闲重加密、guard page anti-dump、异常端口保护、watchdog 多维反调试探针（含双 watchdog 互监控、影子栈校验、Mach port mailbox、PAC 线程入口桥、deny-attach verify、AMFI / entitlement 异常位）、Pass 7 anti-debug runtime gate、Pass 10 导入解析恢复、Pass 11 header sanity restore、Pass 12 text 页恢复、Pass 13 VM 解释器（dispatch/opcode/immediate 双重保护、双主循环解释器、虚拟寄存器、VM 内部子调用、HMAC self-check、dead handler / opaque predicate chain）；构建产物侧同时包含 Pass 6 的 export trie scrub、Pass 8 对 `__TEXT.__text` 的保守等长指令替换与 Pass 9 CFF 策略编排。

**适用场景**：

- 金融 / 银行 / 支付类 App（苹果对安全防护容忍度最高）
- 已有审核历史的大型 App（审核系统对已通过的 App 更宽松）
- 对逆向对抗有硬需求的场景（反作弊、反薅羊毛）

**审核风险**：低至中。与 Promon SHIELD、Guardsquare iXGuard 等商用安全 SDK 的保护等级一致，大量银行 App 采用同等甚至更激进的保护手段并在 App Store 正常运行。

**Review Notes 使用口径 A（完整版）。**

#### Profile B：AppStore Safe（保守策略）

```bash
cprisk-armor --input <app_binary> --output <output> --pass3 --pass4 --pass5 --pass6 --pass7 --pass10 --pass11 --key <hex>
```

| Pass | 名称 | 启用 | 说明 |
|------|------|------|------|
| Pass 1 | 字符串加密 | **否** | 关闭后苹果静态扫描器可正常扫描字符串，不会触发"隐藏内容"怀疑 |
| Pass 2 | 元数据擦除 | **否** | 关闭后 ObjC metadata 保持完整，苹果可正常分析类/方法结构 |
| Pass 3 | 数据段加密 | 是 | `__DATA` 段加密，运行时解密，苹果静态分析不受影响 |
| Pass 4 | 完整性锚点 + 白盒 PRF（6.5） | 是 | 完整性校验链 + 白盒 S-box 表正常工作 |
| Pass 5 | 结构混淆 | 是 | Mach-O 结构层面混淆 |
| Pass 6 | 符号剥离 + export trie scrub | 是 | 不仅清理 `LC_SYMTAB`，还会对 `MH_EXECUTE` 清理 export trie；比 `strip -x` 更强，但仍不改变业务逻辑路径 |
| Pass 7 | AntiDebug 注入计划 + runtime gate | 是 | 通过 `__DATA,__cpr_adbg7` 驱动运行时 gate，风险仍低于大规模机器码重写 |
| Pass 8 | InstructionSubstitution（1:1 等长指令替换） | **否** | 会直接改写 `__TEXT.__text` 指令流；虽然不做 CFG flattening、只改安全子集，但首发提审阶段建议关闭 |
| Pass 9 | ControlFlowOrchestrator（CFF 控制流平坦化） | **否** | 会改写 `__TEXT.__text` 控制流结构；首发提审阶段建议关闭 |
| Pass 10 | ImportEncryptor（导入表加密） | 是 | 主要影响导入名的静态可见性，不改变业务逻辑路径 |
| Pass 11 | HeaderEncryptor（Header 加密） | 是 | 运行时会做 sanity fallback，审核风险通常低于直接改写 `__TEXT` |
| Pass 12 | TextSegmentEncryptor（`__TEXT.__text` 页级加密） | **否** | 会显著增加静态分析复杂度并改变代码页恢复链路；首发提审阶段建议关闭 |
| Pass 13 | VMProtector（关键函数虚拟化） | **否** | 会把关键函数改写为 VM 跳板 + 自定义字节码，逆向对抗极强，但审核解释成本最高；首发提审阶段建议关闭 |

**适用场景**：

- 新 App / 首次提审 / 无审核历史
- 小团队 / 独立开发者
- 非金融类 App（工具、社交、电商等）
- 对审核通过率要求高于对抗强度的场景

**审核风险**：低。保留的 Pass 仍以结构/完整性保护为主，但 Pass 6 现在会额外收敛导出表可见性，因此解释成本略高于传统 `strip -x`。

**Review Notes 使用口径 B（精简版）。**

### 11.3 为什么这么分

苹果审核二进制的核心链路：

1. **静态分析**：对 IPA 内的 Mach-O 执行 `otool` 风格扫描，检查私有 API 符号引用、字符串中的敏感 API 名
2. **签名校验**：验证 code signature 完整性
3. **动态沙盒测试**：有限度运行 App，检查运行时行为
4. **人工审核**：当静态分析触发 flag 时介入

各 Pass 对这条链路的影响：

| Pass | 对静态分析的影响 | 对动态测试的影响 | 是否可能触发 flag |
|------|-----------------|-----------------|-------------------|
| Pass 1 字符串加密 | 苹果扫不到明文字符串，**无法判断是否调用私有 API** | 运行时解密，功能正常 | **可能** — 这是最容易引起"你在藏什么"怀疑的一个 |
| Pass 2 元数据擦除 | class/protocol/method name 缺失，反射信息不全 | ObjC runtime 信息减少 | **可能** — 苹果可能依赖 metadata 做分析 |
| Pass 3 数据段加密 | `__DATA` 内容是密文 | 运行时解密后正常 | 不太可能 |
| Pass 4 完整性锚点 + 白盒 | 多了非标准 section（含 ~160KB 白盒 S-box） | 不影响执行 | 不太可能 |
| Pass 5 结构混淆 | segment/section 布局异常 | 不影响 dyld 加载 | 不太可能 |
| Pass 6 符号剥离 + export trie scrub | `LC_SYMTAB` 与 `MH_EXECUTE` 的导出表可见性进一步收敛，静态符号恢复更困难 | 不影响执行 | 低至中 |
| Pass 7 AntiDebug runtime gate | 多一个自定义 `__DATA` section，并驱动运行时 patch/gate | 由运行时在关键点插入 `BRK #0xC0E0` 守门，风险高于纯 metadata 但仍低于大规模 CFG 重写 | 低至中 |
| Pass 8 InstructionSubstitution | 直接改写 `__TEXT.__text` 中的部分 ARM64 指令 | 1:1 等长、语义等价、仅限安全子集，但本质上属于机器码重写 | 中 |
| Pass 9 ControlFlowOrchestrator | 改写 `__TEXT.__text` 中策略编排函数的控制流结构 | CFF 编排骨架，源码级状态机已在 SDK 内落地 | 中 |
| Pass 10 ImportEncryptor | 导入符号名从静态明文变成运行时恢复 | 主要影响符号可见性，不影响 App 正常执行路径 | 低 |
| Pass 11 HeaderEncryptor | 头部关键字段被加密并在运行时恢复 | 若恢复失败有 sanity fallback，不依赖隐藏私有 API | 低至中 |
| Pass 12 TextSegmentEncryptor | `__TEXT.__text` 页在静态视角下不再直接可读 | 运行时恢复链更复杂，但仍属防篡改/反逆向 | 中 |
| Pass 13 VMProtector | 高价值函数不再以原生 ARM64 直接暴露 | 运行时需通过 VM 解释器执行，自定义字节码与跳板均提高审核解释门槛 | 中至高 |

**结论**：Pass 1（字符串加密）和 Pass 2（元数据擦除）是最容易影响苹果静态扫描器正常工作的 Pass；Pass 8、Pass 9、Pass 12、Pass 13 直接作用于 `__TEXT.__text` 或关键函数执行形态，首发提审阶段建议关闭。Pass 6 在 7.2 之后不再只是传统 `strip`，还包含 export trie scrub，因此虽然仍远低于 text 重写/VMP 的审核敏感度，但在 Review Notes 中最好主动解释其目的仅为降低静态符号恢复和篡改成本。AppStore Safe Profile 关闭 Pass 1、Pass 2、Pass 8、Pass 9、Pass 12、Pass 13，保留 Pass 3/4/5/6/7/10/11，既能提供有效保护（完整性校验 + 数据加密 + 结构混淆 + 符号/导出可见性收敛 + anti-debug runtime gate + import/header 保护），又尽量不干扰苹果的审核流程。

### 11.4 渐进开启策略

对于首次提审的 App，推荐以下路径：

1. **首次提审**：使用 Profile B（AppStore Safe），确保顺利通过
2. **建立审核历史后**：下一版本开启 Pass 6 + Pass 5 + Pass 3（如果 Profile B 已包含则保持）
3. **稳定后**：逐步开启 Pass 1（字符串加密）
4. **完全稳定后**：开启 Pass 2（元数据擦除），达到 Full Armor 等级

每次升级之间至少间隔一个正常审核周期。苹果对已有审核历史的 App 后续更新的审核强度通常低于首次提审。

### 11.5 运行时能力的合规说明

除了构建时的 13 个 Pass，SDK 的 CRiskCore 运行时还包含以下能力：

| 运行时能力 | 实现 | 合规风险 | 建议 |
|-----------|------|---------|------|
| Mach-O Header 擦除 | `cprisk_erase_macho_header()` | 中高 — 阻碍内存 dump，但只影响运行时，不影响提审时静态分析 | 金融 App 可开；普通 App 谨慎 |
| JIT 按页解密 | `cprisk_jit_decrypt_page()` | 中 — `mprotect` 切换读写权限，不违反 W^X（不会同时可写可执行） | 可开，iOS 本身允许 `mprotect` |
| 空闲重加密 / guard page | `cprisk_text_encrypt_service_idle()` / `cprisk_guard_page_fault_notify()` | 中至高 — 明显属于高对抗 anti-dump 设计，需在 Review Notes 中解释其仅用于运行时完整性保护 | 金融 App / 高安全行业优先 |
| 异常端口保护 | `cprisk_register_exception_handler()` | 中 — 抢占 EXC_BREAKPOINT 处理权 | 可开，但可能影响苹果 crash reporting |
| 完整性重校验 | `cprisk_recheck_integrity()` | 低 — 标准反篡改手段 | 始终开启 |
| Anti-Debug | `cprisk_deny_attach()` | 低 — `ptrace(PT_DENY_ATTACH)` 是公开 API | 始终开启 |
| 反调试 Watchdog | `cprisk_start_anti_debug_watchdog()` | 低至中 — 周期性重调 `ptrace`、exception port、SIGTRAP、csops、硬件断点、软件断点、异常分发超时、双 watchdog 互监控、影子栈校验、deny-attach verify、AMFI / entitlement 异常位等，异常转 RiskSignal | 始终开启 |
| Pass 7 运行时消费 | 读取 `__DATA,__cpr_adbg7` 计划并做 anti-debug gate | 低至中 — 运行时会在关键点插入 gate，但仍明显弱于大规模机器码重写 | 金融 App 可开；普通 App 可随审核历史逐步启用 |
| Pass 10 导入恢复 | `cprisk_import_resolver.c` | 低 — 主要改变符号恢复方式，不新增数据采集 | 可开 |
| Pass 11 Header 恢复 | `cprisk_header_restore.c` | 低至中 — 影响镜像头字段恢复，但有 sanity fallback | 金融 App 可开；普通 App 视审核历史启用 |
| Pass 12 Text 恢复 | `cprisk_text_encrypt.c` | 中 — 代码页恢复链会引入更多审核解释成本，但不改变隐私边界 | 金融 App / 高安全场景优先 |
| Pass 13 VM 解释器 | `cprisk_vm_interpreter.c` | 高 — 高价值函数通过 VM 字节码执行，当前还包含多入口、多解释循环、HMAC self-check 与虚拟寄存器，需要在 Review Notes 中清楚说明其仅用于反篡改与反逆向 | 仅建议在已有审核历史或高安全行业启用 |
| 白盒表 ASLR 绑定 | `cprisk_whitebox.c` | 中 — 主要影响密钥/白盒内部求值路径，对隐私无直接新增，但会提高 reviewer 对“运行时自恢复/自解释”的敏感度 | 高安全场景优先 |
| Pass 9 CFF 运行时 | 源码级 CFF 状态机（CFFDispatcher / CFFStateCodec） | 低 — 纯逻辑层控制流编码，不新增系统调用或数据采集 | 始终开启（SDK 内嵌） |
| MIE / MTE 姿态（`MIEPostureDetector` + `AntiTamperingSignalProvider`） | 读取 `sysctl hw.optional.arm.FEAT_MTE*` 等设备级能力摘要；可选软信号说明进程级 tagging 不可由 sysctl 单独推断；通常仅 A17 / A17 Pro 及后续较新产品线更可能暴露相关位形 | 低 — 与设备能力查询同类，不读取用户内容；非全设备具备 OID 或非零读数，需按“安全降级”理解 | 默认开启；可按 `enableMIEPosture` 关闭 |

### 11.6 合规参考：同类商用 SDK 的保护等级

以下商用安全 SDK 均在 App Store 上正常运行，其保护手段覆盖范围等于或超过 cprisk-armor Full Armor：

| 商用 SDK | 代码混淆 | 字符串加密 | 数据加密 | 完整性校验 | 反调试 | 反 Hook | 反重打包 | 截屏防护 | 安全键盘 |
|---------|---------|-----------|---------|-----------|--------|---------|---------|---------|---------|
| **Promon SHIELD** | 控制流混淆 | 有 | 有 | 有 | 有 | 有 | 有 | 有 | 有 |
| **Guardsquare iXGuard** | 控制流 + 算术混淆 | 有 | 资源全量加密 | 有 | 有 | 系统库内存完整性 | 有 | 有 | — |
| **Appdome ONEShield** | 有 | 有 | 有 | 有 | 有 | 有 | 有 | 有 | 有 |
| **cprisk-armor (Full)** | 有限（Pass 8：1:1 等长指令替换；Pass 9：CFF 策略编排） | 有 | 数据段加密 | 三路径哈希 + HMAC + 白盒 PRF（6.5） | 有 | Prologue Guard | AppSigningIdentity（6.5） | — | — |

cprisk-armor 在控制流混淆、反重打包、截屏防护、安全键盘等方面比上述商用方案覆盖面更窄。苹果允许上述商用方案的全量保护通过审核，cprisk-armor 不会比它们更激进。

---

## 12. 当前 7.3 上架风险评估

这一节回答一个最实际的问题：**基于当前仓库状态，7.3 版本如果直接按 Full Armor 提审，审核风险到底有多大。**

### 12.1 先结论

当前 7.3 版本的风险结构可以概括为：

| 维度 | 当前判断 | 说明 |
|------|----------|------|
| **隐私合规风险** | 低到中 | SDK manifest 当前只覆盖 `Device ID`、`UserDefaults`、`SystemBootTime`，且 `NSPrivacyTracking = false`；只要宿主 App 正确承接 app-level manifest、权限说明与 App Privacy，隐私本身不是最大阻塞项 |
| **二进制审核风险** | 中到高 | Pass 6 export trie scrub、Pass 12 `TextSegmentEncryptor`、Pass 13 `VMProtector`、CPSV/CPSH 驱动的 VM self-check 与 handler 跨 TU 散布已经进入“改变代码可见形态与执行形态”的级别，会显著提高 reviewer 的解释成本 |
| **金融 / 高安全行业适配度** | 高 | 若业务场景本身就是反欺诈、账户安全、支付保护，这些机制较容易被接受 |
| **普通消费类 App 首发适配度** | 一般 | 若是工具、电商、内容、社交等普通消费类 App，首次提审不建议直接使用 Full Armor |

**建议性结论**：

1. **如果是金融、支付、企业安全、高风险账户防护场景**，可考虑带强 Review Notes 试 Full Armor，但仍建议优先评估是否先关闭 Pass 12/13。
2. **如果是普通 App、首发、没有审核历史**，不建议直接拿当前 Full Armor 版本提审。
3. **首发更稳妥的选择** 是使用前文的 `AppStore Safe` Profile，并把 `Pass 12/13` 继续保持关闭。

### 12.2 为什么当前主要风险不在隐私

从隐私与合规文档角度看，当前 7.3 版本已经具备以下基础条件：

- SDK 当前明确声明 `NSPrivacyTracking = false`
- 没有 `NSPrivacyTrackingDomains`
- Required Reason API 范围收敛在 `UserDefaults` 与 `SystemBootTime`
- SDK 级文档已经把“本地处理”和“宿主 App 是否上报”区分开

这意味着：

- 风险信号、行为摘要、设备状态是否被认定为“已收集并上传”，主要取决于**宿主 App 的接入方式**
- 只要宿主 App 正确补齐 `PrivacyInfo.xcprivacy`、`Info.plist` 权限说明、App Store Connect 中的 `App Privacy` 标签，**隐私本身通常可控**

因此，当前 7.3 的主要不确定性不在 manifest，而在 reviewer 对**保护强度是否“明显超过普通 App 常见做法”**的判断。

### 12.3 当前最敏感的审核点

从当前实现看，最需要谨慎面对 reviewer 的是以下六类机制：

| 风险点 | 当前状态 | 为什么敏感 |
|--------|----------|------------|
| **Pass 13 VMProtector** | 已上线，且含 M2/M3 + CPSV/CPSH self-check + 双主循环解释器 | 高价值函数已不再以原生 ARM64 直接暴露，而是通过 VM 跳板 + 自定义字节码执行；当前解释器路径更复杂，更容易被理解为“隐藏核心逻辑” |
| **Pass 12 TextSegmentEncryptor** | 已上线，且带空闲重加密 / guard page | `__TEXT.__text` 页级加密会让静态代码可见性明显下降，解释成本高于 import/header 级别保护 |
| **Pass 6 export trie scrub / Swift 可见性收敛** | 已上线 | 可执行文件的导出表与部分反射可见性被主动收敛，虽然不改业务逻辑，但会让 reviewer 更难从静态视角直接恢复符号 |
| **runtime anti-debug 组合** | 已上线 | 异常端口、watchdog、runtime gate、timing canary、Frida 指纹等叠加后，整体观感会偏“高对抗” |
| **解释器自身加固** | 已上线 | 解释器纳入 CFF 接线、dead handler、opaque predicate chain、CPSV/CPSH self-check、handler 跨 TU 散布后，已不再只是“普通防护逻辑”，而是明显具备反分析特征 |
| **白盒表 ASLR 绑定 / mini-VM bootstrap** | 已上线 | 这类机制虽然不新增隐私采集，但会让 reviewer 更关注“是否存在运行时自恢复、自解释、自隐藏逻辑” |

要注意的是：

- 这些点**不等于违规**
- 但它们会提高 reviewer 的不确定性
- 尤其在**普通 App 首发**场景下，更容易被要求解释

### 12.4 当前版本的适用建议

| 场景 | 直接使用 Full Armor 7.3 | 建议 |
|------|-------------------------|------|
| 金融 / 银行 / 支付 | 可考虑 | 建议准备完整 Review Notes，并做好被问询的准备；必要时优先灰度启用更激进的 guard page / 白盒表绑定 |
| 企业安全 / 账号高价值风控 | 可考虑 | 若业务定位明确，强保护通常更容易自洽 |
| 游戏反作弊 / 灰产对抗 | 视业务而定 | 若存在账户价值与攻击收益，可论证必要性 |
| 普通工具 / 内容 / 电商 / 社交首发 | 不建议 | 优先使用 `AppStore Safe`，关闭 Pass 12/13 |
| 已有多次稳定过审历史的老 App | 可逐步尝试 | 适合采用分阶段增配策略 |

### 12.5 首发提审推荐策略

如果目标是“**先稳过审，再逐步加固**”，推荐按下面节奏推进：

1. **首发版本**：使用 `AppStore Safe`，保持 `Pass 12/13` 关闭。
2. **拿到第一次通过记录后**：根据业务场景评估是否先启用 `Pass 8/9`。
3. **确认审核历史稳定后**：再评估 `Pass 12`。
4. **仅在高安全行业或已有充分审核历史时**：再启用 `Pass 13 VMProtector`。

对当前 7.3 来说，最保守也最稳妥的建议是：

> **首发不直接启用 Pass 12/13；把 VMP 与按页 text 恢复链作为第二阶段加固能力，而不是第一版即全量上线。**

### 12.6 提审前检查清单

若宿主 App 决定提审，建议在交付前逐项确认：

- 宿主 App 自己的 `PrivacyInfo.xcprivacy` 已承接 SDK 的 `Device ID` / `UserDefaults` / `SystemBootTime`
- 宿主 App 的 `App Privacy` 已根据“是否上传风险报告”做真实填写
- `NSMotionUsageDescription`、`NSFaceIDUsageDescription`、`LSApplicationQueriesSchemes` 等权限说明已按实际启用能力补齐
- Review Notes 已明确说明：这些能力仅用于 fraud prevention / runtime integrity / anti-tamper，不用于隐藏私有 API 或规避审核
- 已在真实 `iphoneos` Archive / TestFlight 路径上验证运行正常，而不是只在模拟器或本地 Release 构建验证
- 若是首发版本，已确认是否需要关闭 `Pass 12/13`

---

## 13. 常见误区

### 误区 4：壳加固后苹果一定会拒审

不对。
Promon SHIELD、Guardsquare iXGuard、Appdome ONEShield 等商用安全 SDK 的保护等级等于或超过 cprisk-armor，大量银行/支付/游戏 App 采用并在 App Store 正常运行。苹果拒审的理由是"私有 API / 隐藏功能 / 元数据欺骗"，不是"二进制有保护"。

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

## 14. 对外沟通时推荐怎么说

如果你把这份指南发给客户，最适合的一句话是：

> `CloudPhoneRiskKit` 已提供 SDK 级 privacy manifest 与合规说明；由于当前交付形态以静态集成为主，宿主 App 仍需在 app-level privacy manifest、App Privacy 标签、权限说明与审核备注中承接最终责任。

这句话既不会让客户误解成“全自动合规”，也不会显得 SDK 完全没准备。

---

## 15. 相关配套文档

建议与本指南一起放在 `CloudPhoneRiskKit_文档/` 目录中交付：

- `CloudPhoneRiskKit_SDK_隐私声明.md`
- `CloudPhoneRiskKit_使用说明.md`
- SDK 版本变更记录
- 宿主 App 接入 checklist

其中：

- 本指南回答“怎么接入才合规”
- SDK 隐私声明回答“SDK 自己到底收什么、为什么收”

这两份文档应该分开。
