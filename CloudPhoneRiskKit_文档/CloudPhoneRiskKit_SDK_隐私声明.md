# CloudPhoneRiskKit SDK 隐私声明

> 文档定位：`CloudPhoneRiskKit` 的 SDK 级隐私声明  
> 适用对象：SDK 接入方、法务/隐私团队、客户安全评审  
> 适用范围：iOS / iPadOS 端集成 `CloudPhoneRiskKit` 的场景  
> 说明：本文描述的是 **SDK 自身的处理边界**，不替代宿主 App 的隐私政策、App Privacy 标签或 App Review Information

---

## 1. 文档目的

`CloudPhoneRiskKit` 是一套面向业务风控场景的 iOS 端风险检测 SDK，主要用于识别：

- 越狱 / Hook / 动态注入
- 云手机 / 虚拟化 / 机房设备特征
- 设备完整性异常
- 行为异常与环境异常

为实现上述能力，SDK 会在设备侧采集、处理或生成部分风险相关数据。  
本声明的目标，是把以下问题说清楚：

1. SDK 自己会接触哪些数据
2. 这些数据是在本地处理，还是可能由宿主 App 上传
3. SDK 是否用于 tracking
4. 接入方还需要承担哪些隐私和合规责任

---

## 2. 核心结论

从 SDK 自身边界看，`CloudPhoneRiskKit` 的设计原则是：

1. **以设备安全与欺诈防护为目的**，而非广告跟踪或营销画像。
2. **优先本地处理**，由宿主 App 决定是否将风险报告或部分字段上传到服务端。
3. **不基于 ATT 语义进行 tracking**，当前 SDK 的 privacy manifest 中 `tracking = false`。
4. **对部分图计算字段采用单向哈希**，降低直接暴露原始标识的风险。

需要特别注意：

> SDK 是否“收集并上传”某类数据，最终取决于宿主 App 的集成方式和调用路径。  
> SDK 本身生成或持有某些字段，不等于这些字段一定会离开设备。

---

## 3. 当前 SDK 的 Privacy Manifest 声明

SDK 当前自带的 privacy manifest 文件位于：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Resources/PrivacyInfo.xcprivacy`

当前 manifest 声明了以下内容。

### 3.1 Collected Data

| 项目 | 当前声明 |
|------|----------|
| Data Type | `NSPrivacyCollectedDataTypeDeviceID` |
| Linked | `false` |
| Tracking | `false` |
| Purpose | `NSPrivacyCollectedDataTypePurposeFraudPrevention` |

### 3.2 Required Reason APIs

| API 类别 | Reason | 用途 |
|----------|--------|------|
| `NSPrivacyAccessedAPICategoryUserDefaults` | `CA92.1` | 本 App 范围内配置、缓存、降级状态保存 |
| `NSPrivacyAccessedAPICategorySystemBootTime` | `35F9.1` | 时序基线、反篡改、环境一致性判断 |

### 3.3 Tracking 立场

从当前 SDK manifest 与实现口径看：

- SDK **显式声明 `NSPrivacyTracking = false`**
- SDK **显式声明空的 `NSPrivacyTrackingDomains`**
- SDK **不以广告追踪为目的**使用所采集数据

---

## 4. SDK 可能处理的数据类型

下面按“数据类别”而不是“代码文件”来描述，这也是主流 SDK 对外文档更常见的写法。

### 4.1 设备标识类

SDK 可能处理以下设备级标识：

- 设备 ID（SDK 自建持久化 ID）
- `identifierForVendor`（若系统可提供）
- 硬件型号、系统版本、设备模型等设备画像字段

说明：

- SDK 的设备 ID 通过 `Keychain + UserDefaults 降级` 机制维护。
- 当 Keychain 与本地降级存储都不可可靠使用时，SDK 可能返回带 `ephemeral:` 前缀的临时 ID。
- 这些标识主要用于设备级风控、设备稳定识别、报告关联与信任等级判断。

### 4.2 设备环境与完整性类

SDK 可能处理以下环境风险数据：

- 越狱检测结果
- Hook / 注入 / anti-tamper 信号
- 网络环境信号（代理、VPN、网络接口异常）
- 设备/系统环境一致性信号
- 代码段完整性校验结果
- App Attest / 硬件信任根相关状态（若启用）

这些字段的共同特点是：

- 本质上属于**安全与风险信号**
- 默认服务于**欺诈防护、设备完整性判断、安全策略**
- 是否上报，由宿主 App 的接入策略决定

### 4.3 行为与传感器类

SDK 在启用对应能力时，可能处理：

- 触摸行为统计特征
- 运动传感器摘要
- 行为耦合特征
- 触摸力度方差、运动静止比例、运动能量等摘要

说明：

- 这部分能力通常需要宿主 App 在 `Info.plist` 中提供对应权限说明。
- 当前设计更偏向**摘要/统计量**，而非“完整行为录像式原始重建”。
- 是否离开设备，依赖宿主 App 是否将风险报告上传。

### 4.4 生物识别状态类

在启用生物识别状态探测能力时，SDK 可能处理：

- 是否已录入生物识别
- 生物识别是否可用
- 生物识别锁定状态

说明：

- 这部分不是读取用户的指纹/面容模板。
- SDK 只探测**能力状态**和**可用性状态**，用于风控判断。
- 宿主 App 需要配置 `NSFaceIDUsageDescription`。

### 4.5 网络与服务端关联类

如果宿主 App 开启远程配置或把服务端聚合信号回灌到 SDK，SDK 还可能处理：

- 公网 IP
- ASN / 运营组织
- 数据中心标记
- IP 聚合度 / 账号聚合度
- 地理区域标签
- 风险标签

说明：

- 这部分数据并不是 SDK 固定主动采集的全部内容。
- 很多字段来自宿主 App 或业务服务端回传。
- 因此它们在合规上常常同时属于“SDK 处理范围”和“宿主 App 最终责任范围”。

### 4.6 图特征与哈希特征

SDK 支持输出图计算相关特征，主要包括：

- 设备画像哈希
- IP 哈希
- ASN 哈希
- 账号 ID 哈希

其中当前实现明确写明：

- 对 IP、账号 ID 等敏感字段采用 **单向 SHA-256 哈希**
- 不直接在图特征结构中暴露原始值

需要注意：

- “哈希化”不等于“完全脱离隐私语境”
- 这些字段仍然可能被视为与设备或账户相关的风险数据

---

## 5. 本地处理 vs 可能上传

这部分是很多 SDK 文档里最关键但最容易写糊的地方。

### 5.1 默认可在本地完成的处理

SDK 可以在设备侧本地完成：

- 风险信号采集
- 风险评分
- 本地报告生成
- 本地缓存与安全存储
- 本地完整性校验

如果宿主 App 只做本地判定，不调用报告上传相关能力，那么很多数据可能**仅在设备上处理**。

### 5.2 在哪些情况下数据可能离开设备

当宿主 App 使用以下能力时，部分数据可能会被发送到业务服务端：

- `buildSecureReportEnvelope(...)`
- `buildSecureReportEnvelopeJSON(...)`
- `buildSecureReportEnvelopeGrpcCompatibleJSON(...)`
- `buildSecureReportEnvelopeGrpcRequestBytes(...)`
- 自定义上报 `CPRiskReport` / `ReportEnvelope` / `GrpcReportPayload`

一旦宿主 App 这么做，常见会离开设备的数据包括：

- 设备 ID
- 风险信号
- 设备画像摘要
- 行为摘要
- 服务端关联字段
- 可选的账号 ID / session ID / sceneTag

因此：

> SDK 是否“上传数据”不是一个只看 SDK 就能单独回答的问题，必须结合宿主 App 的调用方式来判断。

---

## 6. 可选能力与隐私边界

`CloudPhoneRiskKit` 不是所有能力默认都等价开启。  
从隐私合规角度，更合理的对外写法是：**按能力说明边界**。

### 6.1 行为采样能力

启用后，SDK 会处理触摸与运动相关摘要。  
宿主 App 应：

- 提供清晰权限文案
- 只在必要业务场景开启
- 在隐私政策中说明用途属于安全/风控

### 6.2 生物识别状态探测

启用后，SDK 会探测设备生物识别可用性状态。  
宿主 App 应：

- 配置 `NSFaceIDUsageDescription`
- 避免把该能力描述成“读取用户生物模板”

### 6.3 URL Scheme / 完整性探测

启用后，宿主 App 可能需要配置 `LSApplicationQueriesSchemes`。  
对外说明时应明确：

- 这些查询仅用于设备完整性验证
- 不用于营销或安装应用画像

### 6.4 远程配置与服务端聚合

如果宿主 App 配置了远程配置地址、证书固定、外部服务端信号注入，SDK 会参与：

- 配置拉取
- 配置签名校验
- 服务端风控上下文融合

这类能力意味着：

- 宿主 App 的隐私声明不能只写“纯本地处理”
- 宿主 App 需要对网络交互和服务端数据使用负责

---

## 7. SDK 不做的事情

为避免误解，SDK 级隐私声明里建议明确写出“不做什么”。

当前 SDK 口径下，不应将其描述为：

- 广告归因 SDK
- 广告追踪 SDK
- ATT tracking SDK
- 社交画像 SDK

更准确的说法是：

- 用于**设备完整性验证**
- 用于**风控与反欺诈**
- 用于**安全信号采集与风险决策**

---

## 8. 接入方仍需承担的责任

即使 SDK 已自带 privacy manifest，接入方仍需负责：

1. 宿主 App 的 `App Privacy` 标签填写
2. 宿主 App 的隐私政策
3. 宿主 App 的权限说明文案
4. 宿主 App 的审核备注
5. 静态集成场景下对 app-level privacy manifest 的承接

尤其在当前项目以**静态库 / 源码集成**为主的情况下，接入方不能误以为“SDK 带了 manifest 就自动全部覆盖”。

---

## 9. 推荐给客户的标准口径

如果要把这份声明发给客户，推荐用下面这种简洁表述：

> `CloudPhoneRiskKit` 是一款面向设备安全与欺诈防护的 iOS 风控 SDK。  
> SDK 可能在设备侧处理设备标识、环境完整性信号、行为摘要和可选的生物识别状态信号，用于风险识别与安全决策。  
> SDK 当前不以广告 tracking 为目的使用这些数据。  
> 是否将相关数据上传到服务端，取决于宿主 App 的具体集成方式和上报策略。

---

## 10. 配套关系

建议这份文档和下面两份配套使用：

- `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_AppStore_合规指南.md`
- 宿主 App 自身隐私政策 / App Privacy 填写文档

三者分工如下：

| 文档 | 作用 |
|------|------|
| SDK 隐私声明 | 说明 SDK 自己处理哪些数据、以什么目的处理 |
| App Store 合规指南 | 说明客户接入后，宿主 App 还需要做哪些声明和审核准备 |
| 宿主 App 隐私政策 | 面向终端用户，说明最终 App 的真实数据处理方式 |

---

## 11. 最后一句话

对于风控 SDK，最稳的隐私表述不是“我们什么都不收”，而是：

**把 SDK 在设备侧处理什么、哪些能力可选、哪些数据是否离开设备、最终由谁负责披露，说清楚。**
