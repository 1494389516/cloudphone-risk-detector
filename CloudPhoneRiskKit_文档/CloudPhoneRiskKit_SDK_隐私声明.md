# CloudPhoneRiskKit SDK 隐私声明

> 文档定位：`CloudPhoneRiskKit` 的 SDK 级隐私声明  
> 适用版本：SDK 7.3  
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

> **① SDK 不会触发 ATT（广告追踪弹窗）。** manifest 中 `NSPrivacyTracking = false`，不存在 `NSPrivacyTrackingDomains`，不请求广告追踪授权。宿主 App 集成本 SDK 不会因此被要求向用户弹出 ATT 权限框。
>
> **② SDK 的 manifest 是宿主 App 合规的参考基线，不是宿主 App 的 Privacy Label。** 宿主 App 必须在自己的 app-level `PrivacyInfo.xcprivacy` 中手工承接 `DeviceID`、`UserDefaults`、`SystemBootTime` 这三项。静态库 / 源码集成下 Xcode 不会自动合并，需宿主 App 主动完成。
>
> **③ 风险报告上传会改变 Privacy Label 的填写要求。** 如果宿主 App 调用 `buildSecureReportEnvelope` 等接口上传风险报告，App Store Connect 中的 `DeviceID` 条目**必须声明**，`Linked` 字段取决于是否与账号 ID 一同上传（若是，应填 `true`）。
>
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

### 3.4 7.3 版本升级是否改变隐私声明范围

不会。

7.3 继承 7.1 / 7.2 的 VM self-check / dispatcher / MIE 姿态等基线，对外文档与 `Version.current` 对齐；能力侧仍强调**设备安全姿态探测、运行时完整性校验和构建产物可见性收敛**，例如：

- `MIEPostureDetector` / `cprisk_mte_guard`：通过 `sysctl` 读取设备级 MTE/PAuth 能力摘要，并配合本地 snapshot / canary 生成安全姿态信号
- Pass 6 在 `MH_EXECUTE` 上扩展为 **符号表清理 + export trie scrub**，降低 IDA/Hopper 通过导出表恢复函数名的能力
- Release 构建启用 `SWIFT_REFLECTION_METADATA_LEVEL=minimal`，并继续通过关键类的 `@objc(CPR_...)` 别名压缩 Swift / ObjC 暴露面
- watchdog 引入 Mach port mailbox peer-liveness、PAC bridge 线程入口校验、更多 exception / software breakpoint / timeout 维度
- VM region image 白名单差异比对、`user_tag` 精细化扫描、SVC 桩代码页 hash 滚动校验
- 白盒 PRF 与被动完整性信号、runtime material 的耦合进一步加强

这些能力会增强 SDK 的反调试、反篡改和逆向对抗强度，并改变二进制在静态视角下的可见性，但**不会新增 privacy manifest 中的 collected data 类型，也不会新增 Required Reason API 类别**。因此从隐私边界上看，7.3 仍然以 `Device ID`、`UserDefaults`、`SystemBootTime` 这三项 manifest 事实为基线。

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
- 反调试 watchdog 信号（如被调试、exception port 异常、硬件断点、软件断点、`csops` 调试态、异常分发超时、双 watchdog 互监控、影子栈校验）
- `deny_attach` 生效回溯验证、`task_for_pid` 异常成功、AMFI / entitlement 异常位
- Frida/Gum/Gadget 模块特征（如已加载 image 名、可疑 Mach-O section 名、只读字符串片段）
- guard page 命中、按页解密/重加密状态、VM 自校验状态、解释器路径异常
- Mach port mailbox 心跳、PAC 线程入口桥、VM region image 白名单差异、镜像外匿名可执行页、SVC 桩整页 hash/滚动校验结果
- 白盒 PRF 退化/绑定状态、runtime material 完整性结果、MIE/MTE 安全姿态与 canary 状态
- **内存完整性 / MTE 姿态（`MIEPostureDetector`）**：在支持的系统上，仅通过内核导出的 `sysctl`（如 `hw.optional.arm.FEAT_MTE*` 等 OID）读取**设备级硬件能力摘要**，用于本地安全姿态评估与反篡改信号的轻量上下文加权；**不读取通讯录、照片、消息等用户内容**，也不访问应用沙箱内的用户文件。该能力通常只会在 **A17 / A17 Pro 及后续较新产品线**上更可能观察到相关位形，最终仍以系统实际导出的 OID 与数值为准。

这些字段的共同特点是：

- 本质上属于**安全与风险信号**
- 默认服务于**欺诈防护、设备完整性判断、安全策略**
- 是否上报，由宿主 App 的接入策略决定

补充说明：

- `FridaModuleDetector` 主要检查**当前进程已加载模块与只读段内容**，用于识别 Frida/Gum/Gadget 注入痕迹，不读取用户文件内容，也不扩大对外网络发送的数据范围。
- 新增的 watchdog / software breakpoint / exception timeout / guard page / deny-attach verify / HMAC self-check / SVC page-hash / VM image whitelist / MIE posture 探针，本质上仍属于**运行时完整性状态**，不是新的个人信息类别。

**关于 MIE / MTE（含 Apple 在 sysctl 中暴露的 EMTE 相关位形）的补充说明**：

- 该能力依赖**A17 / A17 Pro 及后续较新 Apple 芯片与对应系统**对 ARM 内存标记扩展（MTE）等能力的导出与兼容；**并非所有设备、并非所有系统版本**都会暴露相同的 `sysctl` OID 或非零读数。
- 在不支持或 OID 不可读时，SDK **安全降级**为较低姿态层级（例如仅反映 PAC/PAuth 路径），**不会**为了“凑齐”能力而采集额外敏感个人信息或用户内容。
- 输出语义为**本地安全姿态探测 / 运行时防护增强的上下文**，用于解释与加权部分风险信号；**不等于**读取用户数据、也不构成对用户存储的扫描。

### 4.2a 构建产物可见性收敛（新增）

除运行时安全信号外，7.3 当前交付版还会在 Release / 壳后产物上体现一些**“可见性收敛”**能力，例如：

- Pass 6 对 `MH_EXECUTE` 执行 `LC_SYMTAB` 清理、旧 `LINKEDIT` payload 覆写，以及 export trie scrub
- Swift Release 构建使用 `SWIFT_REFLECTION_METADATA_LEVEL=minimal`
- 关键对外暴露类维持 `@objc(CPR_...)` 别名，而不是直接暴露完整 Swift 类名

这类能力的边界需要单独说明：

- 它们作用于**代码、元数据和导出表的静态可见性**
- 目的是**降低逆向恢复与篡改成本**
- **不新增用户数据采集**
- **不改变 privacy manifest 的 collected data / Required Reason API 范围**

### 4.3 行为与传感器类

SDK 在启用对应能力时，可能处理：

- 触摸行为统计特征（坐标分布、点击间隔变异系数、滑动线性度）
- 触控压力方差（`forceVariance`）、接触半径方差（`radiusVariance`）、滑动速度变异系数（`swipeSpeedCV`）
- 运动传感器摘要（静止比例、运动能量）
- 行为耦合特征（触控-运动相关性）

说明：

- 这部分能力通常需要宿主 App 在 `Info.plist` 中提供对应权限说明。
- 当前设计更偏向**摘要/统计量**，而非"完整行为录像式原始重建"。
- 是否离开设备，依赖宿主 App 是否将风险报告上传。

### 4.3a 硬件物理指纹类（新增）

SDK 引入了以下基于物理硬件的指纹采集能力：

- **GPU 渲染指纹**（`GPURenderFingerprintProvider`）：通过 Metal Compute Shader 渲染固定模式，读取像素并计算 SHA-256，用于检测虚拟 GPU / 模拟器渲染器。指纹数据为哈希摘要，不包含用户内容。
- **IMU 噪声谱指纹**（`IMUNoiseSpectrumProvider`）：采集加速度计数据，经 FFT 频域分析生成噪声谱特征摘要，检测合成 / 注入运动数据。指纹数据为频谱统计摘要。

说明：

- 两类指纹均仅反映**硬件物理特性**，不采集用户内容或位置信息。
- 结果在进程内缓存，不重复触发采样。
- 模拟器环境下两个 Provider 均返回 `unavailable`，不产生指纹数据。

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

### 5.3 一个最容易误判的点

很多客户会把“SDK 在本地看到了什么”与“宿主 App 实际对外发送了什么”混为一谈。更稳妥的理解方式是：

- SDK 本地为了做风控而读取、计算、比对某些信号，并不等于这些信号一定会离开设备
- 只有当宿主 App 选择上报 `CPRiskReport`、`ReportEnvelope`、`GrpcReportPayload` 或自定义抽取其中字段时，相关数据才进入宿主 App 的对外披露范围
- 7.3 交付中的 runtime gate / text 加密 / VMP 保护 / export trie scrub / Swift 可见性收敛 / MIE posture 只增强代码保护与本地安全姿态判断，不会单独增加新的用户数据出境路径

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

### 6.3a 反调试与模块内存探测

SDK 当前会在本地执行更强的运行时完整性探测，包括：

- 反调试 watchdog 周期性探针（含双 watchdog 互监控、影子栈校验）
- Frida/Gum/Gadget 模块名、section 名、字符串片段匹配
- 检测顺序稳定随机化（按设备与策略种子改变 detector 执行顺序）

这类能力的隐私边界需要这样理解：

- 它们主要读取**当前进程自身的运行时状态、内存布局和完整性信号**
- 不会因为启用这些能力而新增广告跟踪语义
- 不会直接引入新的用户可识别数据类别
- 是否上报这些检测结果，仍由宿主 App 的风险报告上报策略决定

### 6.4 远程配置与服务端聚合

如果宿主 App 配置了远程配置地址、证书固定、外部服务端信号注入，SDK 会参与：

- 配置拉取
- 配置签名校验
- 服务端风控上下文融合

这类能力意味着：

- 宿主 App 的隐私声明不能只写“纯本地处理”
- 宿主 App 需要对网络交互和服务端数据使用负责

### 6.5 权限与隐私边界不要混写

接入方在对外文档里，最好把下面三件事分开写：

1. **privacy manifest 事实**：当前 SDK 自声明的是 `Device ID`、`UserDefaults`、`SystemBootTime`
2. **系统权限说明**：例如 `NSMotionUsageDescription`、`NSFaceIDUsageDescription`
3. **App Privacy / 隐私政策**：取决于宿主 App 是否把风险报告、行为摘要、环境信号上传到服务端

这样能避免客户把“需要权限说明”误解成“SDK manifest 已经声明了这类 collected data”，也能避免把安全实现细节误写成隐私采集范围。

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
- 用于**识别动态注入、Frida 模块加载与调试篡改**

另外，`cprisk-armor` 的 Pass 6 `SymbolStripper + ExportTrieScrubber`、Pass 7 `AntiDebugInjector`、Pass 8 `InstructionSubstitution`、Pass 9 `ControlFlowOrchestrator`、Pass 10 `ImportEncryptor`、Pass 11 `HeaderEncryptor`、Pass 12 `TextSegmentEncryptor` 与 Pass 13 `VMProtector` 都属于**构建期二进制保护能力**。其中 Pass 6 现在不仅清理 `LC_SYMTAB`，还会在 `MH_EXECUTE` 上清理 export trie；Pass 7 负责写入 anti-debug metadata ABI 并驱动运行时 gate，Pass 8 负责对 `__TEXT.__text` 中的安全 ARM64 指令子集做 1:1 等长语义等价替换，Pass 9 负责对策略编排的函数执行控制流平坦化，Pass 10/11 分别负责导入表与 header 关键字段的加密/恢复，Pass 12 负责对 text 页执行加密元数据编排并配合运行时按页解密/空闲重加密，Pass 13 则把部分高价值函数转成 VM 字节码并由解释器执行；当前还配套 `SWIFT_REFLECTION_METADATA_LEVEL=minimal`、`__swift5_mdvsk` 自校验元数据、白盒表 ASLR 绑定、字符串 lazy decrypt 与 bootstrap mini-VM。它们均不会新增终端用户数据采集，只影响构建产物的代码与元数据形态，因此不改变 SDK 的隐私数据边界。

---

## 8. 接入方仍需承担的责任

即使 SDK 已自带 privacy manifest，接入方仍需负责：

1. 宿主 App 的 `App Privacy` 标签填写
2. 宿主 App 的隐私政策
3. 宿主 App 的权限说明文案
4. 宿主 App 的审核备注
5. 静态集成场景下对 app-level privacy manifest 的承接

尤其在当前项目以**静态库 / 源码集成**为主的情况下，接入方不能误以为“SDK 带了 manifest 就自动全部覆盖”。

### 8.1 当前 7.3 版本的额外提醒

从当前 7.3 版本的整体风险结构看，接入方需要区分两件事：

1. **隐私合规**
2. **App Store 对二进制保护强度的接受度**

就 SDK 隐私边界本身而言，当前 7.3 版本并没有因为 Pass 6 export trie scrub、Swift metadata 可见性收敛、Pass 12 `TextSegmentEncryptor`、Pass 13 `VMProtector`、CPSV span map 驱动 self-check、CPSH/HMAC expect blob、handler 跨编译单元散布、guard page anti-dump、白盒表 ASLR 绑定、Mach port watchdog、SVC page hash 或 bootstrap mini-VM 而新增新的 collected data 类型，也没有扩大 Required Reason API 范围。因此：

- 7.3 的主要新增风险**不是隐私类型扩张**
- 而是宿主 App 是否选择启用更强的二进制保护后，带来额外的审核解释成本
- 当前项目比早期 7.0/7.1 文档所描述的 Full Armor 更进一步，已经落到“符号表 + export 双路径可见性收敛、按页代码恢复、guard page 反 dump、CPSV/CPSH 驱动 self-check、白盒表绑定、跨 TU handler 散布、Mach port watchdog、SVC page hash”这一层，审核备注和交付说明需要比之前写得更明确

也就是说：

> **隐私文档回答的是“收什么、为什么收、谁来披露”；是否适合直接带 Full Armor 版本上架，则应优先参考 `CloudPhoneRiskKit_AppStore_合规指南.md` 中的 7.3 上架风险评估章节。**

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
