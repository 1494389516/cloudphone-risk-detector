<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-5.2.0-FF3B30?style=for-the-badge" alt="SDK">
  <img src="https://img.shields.io/badge/SPM-Compatible-34C759?style=for-the-badge&logo=swift&logoColor=white" alt="SPM">
  <img src="https://img.shields.io/badge/License-Proprietary-8E8E93?style=for-the-badge" alt="License">
</p>

<h1 align="center">CloudPhoneRiskKit</h1>

<p align="center">
  <strong>iOS 端环境风险检测 SDK — 识别越狱、云手机、Hook 注入与机房设备</strong>
</p>

<p align="center">
  面向业务风控场景的本地信号采集与决策引擎，提供硬件指纹、行为熵分析、<br>
  反篡改对抗与场景化策略，帮助 App 在端侧完成高质量的环境风险判定。
</p>

---

## 项目速览

- **定位**：这是一个 iOS 端风控 SDK（`CloudPhoneRiskKit`）与示例应用（`RiskDetectorApp`）的组合仓库，重点做端侧环境风险识别。
- **核心能力域**：越狱/Hook/注入检测、行为信号分析、设备一致性校验、服务端聚合信号融合。
- **代码结构（高频目录）**：
  - `RiskDetectorApp/Sources/CloudPhoneRiskKit/`：SDK 主体（检测、决策、存储、上报、安全加固）。
  - `RiskDetectorApp/Sources/CloudPhoneRiskAppCore/`：应用层编排（配置加载、检测流程、报告摘要）。
  - `RiskDetectorApp/App/`：SwiftUI 示例 App（Dashboard、配置、结果展示、历史页）。
  - `RiskDetectorApp/Tests/CloudPhoneRiskKitTests/`：核心单元测试（决策树、策略、评分、信号模型）。
- **本地运行（SPM）**：在仓库根目录执行 `cd RiskDetectorApp && swift test` 可先验证核心逻辑测试。

## 版本演进

| 版本 | 定位 | 关键能力 |
|------|------|----------|
| 3.0 | 架构重建 | 四层检测体系、场景化决策树、信号状态模型 |
| 3.1 | 检测补强 | 关键符号扩展、trampoline 识别、路径判定强化 |
| 3.5 | **安全加固 + 检测能力补强** | DRM 等级检测、电池物理熵、RWX 内存扫描、字符串混淆、SVC 直调、PLT 完整性校验、HMAC 签名 |
| 3.5.1 | **图算法对接 + 代码段完整性** | 账号/会话绑定、行为向量导出、图特征反哺、__TEXT 段哈希校验 |
| 3.6 | **Frida 深度对抗** | 线程枚举异常、异常端口劫持、V8 堆特征、Stalker JIT 检测、ObjC Swizzle、Dispatch Queue 扫描、Unix Socket、时序侧信道（8 维全覆盖） |
| 3.7 | **SDK 自保护加固 + 全面纵深** | 基线迁移 Keychain、TLS 证书固定、PLT 持久化、ptrace 反调试、DYLD Interpose、SDK 二进制校验、传感器回放检测、GPU 深度探测、isa swizzling、消息转发检测、Keychain ACL、多路径一致性、指纹突变、随机化检测 |
| **4.0** | **双轮红队审计 + 全栈安全加固** | 竞态条件修复、时序侧信道消除、存储加密、配置签名验证、Provider 注册表强化、决策引擎加固、行为信号增强、检测超时机制（22 项安全漏洞全修复） |
| **4.1** | **第三轮红队审计 + 攻击链纵深封堵** | 配置缓存来源验签、HTTPS 强制、Provider 实例锁定、首跑基线防投毒、存储加密 Fail-Closed、DeviceHistory 迁移加密、ReportEnvelope 元数据入签名域、DetectorRegistry 封印（10 项结构性漏洞全修复） |
| **4.2** | **第四轮红队审计 + 信任根全面收紧** | 配置/策略双链 Release 禁 unverified fallback、安全地板扩展覆盖行为与越狱关键检测开关、DualPathValidator 接入核心 Detector、anti_tamper 结论消除分裂、基线首跑软信号化、deviceID 漂移修复、历史时钟回拨防御、CPRiskStore 暴露面收紧、EnvelopeSignature Release 强制 v2（8 项漏洞全修复） |
| **4.3** | **第五轮红队审计 + 对抗降维打击** | 锁屏 Keychain ACL 撕裂死锁修复、ConfigCache 并发状态机锁绕过修复、内存 AES 密钥明文残影消除、时间跳跃重放绕过修复、线程级异常与硬件断点劫持检测、匿名内存隐写扫描、ObjC Inline Hook 跳板拦截、fsid 沙盒视图隔离探测、指令计数器时序侧信道双路校验、底层 SVC 0x80 原生系统调用接入（11 项极深层漏洞修复） |
| **4.4** | **硬件信任根 + 执行流锁定 + 内存蜜罐反制** | Apple App Attest / Secure Enclave 硬件绑定签名、调用栈回溯 ROP/JOP 链检测、Syscall Canary 探针致盲感知、蜜罐内存页 SIGBUS 反 Dump、iOS 版本动态基线自适应、gRPC 传输层升级（7 项硬件级 + 执行流级深度加固） |
| **4.6** | **第六轮红队审计 + 硬件信任根全链加固** | App Attest TOCTOU 竞态消除 + attestation 入签名域、CallStack RTLD_NEXT 双路 + vm_region 交叉校验、蜜罐三页分散 + handler/保护位自检、金丝雀 DualPath 双路 + 随机探针池、ExpectedBaseline sysctl 双路版本、payload_sha256 上下文绑定、PAC vm_read_overwrite 安全读取（12 项漏洞全修复） |
| **4.7** | **Inline Hook 穿透 + 内核 Hook 侧信道 + 探针纵深** | LibcPrologueGuard 机器码入口校验（mach_vm_read_overwrite 检测 Dobby/Substrate 跳板）、KernelHookSideChannel 四策略内核 Hook 检测（时序分布 / inode 一致性 / 时钟交叉 / 返回值熵）、金丝雀探针池 5→16 + 动态路径 3 条 + 子集 6 选、DualPathValidator 三路验证（标准 / RTLD_NEXT / 入口完整性）、修正 SVC 0x80 声称为 Prologue Guard 实际机制（6 项深层加固） |
| **4.8** | **4.7 遗留安全隐患修复** | LibcPrologueGuard TOCTOU 消除（废弃静态缓存、30% 概率重扫）、SecureBuffer 密钥内存安全擦除、ProcessInfo 全面替换为 sysctl、越狱特征字符串全量混淆（ObfuscatedJailbreakStrings）、DetectorRegistry 统一 do-catch 容错 + 高危权重异常信号（5 项致命隐患全修复） |
| **4.9** | **信任根防投毒 + fail-open 全面封堵** | RTLD_NEXT fail-open 消除（安全路径失败不再回退普通 libc）、LibcPrologueGuard 50% 概率 + 5s 时间衰减 + tampered 联动清缓存、完整性基线首启/升级环境检查（可疑环境拒绝建基线 + 高危信号）、App Attest 静默降级消除（requireAttestation 强制模式 + attestation 一致性校验）、deviceID ephemeral 标记修正、replay store 时间轴 systemUptime→Unix 对齐（6 项结构性漏洞全修复） |
| **4.9.2** | **内存 Dump + 结构体恢复攻击面封堵** | ConfigSignatureVerifier 密钥 Keychain 按需加载、StorageIntegrityGuard/KeychainSalt/ReportEnvelope/ChallengeTrigger 密钥用后清零、SignedRiskConclusion 字符串插值 SecureScope、CPRiskKit/PolicyManager 敏感状态清理、Logger 敏感信息 DEBUG 限定（7 项内存安全加固） |
| **5.0** | **端侧信任根链 + 内存语义压缩 + 挑战闭环 + 图风控联动** | TrustChainManager / TrustLevel / KeyRotation 端侧信任根链、内存语义压缩快速判决（CompressedVerdictRule）、挑战式验证闭环、图风控联动（GraphFeatureCollector / GraphNodeDescriptor） |
| **5.1** | **vPhone 裸金属检测扩展** | PhysicalSensorProbe（CoreMotion 重力/加速度/陀螺仪/磁力计/气压计）、EnvironmentConsistencyProvider（热状态熵、电池状态转移、屏幕亮度熵）、HardwareCapabilityProvider（Haptic Engine、刷新率一致性、接近传感器）、NetworkInterfaceProvider（虚拟接口、MTU 异常、接口数量） |
| **5.2** | **云手机运维特征检测 + Impossible States** | DisplayMuxProvider（录屏/推流、外接显示器）、BiometricStateProvider（生物特征未录入/不可用）、AudioRouteProvider（USB 音频、虚拟声卡）、BasebandIsolationProvider（无蜂窝、系统 App 阉割）、Impossible States 五信号组合强制拦截 |

## 架构概览

```
┌──────────────────────────────────────────────────────┐
│                   业务应用层                           │
│            evaluate(scenario: .payment)               │
├──────────────────────────────────────────────────────┤
│               RiskDetectionEngine                     │
│   场景策略 ─ 决策树 ─ 组合规则 ─ 盲挑战 ─ HMAC 签名   │
│   安全地板强制 ─ 关键信号权重下限 ─ 异常容错链          │
├──────────┬───────────┬───────────┬───────────────────┤
│ Layer 1  │  Layer 2  │  Layer 3  │     Layer 4       │
│ 硬件指纹  │  一致性    │  行为熵    │   服务端聚合       │
├──────────┼───────────┼───────────┼───────────────────┤
│ GPU 名称  │ PLT/GOT   │ 触摸熵    │  公网 IP / ASN    │
│ DRM 等级  │ RWX 内存   │ 传感器熵   │  机房属性         │
│ 设备型号  │ Hook 检测  │ 电压方差   │  IP 聚合度        │
│ 电池计数器 │ 挂载点     │ 时序模式   │  图特征反哺       │
│ Board ID │ SVC 双路   │ 耦合分析   │  风险标签         │
│          │ 代码段哈希  │ 行为充足性  │  黑名单           │
│          │ 线程枚举   │           │                   │
│          │ 异常端口   │           │                   │
│          │ V8 堆检测  │           │                   │
│          │ ObjC Swizzle│          │                   │
│          │ Socket 检测 │          │                   │
│          │ 时序侧信道  │           │                   │
│ 指纹突变  │ DYLD Interpose│        │                   │
│          │ SDK 自校验  │           │                   │
│          │ ptrace 防附加│          │                   │
│          │ 多路径一致性 │           │                   │
└──────────┴───────────┴───────────┴───────────────────┘
```

### 信号三分类

| 类型 | 判定方式 | 典型信号 | 权重 |
|------|----------|----------|------|
| **硬信号** | 本地独立判定，单点即可触发 | 越狱、DRM 降级、ChargeCounter 异常、PLT 篡改、ObjC Swizzle、异常端口劫持、SDK 二进制替换、DYLD Interpose | 80-100 |
| **软信号** | 需结合场景综合评分 | VPN、行为异常、电压方差低、挂载点异常、时序侧信道、线程枚举异常、指纹突变、随机化检测、行为数据不足 | 30-75 |
| **服务端信号** | 依赖外部聚合 | 机房 IP、ASN 黑名单、IP 设备聚合度、图社区风险、硬件画像聚集 | 55-100 |

---

## 5.0 新增能力 — 端侧信任根链、内存语义压缩、挑战闭环与图风控联动

5.0 引入端侧信任根链、内存语义压缩快速判决、挑战式验证闭环与图风控联动四大能力。

### 5.0 新特性摘要

| 能力域 | 核心组件 | 说明 |
|--------|----------|------|
| **端侧信任根链** | `TrustChainManager`、`TrustLevel`、`KeyRotationPolicy` | 建立 Secure Enclave → App Attest → DeviceKey → SessionKey → ReportSignature 完整信任传递链；TrustLevel（hardware/derived/degraded）供服务端调整决策权重；KeyRotation 支持服务端下发轮换策略 |
| **内存语义压缩快速判决** | `CompressedVerdictRule`、`SignalCompressor` | 8 字节压缩摘要位向量规则，支持 layer 1–4 及 crossLayer 快速判决通道，服务端可配置 bitMask/matchValue 实现低延迟拦截 |
| **挑战式验证闭环** | `ChallengeSession`、`ChallengeResultStore`、`ChallengeTrigger` | 盲挑战从下发、执行到结果落库的完整闭环，支持 seed 与设备指纹绑定防重放 |
| **图风控联动** | `GraphFeatureCollector`、`GraphNodeDescriptor`、`GraphRiskFeedback` | 端侧产出标准化图节点描述符（单向哈希），服务端可直接入图；支持社区风险、硬件画像等反哺 |

---

## 5.1 新增能力 — vPhone 裸金属检测扩展

5.1 针对裸金属/真机云手机（数据中心机架上的真实 ARM 主板）新增物理环境与硬件能力检测维度。

### 5.1 新特性摘要

| 能力域 | 核心组件 | 说明 |
|--------|----------|------|
| **物理传感器深度探测** | `PhysicalSensorProbe` | CoreMotion 重力矢量锁定、加速度噪底、陀螺仪零漂、磁力计地磁场、CMAltimeter 气压计；机架固定设备与真人手持的 MEMS 特征差异 |
| **环境一致性检测** | `EnvironmentConsistencyProvider` | 热状态熵（工业冷却恒定）、电池状态转移（机架供电）、屏幕亮度熵（无环境光传感器） |
| **硬件能力交叉验证** | `HardwareCapabilityProvider` | Haptic Engine、刷新率与机型一致性（Pro 应为 120Hz）、接近传感器可用性 |
| **网络接口指纹** | `NetworkInterfaceProvider` | 虚拟接口（bridge/tap/tun）、MTU 异常、接口数量异常、缺少蜂窝 |

---

## 5.2 新增能力 — 云手机运维特征检测与 Impossible States

5.2 针对云手机在运维和交互层面的必然妥协，新增显示推流、生物安全引擎、音频路由、基带孤岛四类检测，并实现「不可思议组合」强制拦截规则。

### 5.2 新特性摘要

| 能力域 | 核心组件 | 说明 |
|--------|----------|------|
| **显示推流检测** | `DisplayMuxProvider` | UIScreen.isCaptured（录屏/推流）、screens.count > 1（外接 HDMI 采集卡） |
| **生物安全引擎** | `BiometricStateProvider` | LAContext 探测 biometryNotEnrolled/biometryNotAvailable，机架设备常未录入或硬件缺失 |
| **音频路由** | `AudioRouteProvider` | USB 音频、虚拟声卡输出，CarPlay 场景排除 |
| **基带孤岛** | `BasebandIsolationProvider` | 无蜂窝运营商、系统 App（Watch/Health）被阉割 |
| **Impossible States** | ComboRule | screen_captured + battery_state_static + usb_audio_routed + no_cellular_provider + biometric_not_enrolled 五信号同时命中时强制 block |

### 压缩摘要扩展

- mappingVersion 1.1：digest 由 8 字节扩展为 9 字节，bits 12–15 映射 5.2 新信号，byte 8 承载行为熵。

---

## 项目结构

```
RiskDetectorApp/
├── App/                              # SwiftUI 示例应用
├── Sources/
│   ├── CloudPhoneRiskAppCore/        # 应用层编排 (配置/检测/摘要)
│   └── CloudPhoneRiskKit/            # SDK 主体
│       ├── Detection/
│       │   ├── AntiBypass/           # 反篡改 & 抗绕过检测器
│       │   ├── Behavior/            # 行为信号 (触摸/传感器/时序)
│       │   ├── Environment/         # 环境检测 (越狱/挂载/沙盒)
│       │   └── Hardware/            # 硬件信号 (GPU/DRM/电池/Board)
│       ├── Device/                   # 设备标识 & Keychain
│       ├── Engine/                   # 决策引擎 & 场景策略
│       ├── Provider/                 # 信号 Provider 注册表
│       ├── Risk/                     # 报告封装 & 签名验证
│       ├── Storage/                  # 加密存储 & 历史管理
│       └── Util/                     # 工具 (SVC直调/混淆/加密)
└── Tests/                            # 单元测试
```

---

## 检测器总览

| 检测域 | 数量 | 说明 |
|--------|------|------|
| 越狱检测 | 11 个 Detector | 路径/符号/挂载点/沙盒/环境变量/文件权限/dylib/链接器/URL Scheme/fork/写入测试 |
| 反篡改 & 抗绕过 | 22+ 个 Detector | PLT/GOT、RWX 内存、ObjC Swizzle、DYLD Interpose、线程枚举、异常端口、V8 堆、Socket、时序侧信道、SDK 二进制校验、代码段哈希、LibcPrologueGuard、DualPathValidator、SVC 直调、匿名内存隐写、ObjC Inline Hook 跳板、fsid 隔离探测、指令计数器双路校验、ptrace 反调试 |
| 设备 & 环境信号 | 5 个 Provider | GPU 深度探测、DRM 等级、电池物理熵、Board ID、指纹突变 / 随机化检测 |
| 硬件信任根 | 2 个 | App Attest（TOCTOU 安全 + 强制模式）、Secure Enclave 硬件绑定签名 |
| 执行流检测 | 2 个 | CallStack 回溯 ROP/JOP 链检测、Syscall Canary 探针致盲感知 |
| 内存蜜罐 | 1 个 | HoneypotMemory 三页分散 + SIGBUS handler 自检 + 保护位验证 |
| 内核 Hook 侧信道 | 4 策略 | KernelHookSideChannel — 时序分布 / inode 一致性 / 时钟交叉 / 返回值熵 |
| 行为信号 | 3 个 Provider | 触摸熵、传感器熵、电压方差（含回放检测） |
| 服务端聚合 | 4 维 | 公网 IP/ASN、机房属性、IP 设备聚合度、图特征反哺 |

---

## 安全设计概要

SDK 采用纵深防御架构：**字符串全量混淆**（`ObfuscatedJailbreakStrings`）防止静态特征提取；**DualPathValidator 双路/三路验证**确保检测结果不被单点绕过；**HMAC-SHA256 签名**覆盖报告全字段防篡改；**Keychain + AES-GCM 加密存储**保护本地数据与历史记录；**配置签名信任链**（远端 → 缓存 → 运行时）杜绝配置注入；**__TEXT 段哈希 + SDK 二进制完整性校验**检测代码篡改；**Provider 注册表封印 + 实例锁定**防止运行时替换；**Frida 五维对抗**（线程 / 端口 / V8 堆 / Socket / 时序）全覆盖；**LibcPrologueGuard + KernelHookSideChannel** 实现 Inline Hook 穿透与内核级 Hook 侧信道检测；**IntegrityBaselineEnvCheck** 首启环境把关防止基线投毒；**App Attest 强制模式** 消除所有静默降级路径。

---

## 文档索引

| 文档 | 路径 |
|------|------|
| SDK 使用与构建说明 | `CloudPhoneRiskKit_使用说明.md` |
| 项目技术文档 | `RiskDetectorApp/RiskDetectorApp项目文档.md` |
| 架构设计 | `RiskDetectorApp/docs/architecture-design.md` |
| API 设计 | `RiskDetectorApp/docs/api-design.md` |
| 模块依赖 | `RiskDetectorApp/docs/module-dependencies.md` |

---

## 构建

```bash
cd RiskDetectorApp && swift build
```

---

## 免责声明

本 SDK 仅用于合法合规的应用安全与风控场景。使用者须确保符合当地法律法规及 Apple 开发者协议。作者不对因滥用本工具造成的任何后果承担责任。SDK 的检测结果为辅助判定信号，不构成最终风控决策，建议结合服务端策略综合使用。

---

<p align="center"><sub>CloudPhoneRiskKit 5.2.0 — Display Mux, Biometric State, Audio Route, Baseband Isolation, Impossible States</sub></p>
