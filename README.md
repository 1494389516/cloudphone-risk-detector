<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-3.7-FF3B30?style=for-the-badge" alt="SDK">
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

## 版本演进

| 版本 | 定位 | 关键能力 |
|------|------|----------|
| 3.0 | 架构重建 | 四层检测体系、场景化决策树、信号状态模型 |
| 3.1 | 检测补强 | 关键符号扩展、trampoline 识别、路径判定强化 |
| 3.5 | **安全加固 + 检测能力补强** | DRM 等级检测、电池物理熵、RWX 内存扫描、字符串混淆、SVC 直调、PLT 完整性校验、HMAC 签名 |
| 3.5.1 | **图算法对接 + 代码段完整性** | 账号/会话绑定、行为向量导出、图特征反哺、__TEXT 段哈希校验 |
| 3.6 | **Frida 深度对抗** | 线程枚举异常、异常端口劫持、V8 堆特征、Stalker JIT 检测、ObjC Swizzle、Dispatch Queue 扫描、Unix Socket、时序侧信道（8 维全覆盖） |
| 3.7 | **SDK 自保护加固** | 基线存储迁移 Keychain、ptrace 反调试、DYLD_INTERPOSE 检测、SDK 二进制完整性校验、多路径一致性检测、指纹突变检测、随机化检测接入、调试开关安全化 |

## 架构概览

```
┌──────────────────────────────────────────────────────┐
│                   业务应用层                           │
│            evaluate(scenario: .payment)               │
├──────────────────────────────────────────────────────┤
│               RiskDetectionEngine                     │
│   场景策略 ─ 决策树 ─ 组合规则 ─ 盲挑战 ─ HMAC 签名   │
├──────────┬───────────┬───────────┬───────────────────┤
│ Layer 1  │  Layer 2  │  Layer 3  │     Layer 4       │
│ 硬件指纹  │  一致性    │  行为熵    │   服务端聚合       │
├──────────┼───────────┼───────────┼───────────────────┤
│ GPU 名称  │ PLT/GOT   │ 触摸熵    │  公网 IP / ASN    │
│ DRM 等级  │ RWX 内存   │ 传感器熵   │  机房属性         │
│ 设备型号  │ Hook 检测  │ 电压方差   │  IP 聚合度        │
│ 电池计数器 │ 挂载点     │ 时序模式   │  图特征反哺       │
│ Board ID │ SVC 双路   │ 耦合分析   │  风险标签         │
│          │ 代码段哈希  │           │  黑名单           │
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
| **软信号** | 需结合场景综合评分 | VPN、行为异常、电压方差低、挂载点异常、时序侧信道、线程枚举异常、指纹突变、随机化检测 | 30-75 |
| **服务端信号** | 依赖外部聚合 | 机房 IP、ASN 黑名单、IP 设备聚合度、图社区风险、硬件画像聚集 | 55-100 |

## 3.5 新增能力

### 检测维度扩展

| 能力 | 优先级 | 层级 | 原理 |
|------|--------|------|------|
| **DRM 等级检测** | P0 | Layer 1 | FairPlay/AVContentKeySession 探测硬件安全解码能力，L3 或失败即高风险 |
| **电池 ChargeCounter** | P0 | Layer 1 | 硬件寄存器值 -1 或 0 = 未实现 = 云机特征，误杀率极低 |
| **电压时序方差** | P0 | Layer 3 | 100ms 间隔 5 次采样，方差接近 0 = 返回固定模拟值 |
| **匿名 RWX 内存扫描** | P0 | Layer 2 | `vm_region_64` 检测 Frida trampoline 页（匿名 + rwx） |
| **挂载点异常检测** | P1 | Layer 2 | `getmntinfo()` 双向校验：虚拟化 FS 黑名单 + 必需挂载白名单 |

### 安全加固

| 能力 | 优先级 | 说明 |
|------|--------|------|
| **字符串多段混淆** | P0 | 每个敏感字符串独立混淆（XOR / ROT13 / Caesar / Base64 / 逆序），不存在统一解密入口 |
| **SVC 直调加固** | P0 | `sysctlbyname` / `stat` 通过 RTLD_NEXT 绕过 PLT hook，双路验证检测篡改 |
| **PLT/GOT 完整性** | P0 | 10 个关键函数的地址基线校验，`dladdr` + Mach-O `.text` 段范围验证 |
| **内存安全清零** | P0 | `SecureBuffer` / `SecureString` 使用 `memset_s` 防编译器优化，用完即销毁 |
| **上报语义混淆** | P1 | 字段名运行时映射 + 10-15 个诱饵字段注入，攻击者无法区分真伪 |
| **HMAC 结论签名** | P1 | HKDF-SHA256 派生设备密钥 + HMAC-SHA256 签名，服务端验签防篡改 |
| **Release 日志禁用** | P0 | 生产构建自动禁用所有日志输出，避免 panic 路径泄露信息 |
| **代码段哈希校验** | P0 | 首次运行建立 __TEXT.__text SHA-256 基线，后续校验检测 inline hook，LC_UUID 跟踪版本变更 |

## 3.5.1 新增能力

### 图算法数据对接

| 能力 | 说明 |
|------|------|
| **账号/会话绑定** | `bindAccount` / `unbindAccount` 将业务账号 ID 写入上报 Payload，打通设备-账号关联图 |
| **行为向量导出** | 6 维归一化行为向量（触摸扩散/间隔CV/线性度/力方差/静止比/运动能量）自动写入 Payload，用于行为相似度计算 |
| **图特征反哺** | `setGraphFeatures` 接收服务端图分析结果（社区 ID、风险密度、硬件画像聚集度、PageRank、密集子图标记），自动生成 `graph_community_risk` / `graph_hw_profile_cluster` / `graph_dense_subgraph` 信号参与评分 |

### 代码段完整性校验

| 能力 | 优先级 | 层级 | 原理 |
|------|--------|------|------|
| **__TEXT.__text 哈希** | P0 | Layer 2 | 首次运行建立 SHA-256 基线，后续校验检测 inline hook / 指令替换。通过 `LC_UUID` 跟踪二进制版本变更，`LC_ENCRYPTION_INFO` 处理 FairPlay 加密 |

## 3.6 新增能力 — Frida 深度对抗（8 维全覆盖）

3.6 版本从 **进程、内存、运行时、网络、时序** 五个维度构建 Frida 检测纵深，将检测绕过成本从"改一行脚本"提升到"重写注入框架"。

### 检测器矩阵

| 检测器 | 检测维度 | 优先级 | 绕过难度 | 原理 |
|--------|----------|--------|----------|------|
| `FridaThreadDetector` | 线程枚举异常 | P0 | 高 | `task_threads()` + `pthread_getname_np()` 检测 gum-js-loop / gmain / gdbus 等 Frida 线程；线程数 > 25 辅助判定 |
| `FridaThreadDetector` | 异常端口劫持 | P0 | 极高 | `task_get_exception_ports()` 检测非空异常处理端口，Frida 必须接管异常才能实现 Interceptor |
| `FridaHeapDetector` | V8/QuickJS 堆特征 | P0 | 高 | `vm_region_64` 扫描匿名 rw- 大内存段（> 15MB），V8 引擎典型产生 20-100MB 匿名堆 |
| `FridaHeapDetector` | Stalker JIT 代码页 | P1 | 极高 | 检测匿名 r-x 页（不属于任何 dylib），Stalker 代码追踪必须 JIT 编译 |
| `ObjCSwizzleDetector` | ObjC 方法劫持 | P0 | 高 | `method_getImplementation()` + `dladdr()` 验证 IMP 是否在预期框架镜像内，检测 NSFileManager / UIDevice 等关键类 |
| `ObjCSwizzleDetector` | Dispatch Queue 扫描 | P1 | 中 | 线程关联队列标签匹配 frida / gum-js / linjector 等特征 |
| `FridaSocketDetector` | Unix 域套接字 | P1 | 中 | `/tmp/frida-*` 路径探测 + `getsockname()` FD 扫描 + 目录遍历 |
| `FridaSocketDetector` | 时序侧信道 | P1 | 极高 | `mach_absolute_time()` 纳秒级计时 `getpid()` / `stat()`，Interceptor 注入增加 5-50μs 延迟，p95 > 3μs 即可判定 |

### 信号 ID 与权重

| 信号 ID | 权重 | 触发条件 |
|---------|------|----------|
| `frida_thread_anomaly` | 75 | 发现 Frida 特征线程名 |
| `frida_exception_port` | 85 | 检测到非空异常处理端口 |
| `frida_js_engine_heap` | 80 | 匿名 rw- 堆超过阈值 |
| `frida_stalker_jit` | 78 | 发现匿名 r-x JIT 代码页 |
| `objc_method_swizzled` | 80 | 关键 ObjC 方法 IMP 被重定向 |
| `frida_dispatch_queue` | 70 | 发现 Frida 特征队列标签 |
| `frida_unix_socket` | 75 | 发现 Frida IPC 套接字 |
| `frida_timing_anomaly` | 65 | 系统调用延迟异常 |

### 对抗纵深设计

```
┌─────────────────────────────────────────────────────────┐
│               Frida 深度对抗 — 五维检测矩阵               │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│  进程层   │  内存层   │ 运行时层  │  网络层   │   时序层     │
├──────────┼──────────┼──────────┼──────────┼──────────────┤
│ 线程枚举  │ V8 堆    │ ObjC IMP │ Unix Socket│ getpid 计时 │
│ 异常端口  │ Stalker  │ Swizzle  │ /tmp 扫描  │ stat 计时   │
│ 线程名匹配 │ JIT 代码页│ 队列标签  │ FD 遍历   │ p95 判定   │
└──────────┴──────────┴──────────┴──────────┴──────────────┘
攻击者绕过单层 → 其余 4 层仍然触发
全部绕过需要：重写线程管理 + 隐藏内存 + 替换 IMP 检查 + 清理 Socket + 消除延迟
→ 等价于重写一个 Frida
```

## 3.7 新增能力 — SDK 自保护加固

3.7 版本聚焦 **"保护 SDK 自身不被干掉"**，从存储安全、反调试、二进制完整性、注入检测四个方向堵住攻击者绕过检测的捷径。

### 存储安全加固

| 加固项 | 变更 | 安全影响 |
|--------|------|----------|
| **基线存储迁移 Keychain** | `TextSegmentIntegrityChecker` 的 SHA-256 基线从 UserDefaults 迁移到 Keychain | 攻击者无法通过删除 plist 重置基线 |
| **指纹签名迁移 Keychain** | `FingerprintDeobfuscation` 的设备指纹签名从 UserDefaults 迁移到 Keychain | 防止伪造指纹突变/掩盖真实突变 |
| **调试开关安全化** | `simulate_jailbreak` UserDefaults 开关限制为 `#if DEBUG` | Release 构建中攻击者无法通过设置 UserDefaults 启用模拟模式 |

### 反调试加固

| 加固项 | 原理 | 信号 |
|--------|------|------|
| **ptrace(PT_DENY_ATTACH)** | 通过 `dlsym(RTLD_DEFAULT)` 获取 ptrace 并调用 PT_DENY_ATTACH，主动阻止调试器附加 | `ptrace:debugger_already_attached` |

### 新增检测器

| 检测器 | 检测维度 | 权重 | 原理 |
|--------|----------|------|------|
| `DyldInterposeDetector` | DYLD_INTERPOSE section | 88 | 扫描已加载镜像的 `__DATA.__interpose` section，检测 dyld 层面的符号替换 |
| `DyldInterposeDetector` | DYLD 环境变量滥用 | 78 | 检测 `DYLD_FORCE_FLAT_NAMESPACE` / `DYLD_LIBRARY_PATH` 等危险环境变量 |
| `DyldInterposeDetector` | 镜像数量异常 | 45 | `_dyld_image_count()` > 450 辅助判定注入 |
| `SDKBinaryIntegrityChecker` | SDK 代码签名 | 90 | 校验 SDK 镜像 LC_CODE_SIGNATURE 存在性 |
| `SDKBinaryIntegrityChecker` | SDK 二进制替换 | 95 | LC_UUID 与 Keychain 存储基线对比，检测整体替换 |
| `SDKBinaryIntegrityChecker` | Segment 权限异常 | 85 | `__TEXT` 不可写、`__DATA` 不可执行 |
| `SDKBinaryIntegrityChecker` | 二进制大小异常 | 70 | 与历史大小对比，变化 > 30% 告警 |

### 已有检测器接入主流程

| 检测器 | 原状态 | 现状态 | 检测能力 |
|--------|--------|--------|----------|
| `MultiPathFileDetector` | 已写未接入 | **已接入** | FileManager / stat / lstat / access / fopen 五路径一致性，检测路径 hook |
| `RandomizedDetection` | 已写未接入 | **已接入** | 时序异常 + 时钟反转 + 环境检查（随机化顺序） |
| `FingerprintDeobfuscation` | 已写未接入 | **已接入** | 模拟器环境 / 虚拟化痕迹 / 可疑硬件模型 / 指纹突变 |

### 3.7 新增信号 ID

| 信号 ID | 权重 | 触发条件 |
|---------|------|----------|
| `multipath_hook_detected` | 82 | 多路径文件检测发现 hook 不一致 |
| `multipath_jailbreak_file` | 70 | 多路径一致确认越狱文件存在 |
| `randomized_env_anomaly` | 60 | 随机化检测发现时序/环境异常 |
| `fingerprint_simulator` | 90 | 模拟器环境特征 |
| `fingerprint_virtualization` | 85 | 虚拟化痕迹 |
| `fingerprint_mutation` | 55 | 设备指纹突变 |
| `fingerprint_suspicious_hw` | 80 | 可疑硬件模型 |
| `dyld_interpose_detected` | 88 | 发现 DYLD_INTERPOSE section |
| `dyld_env_abuse` | 78 | 危险 DYLD 环境变量 |
| `dyld_image_overload` | 45 | 加载镜像数量异常 |
| `sdk_code_signature_missing` | 90 | SDK 代码签名缺失 |
| `sdk_binary_replaced` | 95 | SDK 二进制被替换 |
| `sdk_segment_tampered` | 85 | SDK segment 权限异常 |
| `sdk_binary_size_anomaly` | 70 | SDK 二进制大小异常 |

## 快速开始

### 环境要求

- macOS 14.0+ / Xcode 15.0+
- iOS 14.0+ 部署目标
- Swift 5.9+

### 集成方式

**Swift Package Manager**

```swift
// Package.swift
dependencies: [
    .package(path: "../cloudphone-risk-detector/RiskDetectorApp")
]
```

```swift
// target
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "CloudPhoneRiskKit", package: "CloudPhoneRiskKit"),
    ]
)
```

**XcodeGen**

```bash
cd RiskDetectorApp
brew install xcodegen
xcodegen generate
open RiskDetectorApp.xcodeproj
```

### 基础用法

```swift
import CloudPhoneRiskKit

// 1. 启动采集（建议 didFinishLaunching 调用）
CPRiskKit.shared.start()

// 2. 同步评估
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
print(report.score, report.isHighRisk, report.summary)

// 3. async/await
let report = await CPRiskKit.shared.evaluateAsync(config: .default, scenario: .login)

// 4. 停止采集
CPRiskKit.shared.stop()
```

### 场景化决策

```swift
let cfg = CPRiskConfig.default
cfg.defaultScenario = .payment
cfg.enableTemporalAnalysis = true
cfg.enableAntiTamper = true

let report = CPRiskKit.shared.evaluate(config: cfg, scenario: .payment)

// report.score     → 0-100 风险分
// report.isHighRisk → 是否触发高风险
// report.tampered   → 是否检测到篡改
// report.signals    → 所有触发的信号列表
```

支持场景：`login` / `payment` / `register` / `accountChange` / `sensitiveAction` / `apiAccess`

### 账号绑定与图算法对接（3.5.1）

```swift
// 用户登录后绑定账号
CPRiskKit.shared.bindAccount("user_12345", scene: "login")

// 评估时自动写入 accountId / sessionId / behaviorVector
let report = CPRiskKit.shared.evaluate()
// report.accountId  → "user_12345"
// report.sessionId  → 自动生成的会话 UUID

// 注入图算法反哺特征
CPRiskKit.setGraphFeatures(
    communityId: "comm_42",
    communityRiskDensity: 78.5,
    hwProfileDegree: 120,
    devicePageRank: 0.0023,
    isInDenseSubgraph: true,
    riskTags: ["cloud_farm_suspect"]
)

// 登出时解绑
CPRiskKit.shared.unbindAccount()
```

### 服务端信号注入

```swift
CPRiskKit.setExternalServerSignals(
    publicIP: "203.0.113.10",
    asn: "AS64500",
    asOrg: "Cloud-DC",
    isDatacenter: true,
    ipDeviceAgg: 260,
    ipAccountAgg: 800,
    geoCountry: "CN",
    geoRegion: "BJ",
    riskTags: ["cloud_phone", "dc_ip"]
)
```

### HMAC 签名验证（3.5 新增）

```swift
import CloudPhoneRiskKit

let report = CPRiskKit.shared.evaluate()

// 从设备特征派生密钥（不存储在 SDK 中）
let deviceKey = DeviceKeyDeriver.deriveKey(
    deviceID: report.deviceID,
    hardwareMachine: "iPhone15,3",
    kernelVersion: "Darwin 23.0.0"
)

// 签名结论
let signed = SignedRiskConclusion.sign(report: report, deviceKey: deviceKey)

// 服务端验签
let valid = signed.verify(deviceKey: deviceKey)  // false → 结论被篡改
```

### 安全上报信封

```swift
let envelope = try CPRiskKit.shared.buildSecureReportEnvelope(
    report: report,
    sessionToken: "server-issued-token",
    signingKey: "hmac-signing-key",
    keyId: "k1"
)

let json = try envelope.toJSONString(prettyPrinted: false)
// 包含 nonce、签名、字段混淆、诱饵字段
```

## 项目结构

```
RiskDetectorApp/
├── Package.swift
├── project.yml
├── App/                                    # SwiftUI Demo 应用
│   ├── Views/                              # Dashboard / Results / History / Settings
│   └── ViewModels/                         # Detection / History / Settings ViewModel
└── Sources/
    ├── CloudPhoneRiskKit/                  # SDK 核心
    │   ├── CloudPhoneRiskKit.swift         # 主入口 CPRiskKit
    │   ├── Jailbreak/                      # 越狱检测引擎 (11 个检测器)
    │   ├── Detection/
    │   │   ├── AntiTampering/              # 调试器 / Frida / 代码签名 / 内存完整性 / RWX 扫描
    │   │   ├── AntiBypass/                 # SDK 完整性 / PLT 校验 / 随机化 / 指纹反混淆
    │   │   └── Adapter/                    # 信号适配器
    │   ├── Decision/                       # 决策引擎 / 决策树 / 场景策略
    │   ├── Providers/                      # 信号提供者
    │   │   ├── DRMCapabilityProvider       # DRM 等级检测 (3.5)
    │   │   ├── BatteryEntropyProvider      # 电池物理熵 (3.5)
    │   │   ├── MountPointProvider          # 挂载点异常 (3.5)
    │   │   ├── VPhoneHardwareProvider      # 云手机硬件特征
    │   │   ├── DeviceHardwareProvider      # 设备硬件信息
    │   │   ├── LayeredConsistencyProvider  # 跨层一致性
    │   │   └── ...
    │   ├── Risk/                           # 报告 / 评分 / 信封 / 混淆 / HMAC
    │   │   ├── RiskConclusionSigner        # HMAC 签名 (3.5)
    │   │   ├── DecoyFieldInjector          # 诱饵字段 (3.5)
    │   │   └── ...
    │   ├── Util/                           # 工具
    │   │   ├── ObfuscatedStrings           # 字符串多段混淆 (3.5)
    │   │   ├── SVCDirectCall               # SVC 直调加固 (3.5)
    │   │   ├── SecureBuffer                # 内存安全清零 (3.5)
    │   │   └── ...
    │   ├── Behavior/                       # 触摸 / 运动传感器 / 耦合分析
    │   ├── Analysis/                       # 时序分析 / 异常检测 / 行为基线
    │   ├── CloudPhone/                     # 云手机本地信号
    │   ├── Network/                        # VPN / 代理检测
    │   ├── Device/                         # 设备指纹 / Keychain ID
    │   ├── Config/                         # 远程配置
    │   └── Storage/                        # AES-GCM 加密存储
    └── CloudPhoneRiskAppCore/              # App 封装层
```

## 检测器矩阵

### 越狱检测 (11 个)

| 检测器 | 检测维度 |
|--------|----------|
| `FileDetector` | 越狱文件路径探测 |
| `DyldDetector` | 越狱动态库加载 |
| `EnvDetector` | `DYLD_INSERT_LIBRARIES` 等环境变量 |
| `SysctlDetector` | 调试状态与进程信息 |
| `SchemeDetector` | Cydia / Sileo 等 URL Scheme |
| `HookDetector` | 函数 prologue 完整性 |
| `HookFrameworkSymbolDetector` | Hook 框架符号存在性 |
| `ObjCIMPDetector` | ObjC 方法实现地址验证 |
| `PrologueBranchDetector` | ARM64 函数入口跳转指令 |
| `PointerValidationDetector` | 指针有效性验证 |
| `IndirectSymbolPointerDetector` | 间接符号指针完整性 |

### 反篡改 & 抗绕过

| 检测器 | 检测维度 |
|--------|----------|
| `AntiTamperingDetector` | P_TRACED / 可疑父进程 / 调试环境变量 / 时序异常 |
| `DebuggerDetector` | 调试器附加检测 |
| `FridaDetector` | dylib 镜像 / 环境变量 / 端口 / 文件 |
| `RWXMemoryScanner` | 匿名 RWX 内存段（Frida trampoline）**(3.5)** |
| `CodeSignatureValidator` | LC_CODE_SIGNATURE 验证 |
| `MemoryIntegrityChecker` | 内存完整性校验 |
| `SDKIntegrityChecker` | DYLD 注入 / 可疑镜像 / Bundle 路径 / 代码签名 |
| `PLTIntegrityGuard` | 10 个关键函数的 PLT 地址基线校验 **(3.5)** |
| `TextSegmentIntegrityChecker` | __TEXT.__text SHA-256 代码段哈希基线校验 **(3.5.1)** |
| `FridaThreadDetector` | 线程枚举异常 + Mach 异常端口劫持检测 **(3.6)** |
| `FridaHeapDetector` | V8/QuickJS 堆特征 + Stalker JIT 代码页检测 **(3.6)** |
| `ObjCSwizzleDetector` | ObjC 方法 IMP 劫持 + Dispatch Queue 名称扫描 **(3.6)** |
| `FridaSocketDetector` | Unix 域套接字检测 + 时序侧信道分析 **(3.6)** |
| `DyldInterposeDetector` | DYLD_INTERPOSE section + 环境变量滥用 + 镜像数量异常 **(3.7)** |
| `SDKBinaryIntegrityChecker` | SDK 代码签名 + LC_UUID 一致性 + Segment 权限 + 大小校验 **(3.7)** |
| `MultiPathFileDetector` | 多路径文件一致性（FileManager/stat/lstat/access/fopen）**(3.7 接入)** |
| `RandomizedDetection` | 时序异常 + 时钟反转 + 随机化环境检查 **(3.7 接入)** |
| `FingerprintDeobfuscation` | 模拟器 / 虚拟化痕迹 / 可疑硬件 / 指纹突变 **(3.7 接入)** |

### 设备 & 环境信号

| Provider | 检测维度 |
|----------|----------|
| `DRMCapabilityProvider` | FairPlay DRM 等级 + 设备交叉验证 **(3.5)** |
| `BatteryEntropyProvider` | ChargeCounter / EnergyCounter / 电压时序方差 **(3.5)** |
| `MountPointProvider` | 虚拟化 FS 黑名单 + 必需挂载白名单 **(3.5)** |
| `VPhoneHardwareProvider` | GPU 名称 / 设备型号 / Board ID / 内核版本 |
| `LayeredConsistencyProvider` | Prologue 完整性 / Timing / 传感器熵 / 触摸熵 |

## 配置参考

### CPRiskConfig

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `enableBehaviorDetect` | `true` | 行为采集（触摸 + 运动） |
| `enableNetworkSignals` | `true` | VPN / 代理检测 |
| `threshold` | `60` | 高风险判定阈值 |
| `enableRemoteConfig` | `true` | 远程配置拉取 |
| `defaultScenario` | `.default` | 默认业务场景 |
| `enableTemporalAnalysis` | `true` | 时序分析 |
| `enableAntiTamper` | `true` | 反篡改检测（含 RWX / PLT） |

### 场景策略阈值

| 场景 | 中风险 | 高风险 | 严重 | 越狱处置 |
|------|--------|--------|------|----------|
| `default` | 30 | 55 | 80 | challenge |
| `login` | 35 | 60 | 85 | challenge |
| `register` | 25 | 50 | 75 | block |
| `payment` | 20 | 45 | 70 | block |
| `sensitiveAction` | 15 | 40 | 65 | block |

## 安全设计

### 字符串保护

```
明文 "Apple Paravirtual device"
  → 分 3 段，每段不同变换：
    XOR(key=0x42) + ROT13 + reverseBytes
  → IDA 搜索不到任何明文特征
  → 用完通过 SecureString 清零
```

### 双路验证

```
标准调用 sysctlbyname("hw.machine") → "iPhone15,3"
加固调用 RTLD_NEXT → sysctlbyname → "iPhone15,3"
结果一致 → 正常
结果不一致 → tampered 信号触发
```

### HMAC 防篡改

```
客户端：score|isHighRisk|timestamp|nonce|tampered → HMAC-SHA256(deviceKey)
攻击者：修改 score → 无法重算 HMAC（不知道 deviceKey 派生输入）
服务端：验签失败 → 反而暴露攻击行为
```

### 代码段完整性校验

```
首次运行：SHA-256(__TEXT.__text) → 存储基线（keyed by LC_UUID）
后续运行：重新计算哈希 → 与基线对比
哈希一致 → 代码未被修改
哈希不一致 → inline hook / 指令替换 → tampered 信号触发
版本更新（UUID 变化）→ 自动重建基线
FairPlay 加密（cryptid ≠ 0）→ 安全跳过
```

### 图特征闭环

```
SDK 上报 → 服务端存储 → 图构建（Device/Account/IP/ASN/HWProfile）
  → 社区发现 + 中心性分析 → 图特征提取
  → setGraphFeatures() 回传 SDK → 增强本地评分
```

### Frida 五维对抗

```
进程层：task_threads → 线程名/数量异常 → 不可隐藏（Frida 核心线程无法关闭）
内存层：vm_region_64 → V8 堆 / JIT 代码页 → 无法避免（JS 引擎必须分配内存）
运行时层：method_getImplementation + dladdr → IMP 重定向 → 无法绕过（hook 本质就是改 IMP）
网络层：getsockname / 目录遍历 → Unix Socket → 可绕过但需修改 Frida 源码
时序层：mach_absolute_time → 纳秒级延迟 → 物理定律无法绕过（额外指令必然消耗时间）
```

### SDK 自保护纵深（3.7）

```
存储层：基线 + 指纹签名存入 Keychain → 攻击者无法通过 defaults delete 重置
反调试层：ptrace(PT_DENY_ATTACH) → 调试器附加直接失败 / 暴露已附加状态
注入层：DYLD_INTERPOSE section 扫描 → 比 PLT hook 更底层的符号替换无处遁形
完整性层：SDK 二进制 UUID + 签名 + 权限 + 大小四重校验 → 整体替换 SDK 必被发现
多路径层：FileManager / stat / lstat / access / fopen 五路交叉 → 单路 hook 立即暴露
随机化层：检测顺序 + 延迟随机 → 攻击者无法针对固定顺序编写绕过脚本
```

## 文档索引

| 文档 | 路径 |
|------|------|
| SDK 接入说明 | `CloudPhoneRiskKit_使用说明.md` |
| 项目技术文档 | `RiskDetectorApp/RiskDetectorApp项目文档.md` |
| 架构设计 | `RiskDetectorApp/docs/architecture-design.md` |
| API 设计 | `RiskDetectorApp/docs/api-design.md` |
| 模块依赖 | `RiskDetectorApp/docs/module-dependencies.md` |

## 构建

```bash
cd RiskDetectorApp
swift build
```

> 推荐真机调试。模拟器环境下 DRM 检测、电池采样、部分越狱检测器返回 `unavailable`。

## 免责声明

本项目仅供安全研究与学习用途。使用者应遵守当地法律法规，不得用于任何非法目的。

---

<p align="center"><sub>CloudPhoneRiskKit 3.7 — SDK Self-Protection Hardening + Full Detection Enhancement</sub></p>
