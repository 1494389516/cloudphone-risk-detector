<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-6.8-FF3B30?style=for-the-badge" alt="SDK">
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
- **本地运行（SPM）**：在仓库根目录执行 `cd RiskDetectorApp && swift test` 可先验证核心逻辑测试；如需隔离构建目录（例如 CI 或并发测试），可追加 `--scratch-path "${TMPDIR:-/tmp}/cloudphone-risk-detector-riskdetector-tests"`。

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
| **5.3** | **自保护架构升级 + 内核直调** | SVC #0x80 直调 ptrace(PT_DENY_ATTACH) 绕过 Frida Hook、CRiskCore C 模块、自保护 C/Swift 混合层、下一代 6.x 架构奠基 |
| **5.4** | **四盲区修复 + 直调扩展** | RTLD_NEXT 下沉为 SVC 直调、时序动态比值基线、PhysicalSensorProbe 预热缓存、服务端参考哈希、getpid/getppid/getuid/socket/connect 直调 |
| **5.5** | **Bug 修复 + 实验分桶** | RandomizedDetection 父进程逻辑、ptrace 错误处理、ExperimentConfig.random 分桶、WhitelistRules 语义化版本比较、PayloadFieldObfuscator 反向映射、getentropy buflen 校验 |
| **6.0** | **自研壳保护 + 端云签名绑定** | cprisk-armor 编译后壳工具链（Pass 1 字符串加密 / Pass 3 数据段加密 / Pass 4 完整性锚点）、CRiskCore 运行时解密消费链、内联 SHA-256 消除 CommonCrypto Hook 面、自包含 Mach-O 基址解析阻断 Clean Copy 攻击、Section 伪装隐写、编译期 XOR 盐混淆、armor runtime material 渗透式毒化业务签名（v2a）、9 项安全 Bug 修复 |
| **6.1** | **壳工业化 + 运行时加固 + 全量回归** | Pass 1 全量敏感字符串加密 + 原位零化、Pass 2 Metadata 抹除（Swift 类型名/反射字符串/ObjC 方法名混淆）、Pass 3 多 Section 真实数据段加密（`__const`/`__cfstring`/`__swift5_fieldmd`）、Pass 5 结构混淆（5-8 假 Section 注入 + 随机布局）、密钥安全清零（`cprisk_secure_zero`）、Anti-Dump 页面保护验证（`vm_region_64`）、运行时完整性重校验（`cprisk_recheck_integrity`）、v2a 验签密钥派生修复、KDF 全链路测试（14 节点）、E2E 集成测试（6 场景）、10 项 Bug 修复、385 测试全绿 |
| **6.2** | **壳密码学重建 + 全栈安全加固 + 46 项漏洞修复** | ABI v2 壳密码学重建（CLI 强制密钥注入 / HMAC-SHA256 认证标签 / 随机 nonce / IntegrityAnchor HMAC 绑定 rootKey / salt 动态派生 / 密码学安全 seed）、CRiskCore C 层 9 项边界安全加固、运行时反篡改 6 项纵深补强、配置降级 8 项封堵、18 项 Bug 修复 |
| **6.3** | **逆向对抗纵深 + 符号表混淆** | Pass 6 SymbolStripper（nlist 本地符号表 SDK 标记混淆）、ObjC selector 安全修复（仅混淆 SDK 方法名，系统 selector 保留）、MetadataScrubber 全类型混淆（移除 SDK 公开类型白名单）、Codable 短别名 CodingKeys（80+ struct / 25+ 文件，消除 Small String 指令流泄漏）、92 项壳测试全绿 |
| **6.4** | **静态库架构 + 全量符号剥离** | SDK 由动态 framework 改为 library.static（消除 dyld 导出符号暴露面）、armor 壳对最终 app 二进制执行、全量 strip（STRIP_STYLE=all）清除所有本地符号、IDA 中 SDK 函数全部显示为 sub_XXXX（与 Android .so 同等效果）、app bundle 不再包含 Frameworks/ 目录 |
| **6.5** | **白盒加密 + 反重打包** | 白盒 PRF 引擎（5 域 table-driven SPN，~160KB S-box 嵌入二进制，root key 不可逆提取）、anchor/字符串/数据段/签名材料全链路白盒派生（替代 legacy HMAC 路径）、AppSigningIdentityDetector 反重打包（TeamID/bundleID/entitlement 一致性 + 基线漂移检测 + integrity poison 联动）、白盒 4 section 占位符预埋（`__swift5_awbm/awbc/awbd/awbt`）、cprisk-armor IntegrityAnchorPass 白盒集成、CRiskCore 白盒运行时（validate bundle → PRF evaluate → signing helper）、v2a 签名链白盒化 |
| **6.6** | **反调试纵深 + Pass 7/8 + Frida 模块检测** | cprisk-armor Pass 7 AntiDebugInjector（`__DATA,__cpr_adbg7` 编译期注入计划 ABI）+ Pass 8 InstructionSubstitution（对 `__TEXT.__text` 做 1:1 等长语义等价替换）、关键密码学路径被调试时静默毒化、watchdog 多维探针（SIGTRAP/csops/硬件断点/软件断点/异常分发超时/可疑线程/TTY/Developer Disk）、FridaModuleDetector（image/section/字符串三路 Frida/Gum/Gadget 检测）、反篡改检测顺序稳定随机化（MutationStrategy.shuffleChecks）、`software_breakpoint_detected` / `exception_delivery_timeout` 等新 RiskSignal |
| **6.7** | **控制流平坦化 + 反去混淆 + Pass 9** | 源码级 CFF 基础设施（CFFStateCodec / CFFDispatcher / CFFReturnSink / CFFRuntimeSalt）、DecisionTree / RiskDetectionEngine / ChallengeSession / TrustChainManager / anti_debug_watchdog 接入编码状态机、Pass 9 ControlFlowOrchestrator 策略编排（`cff_policy.yaml`）、异构 dispatcher（switch / if-else / dual-rail / region）、runtime salt 绑定、fail-closed 默认路径、避免 OLLVM 模板化特征 |
## 架构概览

```
┌────────────────────────────────────────────────────────┐
│          Layer 0: 自研壳 (cprisk-armor) ABI v2           │
│   全量字符串加密+HMAC / 多 Section 数据段加密+HMAC       │
│   完整性锚点 HMAC / Metadata 抹除 / 结构混淆 / Anti-Dump │
│   Pass 6 符号表混淆 / Pass 7 AntiDebug ABI / Pass 8 指令替换 / Pass 9 CFF 编排 │
│   短别名 CodingKeys / 全量 strip / 强制密钥注入          │
│   白盒 PRF (5域 S-box ~160KB) / 反重打包 TeamID 校验    │
├────────────────────────────────────────────────────────┤
│                   业务应用层                             │
│            evaluate(scenario: .payment)                │
├────────────────────────────────────────────────────────┤
│               RiskDetectionEngine                      │
│   场景策略 ─ 决策树 ─ 组合规则 ─ 盲挑战 ─ HMAC 签名    │
│   安全地板强制 ─ 关键信号权重下限 ─ 异常容错链          │
├──────────┬──────────────┬───────────┬───────────────────┤
│ Layer 1  │   Layer 2    │  Layer 3  │     Layer 4       │
│ 硬件指纹  │  一致性      │  行为熵    │   服务端聚合         │
├──────────┼──────────────┼───────────┼───────────────────┤
│ GPU 名称  │ PLT/GOT      │ 触摸熵    │  公网 IP / ASN    │
│ DRM 等级  │ RWX 内存     │ 传感器熵   │  机房属性          │
│ 设备型号  │ Hook 检测    │ 电压方差   │  IP 聚合度         │
│ 电池计数器 │ 挂载点       │ 时序模式   │  图特征反哺        │
│ Board ID │ SVC 双路     │ 耦合分析   │  风险标签          │
│          │ 代码段哈希    │ 行为充足性  │  黑名单           │
│          │ 线程枚举     │           │                   │
│          │ 异常端口     │           │                   │
│          │ V8 堆检测    │           │                   │
│          │ ObjC Swizzle │           │                  │
│          │ Socket 检测  │           │                   │
│          │ 时序侧信道   │           │                    │
│ 指纹突变  │DYLD Interpose│         │                    │
   │          │ SDK 自校验   │           │                │
│          │ ptrace 防附加 │           │                  │
│          │ 多路径一致性  │           │                   │
└──────────┴──────────────┴───────────┴───────────────────┘
```

### 信号三分类

| 类型 | 判定方式 | 典型信号 | 权重 |
|------|----------|----------|------|
| **硬信号** | 本地独立判定，单点即可触发 | 越狱、DRM 降级、ChargeCounter 异常、PLT 篡改、ObjC Swizzle、异常端口劫持、SDK 二进制替换、DYLD Interpose | 80-100 |
| **软信号** | 需结合场景综合评分 | VPN、行为异常、电压方差低、挂载点异常、时序侧信道、线程枚举异常、指纹突变、随机化检测、行为数据不足 | 30-75 |
| **服务端信号** | 依赖外部聚合 | 机房 IP、ASN 黑名单、IP 设备聚合度、图社区风险、硬件画像聚集 | 55-100 |

---

## 6.7 新增能力 — 控制流平坦化 + 反去混淆 + Pass 9

6.7 引入源码级控制流平坦化（CFF）与反去混淆设计：Swift 侧 CFF 基础设施（CFFStateCodec、CFFDispatcher、CFFReturnSink、CFFRuntimeSalt）、DecisionTree / RiskDetectionEngine / ChallengeSession / TrustChainManager / anti_debug_watchdog 接入编码状态机；cprisk-armor Pass 9 ControlFlowOrchestrator 读取 `cff_policy.yaml` 为函数分配 CFF 计划（heavy/light/never/regionOnly）；刻意避免 OLLVM 模板化特征（异构 dispatcher、runtime salt、fail-closed 默认、region 拆分）。

### 6.7 核心改动

| 改动 | 说明 |
|------|------|
| **Swift CFF 基础设施** | `CFFStateCodec` 编码/解码、`CFFDispatcher` 异构分支、`CFFReturnSink` 统一收口、`CFFRuntimeSalt` 运行时盐混合 |
| **业务 CFF 接入** | DecisionTree.decide、RiskDetectionEngine 四 region、ChallengeSession、TrustChainManager、anti_debug_watchdog |
| **Pass 9: ControlFlowOrchestrator** | 读取 `cff_policy.yaml`，为函数分配 dispatcher 风格、状态编码计划、运行时依赖计划 |
| **反去混淆设计** | 避免唯一高入度 dispatcher、state 非裸常量、return 收口、runtime salt 绑定、fail-closed 默认 |

---

## 6.6 新增能力 — 反调试纵深 + Pass 7/8 + Frida 模块检测

6.6 强化反调试与 Frida 对抗：cprisk-armor 新增 Pass 7 编译期 anti-debug 注入计划 ABI，并进一步加入 Pass 8 `InstructionSubstitution`，对 `__TEXT.__text` 中可安全替换的 ARM64 指令执行 1:1 等长语义等价改写；同时补齐关键密码学路径静默毒化、watchdog 多维探针、FridaModuleDetector 模块级检测和反篡改检测顺序稳定随机化。

### 6.6 核心改动

| 改动 | 说明 |
|------|------|
| **Pass 7: AntiDebugInjector** | 在 `__DATA,__cpr_adbg7` 写入可运行时消费的 anti-debug 注入计划 ABI（seed、probeImmediate、target identifier/hash、patchSiteVMOffset/fileOffset、policyBits、entryFlags、scatterSlot），为后续 inline patch / runtime gate 预留 |
| **Pass 8: InstructionSubstitution** | 对 `__TEXT.__text` 中可安全改写的 ARM64 指令做 1:1 等长替换，当前覆盖 MOV alias、ADD/SUB #0、AND-self、ORR-self、NOP/XZR no-op、MOVZ/ORR logical immediate 等规则族，保持 section 大小不变并支持基于 seed 的稳定随机化 |
| **关键路径静默毒化** | 白盒 PRF、字符串解密、数据段加载、签名材料在被调试时输出错误/毒化值，而非 crash，增加定位难度 |
| **watchdog 多维探针** | 每 3s 执行 ptrace、exception port、SIGTRAP/BRK、csops(CS_DEBUGGED)、硬件断点、软件断点、可疑线程、TTY、Developer Disk Image、single-step timing trap、exception delivery timeout 等探针 |
| **FridaModuleDetector** | 扫描 dyld image 名、可疑 Mach-O section 名、`__cstring/__const` 中 Frida/Gum/Gadget 字符串片段，与 FridaDetector 端口/文件/环境维度分工 |
| **检测顺序随机化** | `MutationStrategy.shuffleChecks == true` 时，anti-tamper/debugger/frida 相关 detector 按 deviceID+scope+seed 稳定洗牌，同一设备顺序稳定、不同设备可变 |
| **新 RiskSignal** | `software_breakpoint_detected`、`exception_delivery_timeout`、`frida_module_detected` 等参与评分 |

---

## 6.5 新增能力 — 白盒加密 + 反重打包

6.5 引入白盒 PRF 引擎，将 root key 嵌入 ~160KB S-box 查找表中不可逆提取，全链路替代 legacy HMAC 派生路径；同时新增 AppSigningIdentityDetector 反重打包检测。

### 6.5 核心改动

| 改动 | 说明 |
|------|------|
| **白盒 PRF 引擎** | 5 域 table-driven SPN（4 轮 S-box + permutation + finalMask），每域 ~32KB 查找表，总计 ~160KB 嵌入 `__swift5_awbc` section；root key 在构建时融入 S-box，运行时无法逆向还原 |
| **5 域全链路白盒派生** | domain 1: anchor tag 校验、domain 2: Pass1 字符串解密密钥、domain 3: 数据段 accumulator seed、domain 4: loader key、domain 5: runtime material（签名基础密钥） |
| **白盒 4 section 预埋** | `__swift5_awbm`（header 48B）、`__swift5_awbc`（S-box ~160KB）、`__swift5_awbd`（descriptor ~1.2KB）、`__swift5_awbt`（tag 32B）通过 `-Wl,-sectcreate` 占位符预埋，armor 更新而非追加 |
| **白盒运行时校验矩阵** | overall tag → config digest → payload coverage → domain mask → permutation → record digest 六层校验，任一失败 bundle 不加载 |
| **白盒 vs Legacy 自动降级** | `cprisk_whitebox_available()` 自动选择路径：白盒可用走 PRF 分支，不可用 fallback 到 legacy HMAC |
| **AppSigningIdentityDetector** | macOS 上通过 `SecTaskCreateFromSelf` + `SecTaskCopyValueForEntitlement` 读取 TeamID / `application-identifier` / `get-task-allow`；iOS 上做 bundle 一致性校验 |
| **签名身份基线漂移检测** | 首次运行存储 `IdentityBaseline`（teamIdentifier + applicationIdentifier + bundleIdentifier），后续运行检测变更字段，变更时注入 `app_signing_baseline_changed` 信号 |
| **integrity poison 联动** | 签名异常时调用 `cprisk_force_integrity_poison()`，使 runtime material 不可信、v2a 签名链失效 |
| **cprisk-armor 白盒集成** | IntegrityAnchorPass 写入白盒 metadata/code/data/tag 四个 section；StringEncryptor / DataSegmentEncryptor 通过白盒 PRF 派生密钥 |

### 白盒 PRF 安全性对比

| 维度 | Legacy 路径 | 白盒路径 (6.5) |
|------|------------|----------------|
| **密钥存在形式** | root_key 明文参与 HMAC/SHA256 | root_key 融入 S-box 表，运行时仅存在查找表 |
| **内存 dump 攻击** | dump root_key 后全线沦陷 | dump 160KB S-box 表，无法还原 root_key |
| **攻击者复现成本** | 提取 32 字节密钥即可离线重建所有派生 | 需完整提取并复现整个白盒引擎（S-box + permutation + finalMask + roundConstants） |
| **anchor 校验** | `HMAC-SHA256(root_key, textHash)` | `WB_PRF(domain=1, textHash)` |
| **签名材料** | `SHA256(root_key ‖ context)` | `WB_PRF(domain=5, anchorHash)` |

### 反重打包检测矩阵

| 检测项 | 信号 ID | 分数 | 触发条件 |
|--------|---------|------|----------|
| TeamID 为空 | `app_signing_identity_tampered` | 55 | entitlement 中无 team-identifier |
| bundleID 不一致 | `app_signing_identity_tampered` | 60 | Bundle.main.bundleIdentifier ≠ Info.plist CFBundleIdentifier |
| get-task-allow 为 true | `app_signing_identity_tampered` | 40 | Release 构建不应有 get-task-allow |
| applicationIdentifier 缺失 | `app_signing_identity_tampered` | 50 | 无 application-identifier entitlement |
| 基线漂移 | `app_signing_baseline_changed` | 44 | teamIdentifier / applicationIdentifier / bundleIdentifier 任一变更 |

---

## 6.4 新增能力 — 静态库架构 + 全量符号剥离

6.4 将 SDK 交付方式从动态 framework 转为 static library，消除 dyld 导出符号这一根本性暴露面，配合全量 strip 实现 Android .so 级别的逆向对抗效果。

### 6.4 核心改动

| 改动 | 说明 |
|------|------|
| **library.static 架构** | `CloudPhoneRiskKit` 与 `CloudPhoneRiskAppCore` 由 `type: framework` 改为 `type: library.static`，SDK 代码静态链入最终 App 二进制 |
| **消除导出符号暴露面** | 动态 framework 必须通过 `__LINKEDIT` Export Trie 暴露公开 API 符号；静态库链入 App 后无需导出，所有 SDK 符号降为本地符号 |
| **armor 壳对 App 执行** | `cprisk-armor` 的 `--sectcreate` placeholder 和 postBuildScripts 移至 `RiskDetectorApp` target，壳直接对最终二进制加固 |
| **全量 strip** | `STRIP_STYLE=all` + 显式 `xcrun strip -x` / `xcrun strip`，剥离所有本地符号与调试信息 |
| **IDA 效果** | SDK 函数全部显示为 `sub_XXXX`，类型名、方法名均不可见；仅剩系统 undefined imports（约 1448 个） |
| **bundle 瘦身** | App bundle 不再包含 `Frameworks/` 目录，减少文件数与加载开销 |

### 静态库 vs 动态 framework 逆向对抗对比

| 维度 | 动态 framework | 静态库 (6.4) |
|------|---------------|-------------|
| **导出符号** | ~5310 个（含所有 public API + Swift metadata + protocol conformance） | 0 个 |
| **IDA 函数名** | `CPRiskKit.evaluate()`、`RiskSignal.init()` 等完整可读 | `sub_10000ABCD` |
| **`nm` 输出** | 数千条 `T` (text) 符号 | 0 条 SDK 符号 |
| **Frameworks/ 目录** | 存在，可直接提取 .framework 分析 | 不存在 |
| **strip 效果** | 只能删本地符号，导出符号由 dyld 强制保留 | 全部可删 |

---

## 6.3 新增能力 — 逆向对抗纵深 + 符号表混淆

6.3 针对 IDA 逆向分析中暴露的多层信息泄漏，新增 Pass 6 符号表混淆，并修复 ObjC selector 误伤、MetadataScrubber 白名单遗漏、Codable 指令流泄漏三项问题。

### 6.3 核心改动

| 改动 | 说明 |
|------|------|
| **Pass 6: SymbolStripper** | 解析 `LC_SYMTAB` 中的 `nlist` 条目，将包含 SDK 标记（`CPRisk`、`CloudPhone`、`Detection` 等）或 `outlined` 的本地符号名替换为等长随机 hex 字节 |
| **ObjC selector 安全修复** | `MetadataScrubber.shouldObfuscateMethod()` 从"排除系统前缀白名单"改为"命中 SDK 标记才混淆"，杜绝系统 selector 被误伤导致 `unrecognized selector` crash |
| **MetadataScrubber 全类型混淆** | 移除保护 `CPRisk`/`CloudPhone`/`Risk` 前缀的白名单，现在所有 Swift 类型名（>2 字符，非 `cprisk_` C 层）均被混淆 |
| **Codable 短别名 CodingKeys** | 80+ 个 `Codable` struct 显式声明 `CodingKeys` enum，将 `threshold`→`t`、`mediumThreshold`→`mt` 等长属性名替换为 1-3 字符短别名，消除 Swift Small String Optimization 导致的 MOV 立即数字符串泄漏 |

### 信息泄漏四层防御矩阵

| 泄漏层 | 攻击面 | 防御手段 | strip 能处理？ |
|--------|--------|----------|---------------|
| **符号表** (`LC_SYMTAB`) | `nm` / IDA 函数列表 | Pass 6 + strip | 能 |
| **元数据** (`__swift5_types` / `__swift5_reflstr`) | Swift Metadata 还原 | Pass 2 MetadataScrubber | 不能 |
| **ObjC selector** (`__objc_methname`) | class-dump / IDA ObjC 分析 | Pass 2 SDK selector 混淆 | 不能 |
| **指令流立即数** (`__text` MOV) | IDA 反编译 / Hex-Rays | 源码级短别名 CodingKeys | 不能 |

---

## 6.2 新增能力 — 壳密码学重建 + 全栈安全加固

6.2 对壳保护层执行密码学根本性重建（ABI v1→v2），同时对 CRiskCore C 层、SDK 运行时反篡改、配置/存储/密码学执行全栈安全加固，共计 46 项漏洞修复。

### 6.2 新特性摘要

| 能力域 | 核心改动 | 说明 |
|--------|----------|------|
| **壳 ABI v2 密码学重建** | CLI `--key` / `--key-file` / `CPRISK_ARMOR_KEY` | 强制外部密钥注入，无密钥拒绝执行；拒绝全零密钥 |
| **HMAC 认证标签** | 每加密项 8B nonce + HMAC-SHA256 tag | 解密前先验 HMAC，失败返回 poison；消除 XOR 无认证缺陷 |
| **IntegrityAnchor HMAC** | `HMAC-SHA256(rootKey, fullHash)` | 替代明文 mask 方案，无密钥不可恢复 fullHash |
| **Salt 动态派生** | `SHA256(rootKey \|\| "salt-xor")[0]` | 替代固定 `0xA7`，运行时从 rootKey 动态派生 |
| **密码学安全 seed** | `SecRandomCopyBytes` | 替代时间戳 seed，消除构建时间可预测性 |
| **C 层边界安全（9 项）** | cprisk_decode_salt / page_span / section 上限 / 竞态 / mprotect 回滚 / nbyte / secure_zero / buffer / getentropy | 整数溢出、缓冲区越界、竞态条件、资源限制全面加固 |
| **ServerSignals HMAC** | `setVerified(_:signature:)` | 服务端信号注入需 HMAC 验签，Release 下旧 `set()` 为 no-op |
| **Evaluator 封印** | `ConditionExpression.sealCustomEvaluators()` | `start()` 后拒绝注册自定义条件求值器 |
| **基线交叉验证** | UUID 变更 + TextSegment 联合判断 | UUID 变了但 hash 没变 → `sdk_binary_baseline_anomaly` (weight=85) |
| **Challenge HMAC** | `ChallengeVerificationResult.hmac` | 服务端挑战结果需 HMAC 验签，失败产出 `challenge_hmac_mismatch` 信号 |
| **结论签名 v2** | `SignedRiskConclusion` 签名域扩展 | signals 摘要纳入签名域，防止信号列表被替换 |
| **动态可疑特征列表** | `DynamicFeatureList` + RemoteConfig 下发 | 可疑库/路径/端口支持服务端热更新，替代全硬编码 |
| **DEBUG/Release 对齐** | ConfigSignatureVerifier / ConfigCache / JailbreakEngine | 未配置时统一返回 false，消除 DEBUG 放行路径 |
| **Keychain 策略统一** | 全量 `AfterFirstUnlockThisDeviceOnly` | 10+ 个 Keychain 调用点策略统一 |
| **行为数据用后清零** | TouchCapture / MotionSampler `clearSensitiveData()` | `stop()` 时 memset 零化敏感缓冲区 |
| **18 项 Bug 修复** | loader 返回值 / flags 丢失 / decoySectionPool 拼写 / set(nil) / applyChallengeResult / checkBinarySize / ConfigCache rollback / KeychainDeviceID 并发 / SecItemAdd 返回值等 | 全量回归修复 |

---

## 6.0 / 6.1 新增能力 — 自研壳保护 + 壳工业化

6.0 引入编译后自研壳（cprisk-armor）工具链；6.1 将壳从概念验证升级为工业级全量保护，补齐 Pass 2 / Pass 5，并引入运行时加固与全链路测试。

### 6.0 / 6.1 新特性摘要

| 能力域 | 核心组件 | 说明 |
|--------|----------|------|
| **全量字符串加密 (Pass 1)** | `StringEncryptor` → `cprisk_string_decrypt.c` | 6.0 基础加密；6.1 升级为全量敏感字符串加密（18 关键词识别）+ 原位零化 `__cstring`，`strings` 工具提取归零 |
| **Metadata 抹除 (Pass 2)** | `MetadataScrubber` | **6.1 新增**：Swift 类型名混淆、`__swift5_reflstr` 全段随机化、ObjC 方法名混淆，class-dump/dsdump 无法还原业务类名 |
| **多 Section 数据段加密 (Pass 3)** | `DataSegmentEncryptor` → `cprisk_data_loader.c` | 6.0 单 blob 加密；6.1 升级为白名单多 Section 加密（`__const`/`__cfstring`/`__swift5_fieldmd`/`__swift5_assocty`），IDA 中 `__DATA` 显示全乱码 |
| **完整性锚点 (Pass 4)** | `IntegrityAnchor` → `cprisk_integrity.c` | 多路径完整性哈希注入四个伪装 Section，运行时交叉校验；哈希参与 KDF 链 |
| **结构混淆 (Pass 5)** | `StructureObfuscator` | **6.1 新增**：5-8 个假 Section 注入（Apple 风格命名）+ 结构化伪数据 + 随机 seed 布局，每次构建指纹不同 |
| **内联 SHA-256** | `cprisk_sha256.h` | `always_inline` FIPS-180-4 SHA-256，消除 CommonCrypto Hook 面 |
| **自包含 Mach-O 解析** | `cprisk_macho.h` | 不依赖 `dladdr`/`getsectiondata`/`_dyld_*`，阻断 Clean Copy 攻击 |
| **密钥安全清零** | `cprisk_secure_zero()` | **6.1 新增**：统一 `volatile` 清零，覆盖全部解密密钥、keystream、中间哈希 |
| **Anti-Dump 页面保护** | `cprisk_verify_page_protection()` | **6.1 新增**：`vm_region_64` 验证解密后数据页保护属性，检测攻击者重映射 |
| **运行时完整性重校验** | `cprisk_recheck_integrity()` | **6.1 新增**：运行时重新计算 `__TEXT.__text` 哈希，不一致时静默毒化 material |
| **v2a 验签修复** | `SecureEnvelopeValidator` | **6.1 修复**：v2a 验签时正确使用 armor material 派生密钥 |
| **业务签名毒化 (v2a)** | `armorRuntimeMaterial()` → `ReportEnvelope` | armor material 混入 HMAC 签名密钥派生，篡改即签名失效 |
| **Bug 修复** | 6.0: 9 项 + 6.1: 10 项 | rotl64 UB、整数溢出、loader key 过早清零、guard 页下溢、除零、v2a 验签、恒真断言等 |

### 壳保护工作流

```
源码 → swift build → SDK (library.static) + App 链接
                          ↓
                    App 二进制 (SDK 代码静态链入)
                          ↓
                    cprisk-armor CLI (8 Pass, ABI v2)
                    --key <hex> / --key-file / CPRISK_ARMOR_KEY
                    ┌─ Pass 1: StringEncryptor       (白盒 PRF 密钥 + HMAC + nonce)
                    ├─ Pass 2: MetadataScrubber      (元数据抹除)
                    ├─ Pass 8: InstructionSubstitution(1:1 等长指令替换)
                    ├─ Pass 4: IntegrityAnchor       (HMAC 锚点 + 白盒 PRF 5域)
                    ├─ Pass 3: DataSegmentEncryptor  (白盒 PRF 密钥 + HMAC + nonce)
                    ├─ Pass 5: StructureObfuscator   (结构混淆, 安全随机)
                    ├─ Pass 7: AntiDebugInjector     (anti-debug 注入计划 __cpr_adbg7)
                    └─ Pass 6: SymbolStripper        (SDK 符号表混淆)
                          ↓
                    xcrun strip -x && xcrun strip  (全量符号剥离)
                          ↓
                    App 二进制 (加固后, IDA 中 sub_XXXX)
                          ↓
                    运行时 CRiskCore
                    白盒 PRF / HMAC 验证 → 解密 + 完整性校验 + Anti-Dump
                    白盒派生 armor material → ReportEnvelope v2a
```

### 渗透式防护原理

传统壳检测到篡改后通常 crash 退出，容易被攻击者二分搜索定位。6.0 采用**渗透式毒化**：

1. 完整性锚点哈希参与 KDF 派生解密密钥 → 篡改后密钥错误 → 字符串/数据解密失败
2. armor runtime material 混入 ReportEnvelope HMAC 密钥 → 签名静默失效
3. 服务端拒绝异常签名 → 攻击者无法区分"壳被绕过"还是"业务后端异常"
4. 不产生显式 crash / abort → 攻击者无法通过 signal handler 或 exit code 定位防护点

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

## 5.3 新增能力 — SVC 直调 ptrace、CRiskCore 模块与下一代自保护架构奠基

5.3 在自保护维度引入 SVC 直调 ptrace、首个 C/Swift 混合层（CRiskCore），为 6.x 代 C 核心层、混淆与 VMP 奠定基础。

### 5.3 新特性摘要

| 能力域 | 核心组件 | 说明 |
|--------|----------|------|
| **SVC 直调 ptrace** | SVC #0x80 系统调用 | 直接通过 SVC #0x80 调用 ptrace(PT_DENY_ATTACH)，绕过 Frida 对 libc ptrace 的 Hook，实现原生系统调用级反调试 |
| **CRiskCore C 模块** | CRiskCore | 首个 C/Swift 混合层，自保护核心逻辑下沉至 C 层，提升抗逆向与 Hook 能力 |
| **下一代架构奠基** | 6.x 架构基础 | C 核心层、混淆、VMP 等下一代自保护能力的架构基础 |
| **Mach Exception Handler 抢占** | CRiskCore | 主动注册 EXC_BREAKPOINT handler，定期验证是否被劫持 |

---

## 5.5 新增能力 — Bug 修复与实验分桶修正

5.5 修复四轮子代理审计发现的逻辑与配置问题。

### 5.5 修复摘要

| 类别 | 修复项 |
|------|--------|
| **逻辑** | RandomizedDetection：ppid ≤ 1（init）时不再误报为可疑；AntiTamperingDetector：ptrace 失败时统一按失败处理 |
| **配置** | ExperimentConfig.random：分桶改为 0/1 与 variants 匹配；WhitelistRules.isTrusted：语义化版本比较，避免 "10.0" < "9.0" |
| **安全** | PayloadFieldObfuscate 反向映射冲突不崩溃；cprisk_getentropy_direct buflen ≤ 256 校验 |

## 项目结构

```
.
├── cprisk-armor/                         # 编译后壳工具链 (SPM CLI)
│   ├── Sources/
│   │   ├── cprisk-armor/                  # CLI 入口 (8 Pass 编排)
│   │   ├── MachOKit/                     # Mach-O 读写库
│   │   ├── StringEncryptor/              # Pass 1: 全量字符串加密
│   │   ├── MetadataScrubber/             # Pass 2: Metadata 抹除
│   │   ├── DataSegmentEncryptor/         # Pass 3: 多 Section 数据段加密
│   │   ├── IntegrityAnchor/              # Pass 4: 完整性锚点
│   │   ├── StructureObfuscator/          # Pass 5: 结构混淆
│   │   ├── SymbolStripper/               # Pass 6: 符号表混淆
│   │   ├── AntiDebugInjector/            # Pass 7: anti-debug 注入计划
│   │   ├── InstructionSubstitution/      # Pass 8: ARM64 指令替换
│   │   └── ControlFlowOrchestrator/      # Pass 9: CFF 策略编排
│   └── Tests/                            # 99+ 项单元 + E2E + KDF 链 + WhiteBox + AntiDebugInjector + InstructionSubstitution 测试
│
├── RiskDetectorApp/
│   ├── App/                              # SwiftUI 示例应用
│   ├── Sources/
│   │   ├── CRiskCore/                    # C 自保护核心
│   │   │   ├── cprisk_string_decrypt.c   # 运行时字符串解密
│   │   │   ├── cprisk_data_loader.c      # 运行时数据段加载/解密
│   │   │   ├── cprisk_whitebox.c         # 白盒 PRF 引擎 (5域 S-box)
│   │   │   ├── cprisk_integrity.c        # 完整性校验 + 主初始化 (白盒/legacy 双路径)
│   │   │   ├── cprisk_memory_guard.c     # Anti-Dump 页面保护
│   │   │   └── include/
│   │   │       ├── cprisk_armor_abi.h    # 壳 ABI (Section 名/Magic/盐)
│   │   │       ├── cprisk_sha256.h       # 内联 SHA-256 (无 CommonCrypto)
│   │   │       └── cprisk_macho.h        # 自包含 Mach-O 基址解析
│   │   ├── CloudPhoneRiskAppCore/        # 应用层编排 (配置/检测/摘要)
│   │   └── CloudPhoneRiskKit/            # SDK 主体
│   │       ├── Detection/
│   │       │   ├── AntiBypass/           # 反篡改 & 抗绕过检测器
│   │       │   ├── Behavior/            # 行为信号 (触摸/传感器/时序)
│   │       │   ├── Environment/         # 环境检测 (越狱/挂载/沙盒)
│   │       │   └── Hardware/            # 硬件信号 (GPU/DRM/电池/Board)
│   │       ├── Device/                   # 设备标识 & Keychain
│   │       ├── Engine/                   # 决策引擎 & 场景策略
│   │       ├── Provider/                 # 信号 Provider 注册表
│   │       ├── Risk/                     # 报告封装 & 签名验证 (v2a)
│   │       ├── Storage/                  # 加密存储 & 历史管理
│   │       └── Util/                     # 工具 (SVC直调/混淆/加密)
│   └── Tests/                            # 单元测试 (301 tests)
```

---

## 检测器总览

| 检测域 | 数量 | 说明 |
|--------|------|------|
| 越狱检测 | 11 个 Detector | 路径/符号/挂载点/沙盒/环境变量/文件权限/dylib/链接器/URL Scheme/fork/写入测试 |
| 反篡改 & 抗绕过 | 23+ 个 Detector | PLT/GOT、RWX 内存、ObjC Swizzle、DYLD Interpose、线程枚举、异常端口、V8 堆、Socket、时序侧信道、SDK 二进制校验、代码段哈希、LibcPrologueGuard、DualPathValidator、SVC 直调、匿名内存隐写、ObjC Inline Hook 跳板、fsid 隔离探测、指令计数器双路校验、ptrace 反调试、**AppSigningIdentityDetector 反重打包** |
| 设备 & 环境信号 | 5 个 Provider | GPU 深度探测、DRM 等级、电池物理熵、Board ID、指纹突变 / 随机化检测 |
| 硬件信任根 | 2 个 | App Attest（TOCTOU 安全 + 强制模式）、Secure Enclave 硬件绑定签名 |
| 执行流检测 | 2 个 | CallStack 回溯 ROP/JOP 链检测、Syscall Canary 探针致盲感知 |
| 内存蜜罐 | 1 个 | HoneypotMemory 三页分散 + SIGBUS handler 自检 + 保护位验证 |
| 内核 Hook 侧信道 | 4 策略 | KernelHookSideChannel — 时序分布 / inode 一致性 / 时钟交叉 / 返回值熵 |
| 行为信号 | 3 个 Provider | 触摸熵、传感器熵、电压方差（含回放检测） |
| 服务端聚合 | 4 维 | 公网 IP/ASN、机房属性、IP 设备聚合度、图特征反哺 |

---

## 安全设计概要

SDK 采用纵深防御架构：**cprisk-armor 自研壳（9 Pass / ABI v2）** 在编译后对二进制执行全量字符串加密（HMAC 认证 + 随机 nonce）、Metadata 抹除、多 Section 数据段加密（HMAC 认证）、完整性锚点（HMAC 绑定 rootKey + **白盒 PRF 5 域 S-box**）、结构混淆、**符号表混淆**（Pass 6 SymbolStripper）、**AntiDebug 注入计划 ABI**（Pass 7 AntiDebugInjector）、**ARM64 指令替换**（Pass 8 InstructionSubstitution）以及 **CFF 策略编排**（Pass 9 ControlFlowOrchestrator），强制密钥注入消除零密钥降级；**白盒 PRF 引擎**将 root key 融入 ~160KB S-box 查找表不可逆提取，anchor 校验、字符串解密密钥、数据段加载密钥、签名材料全部通过白盒 PRF 派生，内存 dump 无法还原原始密钥；**AppSigningIdentityDetector** 检测重打包/重签名（TeamID/bundleID/entitlement 一致性 + 基线漂移 + integrity poison 联动）；**SDK 以 library.static 交付**，全部代码静态链入 App 二进制后执行 `strip -x` + `strip` 全量剥离，IDA 中 SDK 函数显示为 `sub_XXXX`，消除静态分析与逆向还原特征；**Codable 短别名 CodingKeys** 消除 Small String Optimization 导致的指令流字符串泄漏；**Anti-Dump 页面保护**（`vm_region_64`）检测攻击者重映射，**密钥安全清零**覆盖全部中间态敏感材料；**内联 SHA-256 + 自包含 Mach-O 解析**消除 CommonCrypto 与 dyld API 的 Hook 攻击面，阻断 Clean Copy 攻击；**渗透式毒化**将壳完整性 material 绑定到 ReportEnvelope 签名派生链（v2a），篡改即签名失效而非 crash，攻击者无法定位防护点；**字符串全量混淆**（`ObfuscatedJailbreakStrings`）防止静态特征提取；**DualPathValidator 双路/三路验证**确保检测结果不被单点绕过；**HMAC-SHA256 签名**覆盖报告全字段防篡改，**SignedRiskConclusion v2** 将 signals 摘要纳入签名域；**Keychain + AES-GCM 加密存储**保护本地数据与历史记录，**Keychain 策略统一** `AfterFirstUnlockThisDeviceOnly`；**配置签名信任链**（远端 → 缓存 → 运行时）杜绝配置注入，**DEBUG/Release 行为对齐**消除调试放行路径；**__TEXT 段哈希 + SDK 二进制完整性校验 + 基线交叉验证**检测代码篡改与基线投毒；**Provider 注册表封印 + ConditionExpression 封印 + 实例锁定**防止运行时替换；**ServerSignals HMAC 来源校验 + Challenge HMAC 校验**防止注入伪造信号与中间人篡改挑战结果；**动态可疑特征列表**支持服务端热更新检测规则；**Frida 五维对抗**（线程 / 端口 / V8 堆 / Socket / 时序）全覆盖；**LibcPrologueGuard + KernelHookSideChannel** 实现 Inline Hook 穿透与内核级 Hook 侧信道检测；**IntegrityBaselineEnvCheck** 首启环境把关防止基线投毒；**App Attest 强制模式** 消除所有静默降级路径；**行为数据用后清零**防止内存 Dump 提取。

### 盲区三：PhysicalSensorProbe 预热与支付场景 UX

`PhysicalSensorProbe` 采集 CoreMotion 与气压计数据，同步采集约需 0.5–1.5 秒，在 `.payment` 场景会阻塞主流程。SDK 采用**后台异步预热 + 缓存**机制：

| 机制 | 说明 |
|------|------|
| **预热** | `start()` 时在后台队列异步调用 `PhysicalSensorProbe.prewarm()`，不阻塞主流程 |
| **缓存** | `detect()` 优先读缓存，命中且未过期时**零阻塞**直接返回；缓存 TTL 60 秒 |
| **采样** | 15 帧 @ 30 Hz ≈ 0.5 秒，气压计 1 秒；兜底超时 2 秒 |

**支付场景最佳实践**：应在 `start()` 后**至少 0.5 秒**再调用 `evaluate(scenario: .payment)`，以便预热完成；若用户进入支付页前已有足够停留时间（如浏览商品），通常已命中缓存。

---

### 盲区四：代码段哈希校验与服务端参考哈希

`__TEXT.__text` 代码段哈希用于检测 inline patch（函数替换、指令修改）。客户端优先使用 **RemoteConfig.textSegmentHashReference** 下发的服务端参考哈希，无下发时回退到 Keychain 本地基线。

**服务端参考哈希机制（越狱场景下的可信锚点）**：

| 角色 | 职责 |
|------|------|
| **服务端** | 维护 `sdkVersion -> expectedHash` 映射表；每个 SDK 版本发布时预计算并入库；通过 RemoteConfig 下发 `textSegmentHashReference` |
| **客户端** | 计算当前 `__TEXT.__text` 的 SHA-256 作为 `currentHash`，在 `textSegmentIntegrity` 中上报 `currentHash`、`sdkVersion` 以及 `referenceSource/referenceVersion/usedServerReference` 等观测字段 |
| **服务端二次校验** | 收到上报后，用 `sdkVersion` 查 `expectedHash`，与 `currentHash` 对比；不一致则判定篡改 |

**为何需要服务端参考哈希**：越狱环境下 Keychain 可被替换，攻击者可写入「已篡改」的哈希作为本地基线，使客户端误判为 intact。服务端参考哈希由发布流程预计算，不依赖客户端存储，**Keychain 被越狱篡改时仍可信**。

**扩展点**：若业务方已有独立的签名配置中心，可通过 `CPRiskKit.setTextSegmentReferenceResolver(_:)` 注入自定义参考哈希解析器；未注入时默认仍复用 `RemoteConfig.textSegmentHashReference`。

### 攻击者视角绕过成本对照表

从攻击者经济学的角度，不同检测维度的绕过成本差异显著，体现纵深防御的设计价值：

| 攻击目标 | 最低绕过成本 | 需要的工具链 | 估算工时 |
|----------|--------------|--------------|----------|
| 绕过 DYLD 扫描 | 极低 | Frida 脚本、dylib 隐藏 | 30 分钟 |
| 绕过单点检测（如 PLT 校验） | 低 | 二进制 patch、inline hook | 数小时 |
| 绕过代码段哈希（服务端参考） | 高 | 需伪造服务端或篡改 SDK 发布流程 | 数天 |
| 绕过白盒 PRF 提取 root key | 极高 | 需完整提取 160KB S-box + 逆向 4 轮 SPN 算法 | 理论不可行 |
| 绕过反重打包（TeamID 校验） | 高 | 需 patch 二进制 + 绕过 integrity poison + 基线漂移 | 数天 |
| 绕过全部 8 维 Frida 对抗 | 极高 | Frida 重编译、多维度绕过、时序侧信道消除 | 数周 |
| 物理层/传感器检测 | 架构级成本 | 需改造硬件或高保真 MEMS 仿真 | 无法绕过 |

**纵深防御的经济学意义**：攻击者若仅绕过单点（如 DYLD），仍会触发其他维度；若要全面绕过，需投入与维护成本呈指数级增长，使批量攻击在经济上不可行。

---

## 灰度与降级机制

SDK 在对抗安全的同时兼顾业务可用性，内置多层灰度与降级保护：

### 紧急熔断开关（Kill Switch）

通过 `RemoteConfig.securityHardening.killSwitchEnabled` 远程下发，启用后决策引擎强制返回 `score=0 / action=allow`，所有高风险拦截立即失效。用于线上误杀事故时快速止血，无需发版。

### 远程配置熔断器（Circuit Breaker）

`RemoteConfigProvider` 内置三态熔断器（closed → open → half-open）：

| 状态 | 行为 |
|------|------|
| **closed** | 正常拉取远程配置 |
| **open** | 连续失败 ≥3 次后触发，跳过拉取，直接返回当前配置 |
| **half-open** | 冷却期（30s→60s→120s→300s 递增）过后允许一次探测请求 |

熔断对调用方透明，`fetchLatest()` 在 open 状态下返回 `.success(currentConfig)` 而非错误。

### 配置降级链

远程配置不可用时，SDK 按以下优先级回退：

1. **内存缓存**：最近一次成功拉取的配置
2. **磁盘缓存**：`ConfigCache` 持久化的 verified 配置（Release 下仅接受已验签且未过期的缓存）
3. **本地默认配置**：`RemoteConfig.default` / `config.toSwift()`
4. **安全地板强制**：无论使用哪层配置，Release 下关键检测开关始终强制开启

配置过期（超过 `cacheValidityDuration`）时注入 `remote_config_stale` 软信号（weight=10），供服务端感知。

### 签名降级（v2a → v2）

`buildSecureReportEnvelope` 在 armor 运行时不可用时的行为：

| `requireArmor` | armor 状态 | 行为 |
|:---:|:---:|------|
| `true`（默认） | 不可用 | 抛出 `armorRuntimeUnavailable`，调用方需处理 |
| `false` | 不可用 | 降级为 v2 签名（不含 armor material），报告仍可提交 |

服务端应根据 `signatureVersion` 字段（`v2a` vs `v2`）调整信任评估。

### 检测器容错

| 场景 | 降级行为 |
|------|----------|
| 检测器超时 / 异常 | 返回 `score=80`（高风险），避免静默放过 |
| PhysicalSensorProbe 冷启动 | 返回 `pending_prewarm`（score=0），后台预热 |
| Keychain 不可用 | 降级到 UserDefaults；两层都失败返回 `ephemeral:` 前缀 ID |
| App Attest 不可用 | `requireAttestation=true` 时 throw；`false` 时降级为普通 HMAC |

---

## 文档索引

| 文档 | 路径 |
|------|------|
| SDK 使用与构建说明 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_使用说明.md` |

---

## 构建

```bash
cd RiskDetectorApp && swift build
```

## 测试

单元测试通过 Swift Package Manager 运行。Xcode scheme 的 TestAction 若为空，默认可使用：

```bash
cd RiskDetectorApp && swift test
```

如需隔离构建目录（避免与并发任务共享 `.build`），可使用：

```bash
cd RiskDetectorApp && swift test --scratch-path "${TMPDIR:-/tmp}/cloudphone-risk-detector-riskdetector-tests"
```

若使用 XcodeGen 生成工程（`xcodegen generate`），则 `CloudPhoneRiskKitTests` 与 `CloudPhoneRiskAppCoreTests` 会加入 scheme，可在 Xcode 中直接运行测试。

---

## 免责声明

本 SDK 仅用于合法合规的应用安全与风控场景。使用者须确保符合当地法律法规及 Apple 开发者协议。作者不对因滥用本工具造成的任何后果承担责任。SDK 的检测结果为辅助判定信号，不构成最终风控决策，建议结合服务端策略综合使用。

---

<p align="center"><sub>CloudPhoneRiskKit 6.8 — 控制流平坦化 + Pass 9 + 反去混淆 (9 Pass)</sub></p>
