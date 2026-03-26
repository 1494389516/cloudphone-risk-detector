<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-7.3-FF3B30?style=for-the-badge" alt="SDK">
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
| **6.8** | **反调试 Runtime Gate + Pass 10/11 + CFF/白盒强化** | `__thread_init` 早期异常端口抢占与竞态回收、AntiDebug plan 运行时 inline patch gate（`BRK #0xC0E0`）、Unix syscall vs Mach 路径交叉校验、Frida 协议指纹与可选全端口扫描、多频 watchdog + 互监 deadline、关键路径 timing canary、白盒 PRF 增强扩散层、Pass 10 ImportEncryptor、Pass 11 HeaderEncryptor、CFF 新增 `splitIndirect` dispatcher 与 `affine` 编码风格、CFF 覆盖建议器 |
| **7.0** | **TextSegmentEncryptor + VMProtector(M3) + 13 Pass 收口** | Pass 12 `TextSegmentEncryptor` 对 `__TEXT.__text` 做页级加密并写入 `__swift5_cgenc` 元数据，Pass 13 `VMProtector` 对 7 个高价值函数执行“ARM64 → 自定义字节码 + VM 入口跳板”虚拟化，运行时新增 `cprisk_vm_interpreter`、`__swift5_mdvrt/__swift5_mdirt` section、M2 handler 变体 / VPC 仿射编码 / 更多 ARM64 lift 覆盖，以及 M3 解释器自身 CFF 接线、dead handler 注入、VPC 不透明谓词链与可选自校验门控 |
| **7.1** | **VM 自校验链路对齐 + dispatcher 跨单元散布 + 合规文档收口** | VM self-check 改为优先消费 `__swift5_mdvsi` span map 驱动注入与运行时校验，`cprisk-vm-self-expect` 同时支持 CPSF/CPSH（FNV/HMAC）产物写入；解释器主 dispatcher 延续函数指针表架构，并将 22 个 `cprisk_vm_oph_*` handler 拆分到多个 `.c` 编译单元，减少单文件语义聚合；同步更新 SDK 隐私声明与 App Store 合规文档，明确 7.1 加固升级不扩大 collected data / Required Reason API 边界 |
| **7.2** | **MIE/MTE 姿态接入 + iPhoneOS 26 SDK 构建兼容** | Release 构建接入 `CPRISK_MTE_COMPILE_SUPPORT` 与 `ENABLE_ENHANCED_SECURITY`，新增 `cprisk_mte_guard` / `MIEPostureDetector`，通过 sysctl + 本地快照 + region canary 保守感知 Apple Memory Integrity Enforcement 姿态，并补齐 `HoneypotMemoryDetector` 在 iPhoneOS 26 SDK 下的 `ucontext_t` / PC 字段兼容路径，使 `xcodebuild -sdk iphoneos` 恢复全绿 |
| **7.3** | **文档与版本收口** | README 移除冗长 6.x 独立章节；`CloudPhoneRiskKit_文档` 与合规/隐私声明统一为 7.3；`Version.current` 与对外 SDK 版本号对齐 |
## 架构概览

```
┌────────────────────────────────────────────────────────┐
│        Layer 0: 自研壳 (cprisk-armor) ABI v2 / 13 Pass    │
│   全量字符串加密+HMAC / 多 Section 数据段加密+HMAC       │
│   完整性锚点 HMAC / Metadata 抹除 / 结构混淆 / Anti-Dump │
│   Pass 6 符号表混淆 / Pass 7 Runtime Gate / Pass 8 指令替换 │
│   Pass 9 CFF 编排 / Pass 10 ImportEncryptor / Pass 11 HeaderEncryptor │
│   Pass 12 Text Encrypt / Pass 13 VMP(M3) / 全量 strip    │
│   白盒 PRF (5域 S-box ~160KB, 强扩散) / 反重打包 TeamID │
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

## 7.1 新增能力 — VM Self-Check 对齐 + Dispatcher 跨单元散布

7.1 在 7.0 的 TextSegmentEncryptor、VMProtector(M3) 与解释器自保护基础上，继续把 VM runtime 本身往“更难静态切片、更难单点伪造”的方向推进，重点补齐三条链路：第一，**self-check expect blob 链路从硬编码符号窗口升级为 CPSV span map 驱动**，即由 `__DATA.__swift5_mdvsi` 记录的三段 TEXT 窗口统一驱动注入器与运行时校验，减少 producer / runtime 偏移；第二，**self-check CLI 同时支持 CPSF/FNV 与 CPSH/HMAC**，便于交付时直接生成两种 expect blob；第三，**全局 opcode dispatcher 在保留函数指针表架构的前提下，将 22 个 `cprisk_vm_oph_*` handler 拆分到多个编译单元**，降低单文件聚合语义暴露面，使 pattern-based 恢复更依赖跨 TU 还原。

### 7.1 核心改动

| 改动 | 说明 |
|------|------|
| **CPSV span map 驱动 self-check** | `VMSelfExpectInjector` 优先读取 `__swift5_mdvsi`（CPSV）而不是只依赖 `_cprisk_vm_execute / _cprisk_vm_interp_loop_a / _cprisk_vm_dispatch_lookup` 三符号硬编码布局，注入与 runtime hash/HMAC 共享同一窗口定义 |
| **CPSF / CPSH 双路径 CLI** | `cprisk-vm-self-expect` 支持传统 CPSF/FNV 与 CPSH/HMAC 写入，可通过参数选择写入模式并在交付链路中显式控制 |
| **runtime 自校验对齐 producer span** | `cprisk_vm_interpreter.c` 在 M3 self-check 时优先消费 `__swift5_mdvsi` 中记录的 span 布局，确保 observed bytes 与 post-link producer 注入字节源一致 |
| **dispatcher 继续去 switch 化** | 主 opcode 路径现在走“family 分流 + single-access handler materialization”(`cprisk_vm_dispatch_oph_materialized_i(...)`)，不回退为大 `switch`，也不再暴露明文 `oph_table[logical]()` 指针总表 |
| **handler 跨编译单元散布** | 22 个 `cprisk_vm_oph_*` handler 已拆到 `cprisk_vm_oph_basic/lane/branch/bitwise/vreg/nested.c` 与 `cprisk_vm_oph_table.c`，减少单文件语义聚合 |
| **隐私/合规文档同步升级** | README、SDK 隐私声明、App Store 合规指南统一升级到 7.1，并明确这些 VM/runtime hardening 不会新增 privacy manifest 的 collected data 类型或 Required Reason API 类别 |

---

## 7.2 新增能力 — MIE/MTE 姿态接入 + iPhoneOS 26 SDK 构建兼容

7.2 在 7.1 的 VM self-check / dispatcher 纵深基础上，开始把 Apple 近代硬件提供的内存完整性能力以“**保守接入、可降级、可解释**”的方式纳入 SDK：第一，Release 构建增加 `CPRISK_MTE_COMPILE_SUPPORT` 与 Xcode `ENABLE_ENHANCED_SECURITY` 路径，使 SDK 在支持设备上可以消费更强的系统内存完整性语义；第二，C 层新增 `cprisk_mte_guard`，通过 `hw.optional.arm.FEAT_MTE*` / `FEAT_PAuth` 等 `sysctl`、本地 self-test、关键区域 baseline hash + tag snapshot canary，对 `runtime material` 与完整性摘要做低侵入防护；第三，Swift 层新增 `MIEPostureDetector`，把设备姿态映射为 `mie_posture`、`mte_inactive_for_process`、`mte_canary_tampered` 等信号，并对高价值内存/注入类信号做轻量上下文加权；第四，同步修复 `HoneypotMemoryDetector` 在 iPhoneOS 26 SDK 下 `ucontext_t`/PC 字段形态变化导致的 `iphoneos` 构建失败问题，通过 C 层统一封装 signal context PC 前移逻辑，恢复 `xcodebuild -sdk iphoneos` 全绿。

### 7.2 核心改动

| 改动 | 说明 |
|------|------|
| **Release 编译期开关接入 MIE** | `Package.swift` / Xcode Release 配置接入 `CPRISK_MTE_COMPILE_SUPPORT`，并为对应 target 打开 `ENABLE_ENHANCED_SECURITY`，使支持设备可暴露更强的 Memory Integrity Enforcement 能力 |
| **C 层 `cprisk_mte_guard`** | 新增 `cprisk_mte_available()` / `cprisk_mte_self_test()` / `cprisk_mte_guard_snapshot()` 与 region-bound canary，围绕关键运行时材料做 baseline hash + top-byte tag 快照校验，在不支持设备上安全降级，不强行执行高风险 MTE 指令 |
| **Swift 层 `MIEPostureDetector`** | 通过 `sysctl` + CRiskCore 本地快照评估 `none / pacOnly / miePartial / mieFull` 四级姿态，并输出 `mie_posture`、`mte_unavailable_on_capable_device`、`mte_inactive_for_process`、`mte_canary_tampered` 等信号 |
| **反篡改权重上下文增强** | `AntiTamperingSignalProvider` 在 `miePartial / mieFull` 下对匿名可执行内存、Frida、文本段篡改等高价值信号做小幅上下文加权，同时把 `device_mie_level` 注入证据域，便于服务端解释 |
| **隐私/合规文档同步升级** | README、SDK 隐私声明、App Store 合规指南、架构/威胁模型文档统一补充 MIE 能力边界，明确该能力通常只在 A17 / A17 Pro 及后续较新产品线上更可能观察到相关位形，且不新增 collected data 或用户内容采集 |
| **iPhoneOS 26 SDK 兼容修复** | `HoneypotMemoryDetector` 不再在 Swift 中直接假设 `ucontext_t` 的 `__pc / __opaque_pc` 形态，而改为调用 C 层 `cprisk_advance_ucontext_pc(...)` 做统一适配，消除 arm64 / arm64e 下的新 SDK 接口差异 |

---

## 7.0 新增能力 — Pass 12/13 + VMP M3 收口

7.0 在既有壳链（runtime gate、Pass 10/11、源码级 CFF）之上，完成了当前自研壳链路的两块关键拼图：第一，新增 **Pass 12 `TextSegmentEncryptor`**，对 `__TEXT.__text` 做页级加密并写入 `__swift5_cgenc` 元数据，使关键代码在静态视角下进一步密文化；第二，新增 **Pass 13 `VMProtector`**，对策略指定的 7 个高价值函数执行“原生 ARM64 指令 → 自定义 VM 字节码 + VM 入口跳板”的转换，运行时由 `CRiskCore` 中嵌入的 `cprisk_vm_interpreter.c` 解释执行；第三，在 VMP 基础上完成 **M3**：解释器自身纳入 CFF 接线、dispatch/bytecode 新增 dead handler 元数据与 VPC 不透明谓词链，运行时加入 dead bait handler、opaque predicate chain 与可选自校验门控，从而把对抗重点从“加密 + CFF”进一步推进到“虚拟化 + 反分析”。

### 7.0 核心改动

| 改动 | 说明 |
|------|------|
| **Pass 12: TextSegmentEncryptor** | 对 `__TEXT.__text` 内页做页粒度加密，元数据写入 `__DATA.__swift5_cgenc`，运行时按页恢复，增强静态反编译与字符串/控制流恢复难度 |
| **Pass 13: VMProtector** | 构建期新增 ARM64 lifter、VMIR、opcode table、bytecode emitter、entry trampoline rewriter；运行时新增 `cprisk_vm_interpreter` 执行自定义字节码 |
| **VMP section 伪装落地** | dispatch/bytecode 分别写入 `__DATA.__swift5_mdvrt` 与 `__DATA.__swift5_mdirt`，避免显式泄露壳结构语义 |
| **7 个高价值函数虚拟化** | 当前 `vmp_policy.yaml` 将 `RiskDetectionEngine`、`DecisionTree`、`ChallengeSession`、`TrustChainManager` 的 7 个关键函数纳入 full tier |
| **M2 指令扩展** | 覆盖 `MOVZ/MOVK`、`ADRP+ADD` 融合、`CSEL/CSET`、`CBZ/CBNZ`、`B.cond`、基础 `LDR/STR` 等模式，降低 VM 前导 lift 的回退率 |
| **M2 反分析** | handler 变体池、多态 opcode table、VPC 仿射编码、per-entry/global affine metadata、dispatch tail 扩展 |
| **M3 解释器自身加固** | `cff_policy.yaml` 将 `cprisk_vm_entry` / `cprisk_vm_execute` 纳入 medium tier，Pass 9 已能直接改写解释器入口指令 |
| **M3 dead handler 注入** | dispatch 表注入诱饵 raw opcode 映射，运行时存在 dead bait handler 路径，增加 pattern-based 语义恢复成本 |
| **M3 opaque VPC 链** | 构建期写入 VPC predicate constants，运行时以不透明谓词链包裹 dispatch loop，使解释器 CFG 非线性化 |

## 壳保护工作流

```
源码 → swift build → SDK (library.static) + App 链接
                          ↓
                    App 二进制 (SDK 代码静态链入)
                          ↓
                    cprisk-armor CLI (13 Pass, ABI v2)
                    --key <hex> / --key-file / CPRISK_ARMOR_KEY
                    ┌─ Pass 1: StringEncryptor       (白盒 PRF 密钥 + HMAC + nonce)
                    ├─ Pass 2: MetadataScrubber      (元数据抹除)
                    ├─ Pass 8: InstructionSubstitution(1:1 等长指令替换)
                    ├─ Pass 4: IntegrityAnchor       (HMAC 锚点 + 白盒 PRF 5域)
                    ├─ Pass 3: DataSegmentEncryptor  (白盒 PRF 密钥 + HMAC + nonce)
                    ├─ Pass 5: StructureObfuscator   (结构混淆, 安全随机)
                    ├─ Pass 7: AntiDebugInjector     (anti-debug 注入计划 __cpr_adbg7)
                    ├─ Pass 6: SymbolStripper        (SDK 符号表混淆)
                    ├─ Pass 10: ImportEncryptor      (导入表加密)
                    ├─ Pass 11: HeaderEncryptor      (Header 加密)
                    ├─ Pass 12: TextSegmentEncryptor (__TEXT 页级加密)
                    └─ Pass 13: VMProtector          (函数虚拟化 / VM 跳板)
                          ↓
                    xcrun strip -x && xcrun strip  (全量符号剥离)
                          ↓
                    App 二进制 (加固后, IDA 中 sub_XXXX)
                          ↓
                    运行时 CRiskCore
                    白盒 PRF / HMAC 验证 → 解密 + 完整性校验 + Anti-Dump + VM 解释执行
                    白盒派生 armor material → ReportEnvelope v2a
```

### 渗透式防护原理

传统壳检测到篡改后通常 crash 退出，容易被攻击者二分搜索定位。6.0 采用**渗透式毒化**：

1. 完整性锚点哈希参与 KDF 派生解密密钥 → 篡改后密钥错误 → 字符串/数据解密失败
2. armor runtime material 混入 ReportEnvelope HMAC 密钥 → 签名静默失效
3. 服务端拒绝异常签名 → 攻击者无法区分"壳被绕过"还是"业务后端异常"
4. 不产生显式 crash / abort → 攻击者无法通过 signal handler 或 exit code 定位防护点


## 项目结构

```
.
├── cprisk-armor/                         # 编译后壳工具链 (SPM CLI)
│   ├── Sources/
│   │   ├── cprisk-armor/                  # CLI 入口 (13 Pass 编排)
│   │   ├── MachOKit/                     # Mach-O 读写库
│   │   ├── StringEncryptor/              # Pass 1: 全量字符串加密
│   │   ├── MetadataScrubber/             # Pass 2: Metadata 抹除
│   │   ├── DataSegmentEncryptor/         # Pass 3: 多 Section 数据段加密
│   │   ├── IntegrityAnchor/              # Pass 4: 完整性锚点
│   │   ├── StructureObfuscator/          # Pass 5: 结构混淆
│   │   ├── SymbolStripper/               # Pass 6: 符号表混淆
│   │   ├── AntiDebugInjector/            # Pass 7: anti-debug 注入计划
│   │   ├── InstructionSubstitution/      # Pass 8: ARM64 指令替换
│   │   ├── ControlFlowOrchestrator/      # Pass 9: CFF 策略编排
│   │   ├── TextSegmentEncryptor/         # Pass 12: __TEXT 页级加密
│   │   └── VMProtector/                  # Pass 13: VMP 虚拟化
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
│   │   │   ├── cprisk_vm_interpreter.c   # Pass 13 VM 运行时解释器
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
| SDK 隐私声明 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_SDK_隐私声明.md` |
| App Store / 接入合规指南 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_AppStore_合规指南.md` |

---

## 构建

```bash
cd RiskDetectorApp && swift build
```

如需验证 Xcode 工程在设备 SDK 下的 Release 构建，可使用：

```bash
cd RiskDetectorApp && xcodebuild -project RiskDetectorApp.xcodeproj -target CloudPhoneRiskKit -configuration Release -sdk iphoneos build CODE_SIGNING_ALLOWED=NO
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

<p align="center"><sub>CloudPhoneRiskKit 7.3 — documentation &amp; version alignment</sub></p>
