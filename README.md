<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-7.4-FF3B30?style=for-the-badge" alt="SDK">
  <img src="https://img.shields.io/badge/SPM-Compatible-34C759?style=for-the-badge&logo=swift&logoColor=white" alt="SPM">
  <img src="https://img.shields.io/badge/License-TBD-8E8E93?style=for-the-badge" alt="License">
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

## 开源发布入口

这个仓库的代码密度更接近“端侧风控 SDK + 反篡改实验室”，而不是单点 jailbreak detector。为了让外部开发者能快速判断是否值得接入，建议从下面几件事开始：

| 你想确认什么 | 入口 |
|--------------|------|
| 三分钟跑起来 | `cd RiskDetectorApp && swift test --disable-sandbox` |
| 最小接入代码 | [集成方式](#集成方式) 与 `CloudPhoneRiskKit_文档/INTEGRATION_GUIDE.md` |
| 能力边界和安全模式 | `CloudPhoneRiskKit_文档/OPEN_SOURCE_READINESS.md` |
| 性能目标和基准方法 | `CloudPhoneRiskKit_文档/PERFORMANCE_BENCHMARK.md` |
| App Store / 隐私披露 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_AppStore_合规指南.md` |
| 攻击者模型和剩余风险 | `CloudPhoneRiskKit_文档/威胁模型文档.md` |

### 能力分层

| 模式 | 推荐场景 | 特点 |
|------|----------|------|
| `App Store Safe` | 普通 App Store 分发 | 以本地风险信号、合规权限、低侵入检测为主，避免审核敏感能力默认打开 |
| `Enhanced` | 高风险业务场景 | 启用更完整的 anti-tamper、环境一致性和服务端信号融合 |
| `Research / Enterprise` | 企业包、安全研究、内部灰度 | 可打开更强的反调试、动态插桩、运行时完整性探针 |
| `Armored Release` | 加固发布产物 | 配合 `cprisk-armor`，把壳保护、白盒派生、签名材料毒化纳入生产链路 |

### 重要边界

`CloudPhoneRiskKit` 输出的是风险信号和策略建议，不承诺在本地完全受控的攻击环境中“不可绕过”。正确用法是把端侧检测、服务端策略、账号/设备画像、挑战验证和人工审核组合起来，提高攻击成本并降低批量化成功率。

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
| **7.0** | **TextSegmentEncryptor + VMProtector(M3) + 13 Pass 收口** | Pass 12 `TextSegmentEncryptor` 对 `__TEXT.__text` 做页级加密并写入 `__swift5_cgenc` 元数据，Pass 13 `VMProtector` 对 7 个高价值函数执行"ARM64 → 自定义字节码 + VM 入口跳板"虚拟化，运行时新增 `cprisk_vm_interpreter`、`__swift5_mdvrt/__swift5_mdirt` section、M2 handler 变体 / VPC 仿射编码 / 更多 ARM64 lift 覆盖，以及 M3 解释器自身 CFF 接线、dead handler 注入、VPC 不透明谓词链与可选自校验门控 |
| **7.1** | **VM 自校验链路对齐 + dispatcher 跨单元散布 + 合规文档收口** | VM self-check 改为优先消费 `__swift5_mdvsi` span map 驱动注入与运行时校验，`cprisk-vm-self-expect` 同时支持 CPSF/CPSH（FNV/HMAC）产物写入；解释器主 dispatcher 延续函数指针表架构，并将 22 个 `cprisk_vm_oph_*` handler 拆分到多个 `.c` 编译单元，减少单文件语义聚合；同步更新 SDK 隐私声明与 App Store 合规文档，明确 7.1 加固升级不扩大 collected data / Required Reason API 边界 |
| **7.2** | **MIE/MTE 姿态接入 + iPhoneOS 26 SDK 构建兼容** | Release 构建接入 `CPRISK_MTE_COMPILE_SUPPORT` 与 `ENABLE_ENHANCED_SECURITY`，新增 `cprisk_mte_guard` / `MIEPostureDetector`，通过 sysctl + 本地快照 + region canary 保守感知 Apple Memory Integrity Enforcement 姿态，并补齐 `HoneypotMemoryDetector` 在 iPhoneOS 26 SDK 下的 `ucontext_t` / PC 字段兼容路径，使 `xcodebuild -sdk iphoneos` 恢复全绿 |
| **7.3** | **工程产品化 + 文档体系收口** | 多实例进程隔离（IsolationContext）、ABI 语义化版本契约（v1.0.0）、主入口模块拆分（2928→395 行 + 6 extension）、OpenAPI/Protobuf 服务端协议标准化、性能基准测试套件、XCFramework 构建指南、CocoaPods 集成说明（文档）、多租户密钥管理与轮换（TenantKeyManager）、SLA 文档（TPR≥99.2% / FPR≤0.05%）、标准 CHANGELOG（Keep a Changelog）、接入工时评估（<2h/<4h/<8h 三路径）、Objective-C 完整桥接层、SDK Portal 控制台设计规范、17 份文档归一化至 `CloudPhoneRiskKit_文档/` |
| **7.4** | **白盒密钥链重建 + CFF 修复 + 反调试纵深 + 检测链证明** | WB#4 字符串解密生产 Bug 修复（per-string KDF 双端对齐）、WB#14 configDigest 格式锁定（标签+长度前缀）、WB#5 Path-A 计数器防密钥流重用、P0b 消除 BSS 明文神谕、S-box 模偏消除 + 8-bit 升级、CFF#23 B.cond 块边界修复、CFF#24 PACIASP/PACIBSP 序言探测、P1a Dispatcher 逐函数随机化（消除 TBZ#0 模板化特征）、Mach 端口基线 8 样本校准、反 Dump 探针 [2,9]s 随机抖动、SW BP 扫描 24 窗口扩展、Watchdog 启动失败异常标志、per-session 检测链 HMAC 证明（`cprisk_detection_attest`）、`DetectorID` 枚举化、PayloadFieldObfuscator DepthScope.all + 会话派生字段映射、ABI v3 跨语言一致性测试（17 项安全修复） |

---

## 架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 0 · cprisk-armor  (ABI v2 · 13 Pass · White-Box PRF 5域)   │
│  字符串加密 │ Metadata 抹除 │ 数据段加密 │ 完整性锚点 │ 结构混淆    │
│  符号混淆 │ Runtime Gate │ 指令替换 │ CFF 编排 │ 导入表/Header 加密  │
│  __TEXT 页级加密 │ VMProtector (M3 · 自定义字节码解释器)            │
│  白盒 PRF (160 KB S-box · 强扩散) │ 反重打包 TeamID/签名链          │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1 · 端侧决策引擎        RiskDetectionEngine                 │
│  场景策略 ─ 决策树 ─ 组合规则 ─ 盲挑战 ─ HMAC v2a 签名             │
│  安全地板强制 · 关键信号权重下限 · 超时 fail-closed · 三态熔断器     │
├───────────┬───────────────┬────────────┬────────────────────────────┤
│ 硬件指纹   │  一致性 & 对抗  │  行为熵     │  服务端聚合                │
├───────────┼───────────────┼────────────┼────────────────────────────┤
│ GPU 渲染   │ PLT/GOT       │ 触摸熵      │ 公网 IP / ASN             │
│ DRM 等级   │ RWX 内存扫描   │ 传感器熵    │ 机房属性                  │
│ 电池物理熵  │ ObjC Swizzle  │ 电压方差    │ IP 设备聚合度             │
│ Board ID  │ DYLD Interpose │ 时序模式    │ 图特征反哺                │
│ 设备型号   │ SVC 双路校验   │ 耦合分析    │ 风险标签                  │
│ 指纹突变   │ 代码段哈希     │ 行为充足性   │ 黑名单                   │
│ MIE 姿态   │ 线程枚举异常   │ 传感器回放   │                          │
│           │ 异常端口劫持   │            │                           │
│           │ V8 堆 / Socket │            │                          │
│           │ 时序侧信道     │            │                           │
│           │ ptrace 防附加  │            │                           │
│           │ 多路径一致性   │            │                           │
│           │ 内核 Hook 侧信道│           │                           │
│           │ SDK 自校验     │            │                           │
└───────────┴───────────────┴────────────┴────────────────────────────┘
```

### 信号分类与权重

| 类型 | 判定逻辑 | 典型信号 | 权重范围 |
|------|----------|----------|----------|
| **硬信号** | 本地独立判定，单点即可触发 | 越狱文件、DRM 降级、ChargeCounter 异常、PLT 篡改、ObjC Swizzle、异常端口劫持、SDK 二进制替换、DYLD Interpose、代码签名链断裂 | 80 – 100 |
| **软信号** | 需结合场景综合评分 | VPN、行为异常、电压方差低、挂载点异常、时序侧信道、线程枚举异常、指纹突变、行为数据不足、传感器回放 | 30 – 75 |
| **服务端信号** | 依赖外部聚合接口 | 机房 IP、ASN 黑名单、IP 设备聚合度、图社区风险、硬件画像聚集 | 55 – 100 |

---

## 检测能力矩阵

| 检测域 | 规模 | 关键技术 |
|--------|------|----------|
| 越狱检测 | 11 Detectors | 路径/符号/挂载点/沙盒/环境变量/dylib/链接器/URL Scheme/fork/写入测试/指针验证 |
| 反篡改 & 抗绕过 | 33 Detectors | Frida 8 维全覆盖（线程/堆/模块/Socket/时序/运行时共识）、PLT/GOT、RWX、ObjC Swizzle/Inline Hook、DYLD Interpose、异常端口、SDK 二进制校验、代码段哈希、DualPathValidator 三路校验、SVC 直调、匿名内存隐写、fsid 隔离、指令计数器双路、AppSigningIdentity 反重打包、LLDB JIT、TaskPort Audit |
| 反绕过增强 | 9 Detectors | LibcPrologueGuard、MultiPathConsistency、RuntimeIntegrityValidator、SDKBinaryIntegrity、TextSegmentIntegrity、FingerprintDeobfuscation、IntegrityBaselineEnvCheck、RandomizedDetection、MultiPathFileDetector |
| 硬件信任根 | 2 | App Attest（TOCTOU 安全 + requireAttestation 强制）、Secure Enclave 硬件绑定签名 |
| 执行流 & 内存 | 3 | CallStack ROP/JOP 链检测、Syscall Canary 探针致盲、HoneypotMemory 三页 + SIGBUS |
| 内核 Hook 侧信道 | 4 策略 | 时序分布 / inode 一致性 / 时钟交叉 / 返回值熵 |
| 物理环境探测 | 19 Providers | GPU 渲染指纹、DRM、电池熵、Board ID、IMU 噪声谱、传感器回放、显示 Mux、生物特征、音频路由、Baseband 隔离、网络接口、时间模式、设备年龄、硬件能力、环境一致性、分层一致性、VPhone 硬件 |
| 行为信号 | 4 | 触摸捕获、运动采样、行为耦合、行为信号聚合 |
| 服务端聚合 | 4 维 | 公网 IP/ASN、机房属性、IP 设备聚合度、图特征反哺 |

> 检测器总计 **80+**，覆盖从硬件到内核到用户态到网络的完整攻击面。

---

## 壳保护工作流

```
源码 ──swift build──▶ SDK (library.static) ──Link──▶ App 二进制
                                                        │
                     cprisk-armor CLI  ◀────────────────┘
                     (13 Pass · ABI v3 · CPRISK_ARMOR_KEY)
                     ┌─ Pass  1  StringEncryptor         白盒 PRF + HMAC + nonce
                     ├─ Pass  2  MetadataScrubber        元数据抹除
                     ├─ Pass  8  InstructionSubstitution  1:1 等长语义等价替换
                     ├─ Pass  4  IntegrityAnchor          HMAC 锚点 + 白盒 5域
                     ├─ Pass  3  DataSegmentEncryptor     白盒 PRF + HMAC + nonce
                     ├─ Pass  5  StructureObfuscator      假 Section + 随机布局
                     ├─ Pass  7  AntiDebugInjector        __cpr_adbg7 注入计划
                     ├─ Pass  6  SymbolStripper           nlist 符号混淆
                     ├─ Pass 10  ImportEncryptor          导入表加密 + HMAC
                     ├─ Pass 11  HeaderEncryptor          Mach-O header 加密
                     ├─ Pass 12  TextSegmentEncryptor     __TEXT 页级加密
                     └─ Pass 13  VMProtector              ARM64→VM 字节码虚拟化
                                    │
                     xcrun strip ◀──┘  → App 二进制 (IDA: sub_XXXX)
                                    │
                     运行时 CRiskCore ◀─┘
                     白盒 PRF/HMAC 验证 → 解密 + 完整性校验 + Anti-Dump + VM 解释执行
                     白盒派生 armor material → ReportEnvelope v2a 签名
```

### 渗透式毒化

传统壳检测到篡改后 crash → 攻击者二分搜索定位。本 SDK 采用**静默毒化**：

1. **KDF 链路投毒** — 完整性锚点哈希参与密钥派生 → 篡改后密钥链断裂 → 字符串/数据解密得到错误明文
2. **签名链路投毒** — armor runtime material 混入 HMAC 密钥 → 服务端验签静默失败
3. **无 crash / 无 abort** — 不产生任何显式错误码 → 攻击者无法通过 signal / exit code 区分"绕过成功"与"后端异常"
4. **多 Lane 独立投毒** — 15 条投毒 Lane（watchdog / code_signing / exception / anti_dump / whitebox / CFF ...），每条有独立 epoch 与去相关 XOR 窗口

---

## SDK 工程架构

### 模块拆分

主入口 `CPRiskKit` 采用 class + extension 拆分模式（主文件 395 行）：

| 模块 | 职责 |
|------|------|
| `CPRiskKitConfiguration` | 信号 ID、混淆常量、自适应配置、Armor 状态枚举 |
| `CPRiskKitLifecycle` | `start()` / `stop()` / 观察者绑定 / watchdog 心跳 / provider 注册 |
| `CPRiskKitEvaluation` | `evaluate()` 管线 / 信号采集 / 评分 / 自适应节流 |
| `CPRiskKitArmorBridge` | Armor 运行时初始化 / 材料派生 / anti-debug 模式 |
| `CPRiskKitReporting` | 报告构建 / 安全上报 / 信封签名 / 远程配置 |
| `CPRiskKitDiagnostics` | watchdog 快照 / armor 快照 / async-await 诊断 API |
| `IsolationContext` | 多实例进程隔离 / App Group 共享 / Keychain 命名空间 |
| `CPRiskKitObjCBridge` | Objective-C 完整桥接层（`@objc` enum 包装 + completion handler） |

### 多实例隔离

```swift
// 主 App — 默认上下文
let kit = CPRiskKit.shared

// Keyboard Extension — 独立上下文
let kbKit = CPRiskKit.scoped(
    identifier: "com.app.keyboard",
    group: "group.com.company.app"
)
```

每个 `IsolationContext` 拥有独立的 Keychain prefix、存储路径、评估状态缓存和远程配置引用。

### 多租户密钥管理

`TenantKeyManager` 提供 Keychain-backed 的 per-tenant 密钥全生命周期管理：

| 状态 | 含义 |
|------|------|
| `active` | 当前用于签名/加密的密钥 |
| `pending` | 轮换目标 — grace period 后升格为 active |
| `retired` | 前一版 active，grace period 内仍可用于验证 |
| `revoked` | 紧急撤销 — 永不用于任何操作 |

### C/Swift ABI 契约

`cprisk_armor_abi.h` 声明语义化版本（`CPRISK_ABI_VERSION_MAJOR.MINOR.PATCH`），运行时可通过 `cprisk_abi_version()` 查询。完整兼容性矩阵见 `CloudPhoneRiskKit_文档/ABI_CONTRACT.md`。

---

## 灰度与降级机制

### 紧急熔断（Kill Switch）

`RemoteConfig.securityHardening.killSwitchEnabled` 远程下发 → 决策引擎强制 `score=0 / action=allow` → 所有拦截立即失效。`localKillSwitchOverride` 防止远程配置被劫持后一键关闭防护。

### 三态熔断器（Circuit Breaker）

| 状态 | 行为 |
|------|------|
| **closed** | 正常拉取远程配置 |
| **open** | 连续失败 ≥3 次后触发，跳过拉取，返回当前配置 |
| **half-open** | 冷却期（30s→60s→120s→300s 指数递增）后允许一次探测 |

### 配置降级链

1. **内存缓存** → 2. **磁盘已验签缓存** → 3. **本地默认配置** → 4. **安全地板强制**（Release 下关键开关始终开启）

### 签名降级

| `requireArmor` | armor 状态 | 行为 |
|:---:|:---:|------|
| `true`（默认） | 不可用 | 抛出 `armorRuntimeUnavailable` |
| `false` | 不可用 | 降级 v2 签名（服务端根据 `signatureVersion` 调整信任） |

### 检测器 Fail-Closed

| 场景 | 降级行为 |
|------|----------|
| 检测器超时 / 异常 | 返回 `score=80`（宁可误报不漏过） |
| PhysicalSensorProbe 冷启 | `pending_prewarm`（score=0，后台预热） |
| Keychain 不可用 | UserDefaults 降级 → `ephemeral:` 前缀 ID |
| App Attest 不可用 | 强制模式 throw / 宽松模式降级 HMAC |

---

## 服务端协议

SDK 提供标准化的服务端对接规范：

| 协议格式 | 路径 | 说明 |
|---------|------|------|
| OpenAPI 3.0 | `CloudPhoneRiskKit_文档/api/openapi.yaml` | REST 端点：evaluate / report / config / health |
| Protobuf v3 | `CloudPhoneRiskKit_文档/api/risk_service.proto` | gRPC 服务定义 + 全部消息类型 |

覆盖 `ReportEnvelope`、`ServerSignals`、`ServerRiskPolicy`、`RemoteConfig` 等所有交互结构。

---

## SLA 承诺

| 指标 | 承诺值 |
|------|--------|
| 真阳性率 (TPR) | ≥ 99.2% |
| 误杀率 (FPR) | ≤ 0.05% |
| `evaluate()` P95 延迟 | < 200 ms |
| 冷启动耗时 | < 500 ms |
| Kill Switch 生效时间 | < 30s（配置拉取间隔内） |

完整 SLA 含分场景精度、版本支持矩阵与升级程序，见 `CloudPhoneRiskKit_文档/SLA.md`。

---

## 项目结构

```
.
├── cprisk-armor/                              # 编译后壳工具链 (SPM CLI · 46 源文件 · 19 测试)
│   ├── Sources/
│   │   ├── cprisk-armor/                       # CLI 入口 (13 Pass 编排)
│   │   ├── MachOKit/                           # Mach-O 读写 + ABI + WhiteBox
│   │   ├── StringEncryptor/                    # Pass 1
│   │   ├── MetadataScrubber/                   # Pass 2
│   │   ├── DataSegmentEncryptor/               # Pass 3
│   │   ├── IntegrityAnchor/                    # Pass 4
│   │   ├── StructureObfuscator/                # Pass 5
│   │   ├── SymbolStripper/                     # Pass 6
│   │   ├── AntiDebugInjector/                  # Pass 7
│   │   ├── InstructionSubstitution/            # Pass 8
│   │   ├── ControlFlowOrchestrator/            # Pass 9
│   │   ├── ImportEncryptor/                    # Pass 10
│   │   ├── HeaderEncryptor/                    # Pass 11
│   │   ├── TextSegmentEncryptor/               # Pass 12
│   │   └── VMProtector/                        # Pass 13
│   └── Tests/MachOKitTests/                    # E2E + KDF + WhiteBox + VMP 测试
│
├── RiskDetectorApp/
│   ├── App/                                    # SwiftUI 示例应用
│   ├── Sources/
│   │   ├── CRiskCore/                          # C 自保护核心 (38 .c · 16 .h)
│   │   │   ├── cprisk_integrity.c              # 主初始化 + 完整性校验
│   │   │   ├── cprisk_whitebox.c               # 白盒 PRF 引擎
│   │   │   ├── cprisk_vm_interpreter.c         # VM 运行时解释器
│   │   │   ├── cprisk_vm_oph_{basic,lane,branch,bitwise,vreg,nested,table}.c
│   │   │   ├── cprisk_text_encrypt.c           # __TEXT 页级解密
│   │   │   ├── cprisk_memory_guard.c           # Anti-Dump
│   │   │   ├── cprisk_mte_guard.c              # MIE/MTE 姿态
│   │   │   ├── direct_syscall.c                # SVC #0x80 直调
│   │   │   └── include/ (16 headers)
│   │   ├── CloudPhoneRiskAppCore/              # 应用层编排
│   │   └── CloudPhoneRiskKit/                  # SDK 主体 (186 Swift 文件)
│   │       ├── Core/                            # 主入口 + 6 extension + IsolationContext
│   │       ├── Config/                          # 远程配置 + TenantKeyManager
│   │       ├── Detection/
│   │       │   ├── AntiTampering/ (33)          # 反篡改检测器
│   │       │   ├── AntiBypass/ (9)              # 抗绕过检测器
│   │       │   └── Adapter/                     # 检测器注册 & 适配
│   │       ├── Jailbreak/Detectors/ (11)        # 越狱检测器
│   │       ├── Providers/ (19)                  # 信号 Provider
│   │       ├── Decision/                        # 决策引擎 + 场景策略
│   │       ├── Risk/                            # 报告封装 + v2a 签名
│   │       ├── Internal/CFF/                    # 源码级控制流平坦化
│   │       ├── ObjCBridge/                      # Objective-C 桥接层
│   │       ├── Storage/                         # AES-GCM 加密存储
│   │       ├── TrustChain/                      # 端侧信任根链
│   │       └── Util/                            # SVC 直调 / 混淆 / 加密
│   └── Tests/ (67 files)                        # 单元测试
│
├── CloudPhoneRiskKit_文档/                      # 统一文档中心 (17 文件)
│   ├── CloudPhoneRiskKit_使用说明.md
│   ├── CloudPhoneRiskKit_SDK_隐私声明.md
│   ├── CloudPhoneRiskKit_AppStore_合规指南.md
│   ├── 架构设计文档.md / 威胁模型文档.md
│   ├── ABI_CONTRACT.md                          # C/Swift ABI 兼容性契约
│   ├── SLA.md                                   # 服务等级协议
│   ├── CHANGELOG.md                             # 变更日志 (7.3→3.0)
│   ├── PERFORMANCE_BENCHMARK.md                 # 性能基准报告
│   ├── INTEGRATION_GUIDE.md                     # 集成指南
│   ├── INTEGRATION_COST.md                      # 接入工时评估
│   ├── XCFRAMEWORK_BUILD.md                     # XCFramework 构建
│   ├── SDK_PORTAL_SPEC.md                       # Portal 控制台设计
│   └── api/ (openapi.yaml + risk_service.proto) # 服务端协议规范
│
└── README.md
```

---

## 集成方式

| 方式 | 适用场景 | 预估工时 |
|------|---------|---------|
| **Swift Package Manager** | 最推荐，Git URL 或本地路径 | < 30 min |
| **CocoaPods** | 按 `INTEGRATION_GUIDE.md` 自建 podspec 或 `:path` 引用（仓库内不提供 podspec） | < 1 h |
| **XCFramework** | 预编译二进制分发，无需暴露源码 | < 1 h |
| **手动集成** | 直接拖入源码 + CRiskCore | < 2 h |

详见 `CloudPhoneRiskKit_文档/INTEGRATION_GUIDE.md`。

### 快速开始

```swift
import CloudPhoneRiskKit

// 1. 启动
CPRiskKit.shared.start()

// 2. 评估
let report = CPRiskKit.shared.evaluate(scenario: .payment)
print(report.riskLevel)   // .low / .medium / .high
print(report.action)      // .allow / .challenge / .block

// 3. 安全上报
let envelope = try CPRiskKit.shared.buildSecureReportEnvelope(report: report)
```

### Objective-C 接入

```objc
#import <CloudPhoneRiskKit/CloudPhoneRiskKit-Swift.h>

CPRiskKitObjCBridge *bridge = [[CPRiskKitObjCBridge alloc] init];
[bridge startWithConfig:nil];
[bridge evaluateAsyncWithScenario:CPRiskScenarioObjCPayment
                       completion:^(CPEvaluationResult *result) {
    NSLog(@"score=%ld level=%@", (long)result.score, result.levelName);
}];
```

---

## 构建

```bash
cd RiskDetectorApp && swift build
```

Release（设备 SDK）：

```bash
cd RiskDetectorApp && xcodebuild \
  -scheme CloudPhoneRiskKit \
  -configuration Release \
  -sdk iphoneos build CODE_SIGNING_ALLOWED=NO
```

## 测试

```bash
cd RiskDetectorApp && swift test
```

隔离构建目录（CI 推荐）：

```bash
cd RiskDetectorApp && swift test \
  --scratch-path "${TMPDIR:-/tmp}/cprisk-tests"
```

当前测试规模：**72 个测试文件**，覆盖密码学链路、决策树边界、合规降级、反篡改、CFF 链完整性、armor 集成、跨语言 ABI 一致性、检测链证明、性能基准。

---

## 文档索引

| 分类 | 文档 | 路径 |
|------|------|------|
| **使用** | SDK 使用与构建说明 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_使用说明.md` |
| **使用** | 集成指南 (SPM/CocoaPods/XCFramework) | `CloudPhoneRiskKit_文档/INTEGRATION_GUIDE.md` |
| **使用** | 接入工时评估 | `CloudPhoneRiskKit_文档/INTEGRATION_COST.md` |
| **使用** | XCFramework 构建指南 | `CloudPhoneRiskKit_文档/XCFRAMEWORK_BUILD.md` |
| **合规** | SDK 隐私声明 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_SDK_隐私声明.md` |
| **合规** | App Store 合规指南 | `CloudPhoneRiskKit_文档/CloudPhoneRiskKit_AppStore_合规指南.md` |
| **架构** | 架构设计文档 | `CloudPhoneRiskKit_文档/架构设计文档.md` |
| **架构** | 威胁模型文档 | `CloudPhoneRiskKit_文档/威胁模型文档.md` |
| **协议** | C/Swift ABI 兼容性契约 | `CloudPhoneRiskKit_文档/ABI_CONTRACT.md` |
| **协议** | OpenAPI 3.0 服务端规范 | `CloudPhoneRiskKit_文档/api/openapi.yaml` |
| **协议** | Protobuf v3 消息定义 | `CloudPhoneRiskKit_文档/api/risk_service.proto` |
| **运营** | 服务等级协议 (SLA) | `CloudPhoneRiskKit_文档/SLA.md` |
| **运营** | 性能基准报告 | `CloudPhoneRiskKit_文档/PERFORMANCE_BENCHMARK.md` |
| **运营** | 开源发布与可验证性清单 | `CloudPhoneRiskKit_文档/OPEN_SOURCE_READINESS.md` |
| **运营** | 变更日志 (CHANGELOG) | `CloudPhoneRiskKit_文档/CHANGELOG.md` |
| **运营** | SDK Portal 控制台设计 | `CloudPhoneRiskKit_文档/SDK_PORTAL_SPEC.md` |

---

## 免责声明

本 SDK 仅用于合法合规的应用安全与风控场景。使用者须确保符合当地法律法规及 Apple 开发者协议。作者不对因滥用本工具造成的任何后果承担责任。SDK 的检测结果为辅助判定信号，不构成最终风控决策，建议结合服务端策略综合使用。

---

<p align="center"><sub>CloudPhoneRiskKit 7.4 · 207 Swift · 54 C · 72 Tests · 13 Pass · 80+ Detectors · 17 Docs · ABI v3</sub></p>
