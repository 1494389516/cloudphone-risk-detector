# Changelog

All notable changes to CloudPhoneRiskKit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

#### 签名域闭合 (SHA-256("") trap 修复)
- **新增 v3 签名版本**：将 `trustLevel`、`sha256(attestationAssertion)`、`sha256(reAttestationAssertion)` 纳入 HMAC 输入域。此前这三个客户端自报字段虽在 envelope 顶级字段，但**不在签名域内**，攻击者持有签名密钥时可在签名后任意篡改而 HMAC 仍然通过（SHA-256("") 类漏洞）
- 签名域 v3 = `sigVer|nonce|ts|sessionToken|reportId|keyId|fmv|akId|trustLevel|sha256(attestationAssertion)|sha256(reAttestationAssertion)|canonicalPayload`
- `withAttestation` / `withTrustLevel` / `withReAttestationAssertion` 对 v3 envelope 静默 no-op，防止签名后修改破坏 HMAC（v3 必须在 `create()` 时一次性传入所有字段）
- **OpenAPI 描述强化**：`attestationAssertion` 增加显式警告，要求服务端 MUST 调用 Apple App Attest 验证流程独立验证（仅校验 envelope HMAC 等价于零硬件信任根）；`trustLevel` 标注为客户端自报字段
- 校正 v4.6 CHANGELOG 中 "attestation 入签名域" 措辞 — 当时仅 `attestationKeyId` 入域，assertion 字节内容直到 v3 才闭合
- 新增 binding mode `self_reported_fields_bound_v3`

### Added
- XCFramework 构建文档 (`docs/XCFRAMEWORK_BUILD.md`)
- 集成指南 (`CloudPhoneRiskKit_文档/INTEGRATION_GUIDE.md`，含 CocoaPods 自建 podspec；仓库根目录不跟踪 `CloudPhoneRiskKit.podspec`)
- 多租户密钥管理 (`TenantKeyManager`)
- SLA 文档 (`docs/SLA.md`)
- 集成成本评估 (`docs/INTEGRATION_COST.md`)
- Objective-C 桥接层 (`CPRiskKitObjCBridge`)
- SDK Portal 设计规范 (`docs/SDK_PORTAL_SPEC.md`)
- `ReportEnvelope.create()` 新增 `attestationAssertion` / `reAttestationAssertion` 参数（v3 签名版本必须在创建时传入）

---

## [7.4] - 2026-04-26

### Security

#### 白盒密钥链重建（CPRISK_ARMOR_ABI_VERSION v3）
- **WB#4（Critical）**: 字符串解密生产 Bug 修复 — Swift `StringEncryptor` 与 C `cprisk_string_decrypt` 现均执行 per-string KDF `HMAC(stringKey, "cprisk.str.key.v1" || sid_le4 || nonce)`；此前 Swift 端直接使用原始 `stringKey`，导致 C 运行时解密后得到乱码
- **WB#14**: `configDigest` 双端格式锁定 — Swift/C 两侧统一采用标签+长度前缀格式 `"cprisk.whitebox.config.v2" || len64(code) || code || len64(data) || data || len64(tag) || tag || domain_ids_le32[]`；修复白盒 bundle 加载始终静默失败的问题
- **WB#5**: Path-A 计数器递增 — SHA-256 延伸块引入 4 字节 LE 计数器，消除跨 block 密钥流重用
- **P0b（WB#12）**: 消除 `s_lazy_buf[512]` BSS 明文神谕 — `cprisk_decrypt_string_lazy` 直接转发至 `cprisk_decrypt_string`，不再将明文缓存到可 dump 的全局 BSS 段

#### S-box 安全加固
- 模偏修复：Fisher-Yates 洗牌改用拒绝采样 `(0 - bound) % bound`，消除均匀性偏差
- 8-bit S-box：VM×CFF 融合路径将 4-bit S-box 升级至 8-bit，增强 Feistel-SPN 32-bit codec 扩散层强度

#### 控制流平坦化修复
- **CFF#23**: B.cond 基本块边界修复 — `bits[31:24]=0x54, bit[4]=0` ARM64 条件分支指令现被正确识别为 leader，修复重排后相对偏移量损坏问题
- **CFF#24**: PACIASP/PACIBSP 序言调整 — 检测 `0xD503233F`/`0xD503235F` 指针认证指令，向前延伸 4 字节纳入 prologue candidate
- **P1a**: Dispatcher 模板随机化 — 每个函数的 dispatcher 分支变体（TBZ/TBNZ/CBZ/CBNZ + bit/reg 组合）由 `buildSeed ^ 0xD15C_4ED1_5D15_C4ED` 派生的 per-function RNG 决定，消除 100% TBZ #0 模板化特征

#### 反调试纵深（4 项）
- **#1**: Anti-dump 探针间隔随机化 — 由固定 5s 升级为 SplitMix64 驱动的 `[2, 9]s` 均匀区间 + 0–999ms sub-second 尾部抖动，消除 5s 时序神谕
- **#2**: Mach 端口基线 8 样本校准 — 由首次观测直接锁定改为 8 样本滑动最小值 CAS 更新（`CPRISK_MACH_PORT_BASELINE_CALIB_SAMPLES = 8`），校准期内拒绝告警，防止基线投毒
- **#3**: 软件断点扫描窗口扩展 — watchdog 随机文本窗口 8→24，每窗口扫描字节数 768→1024，降低局部补丁逃逸概率
- **#4**: Watchdog 启动失败标志 — `pthread_create` 耗尽时设置 `STARTUP_LIVENESS | FUNCTION_PROLOGUE` 异常标志，确保 watchdog 线程创建失败不静默消失

#### 检测链 HMAC 证明（P2b）
- 新增 `cprisk_detection_attest.c` — per-session 检测结果 HMAC 滚动证明链，密钥由白盒 PRF Domain 5 派生；`cprisk_attest_session_begin` 生成新鲜 nonce，`cprisk_attest_record` 逐 Detector 累积链，`cprisk_attest_session_finalize` 输出 HMAC 标签
- `JailbreakEngineV2.detectV2` 完成后将 `attest_nonce`/`attest_count`/`attest_tag` 注入 method 标签，服务端可独立验证检测顺序与结论完整性
- `DetectorID: UInt8` 枚举化（0x11=antiTampering, 0x23=debugger, 0x37=frida…），消除明文字符串标识符旁路

#### 字段混淆与会话绑定（P2a）
- `PayloadFieldObfuscator` 新增 `DepthScope.all` — 支持递归嵌套字段重命名，默认 `.topLevel` 保持后向兼容
- `validate()` 冲突检测：构建时检查映射碰撞，防止隐式覆盖
- `deriveSessionMapping(baseKeys:sessionKey:version:)` — 字段名由 `HMAC<SHA256>(sessionKey, "cprisk.field.v1" || keyName)[..8].hex` 会话派生，每会话映射均不同

### Added
- `cprisk_detection_attest.c` / `cprisk_detection_attest.h`：检测链 per-session HMAC 证明模块
- `ABIConsistencyTests.swift`（5 tests）：Swift↔C 跨语言 ABI 一致性套件（域密钥、per-string KDF、configDigest、VM S-box、CFF 编码）
- `DetectionAttestTests.swift`（5 tests）：证明链序列化、会话隔离、nonce 唯一性、方法标签注入验证

### Fixed
- `StringEncryptorTests.swift`：per-string KDF roundtrip 验证对齐新格式
- `WhiteBoxProfileTests.swift`：configDigest 格式对齐新标签+长度前缀格式
- `CryptoTests.swift`：补充嵌套字段混淆 P2a 回归测试

### Changed
- `CPRISK_ARMOR_ABI_VERSION` 升级至 v3（per-string KDF domain label、Path-A counter、configDigest 格式为 breaking changes，Swift producer 与 C consumer 已锁步更新）

---

## [7.3] - 2026-03-27

### Changed
- README 移除冗长 6.x 独立章节，精简为统一版本演进表
- `CloudPhoneRiskKit_文档` 与合规/隐私声明统一对齐 7.3 版本号
- `Version.current` 与对外 SDK 版本号对齐为 7.3.0

---

## [7.2] - 2026-03

### Added
- MIE/MTE 姿态接入：Release 构建接入 `CPRISK_MTE_COMPILE_SUPPORT` 与 `ENABLE_ENHANCED_SECURITY`
- C 层 `cprisk_mte_guard`：sysctl + 本地快照 + region canary 保守感知 Memory Integrity Enforcement
- Swift 层 `MIEPostureDetector`：`none / pacOnly / miePartial / mieFull` 四级姿态评估
- 新增 `mie_posture`、`mte_unavailable_on_capable_device`、`mte_inactive_for_process`、`mte_canary_tampered` 信号

### Fixed
- `HoneypotMemoryDetector` 在 iPhoneOS 26 SDK 下 `ucontext_t` / PC 字段兼容路径修复
- C 层统一封装 `cprisk_advance_ucontext_pc(...)` 消除 arm64/arm64e SDK 接口差异
- `xcodebuild -sdk iphoneos` 恢复全绿

### Changed
- `AntiTamperingSignalProvider` 在 `miePartial / mieFull` 下对高价值信号做上下文加权

---

## [7.1] - 2026-03

### Added
- VM self-check 从硬编码符号窗口升级为 CPSV span map (`__swift5_mdvsi`) 驱动
- `cprisk-vm-self-expect` CLI 同时支持 CPSF/FNV 与 CPSH/HMAC 写入
- 22 个 `cprisk_vm_oph_*` handler 拆分到多个编译单元（跨 TU 散布）

### Changed
- Runtime 自校验对齐 producer span，优先消费 `__swift5_mdvsi` span 布局
- Dispatcher 继续去 switch 化：family 分流 + single-access handler materialization

### Security
- SDK 隐私声明与 App Store 合规文档同步升级，明确 7.1 不扩大 collected data 边界

---

## [7.0] - 2026-02

### Added
- Pass 12 `TextSegmentEncryptor`：对 `__TEXT.__text` 做页级加密，元数据写入 `__DATA.__swift5_cgenc`
- Pass 13 `VMProtector`：ARM64 → 自定义字节码 + VM 入口跳板，7 个高价值函数虚拟化
- `cprisk_vm_interpreter` 运行时 VM 解释器
- VMP section 伪装：dispatch/bytecode 写入 `__DATA.__swift5_mdvrt` / `__DATA.__swift5_mdirt`
- M2 指令扩展：MOVZ/MOVK、ADRP+ADD 融合、CSEL/CSET、CBZ/CBNZ 等
- M2 反分析：handler 变体池、多态 opcode table、VPC 仿射编码
- M3 解释器自身 CFF 接线、dead handler 注入、opaque VPC 链

### Security
- M3 self-check 门控：运行时可选自校验判定解释器完整性
- 13 Pass 壳链路全面收口

---

## [6.8] - 2026-01

### Added
- `__thread_init` 早期异常端口抢占与竞态回收
- AntiDebug plan 运行时 inline patch gate (`BRK #0xC0E0`)
- Unix syscall vs Mach 路径交叉校验
- Frida 协议指纹与可选全端口扫描
- 多频 watchdog + 互监 deadline
- 关键路径 timing canary
- Pass 10 `ImportEncryptor`、Pass 11 `HeaderEncryptor`
- CFF 新增 `splitIndirect` dispatcher 与 `affine` 编码风格
- CFF 覆盖建议器

### Security
- 白盒 PRF 增强扩散层

---

## [6.7] - 2026-01

### Added
- 源码级 CFF 基础设施：CFFStateCodec / CFFDispatcher / CFFReturnSink / CFFRuntimeSalt
- DecisionTree / RiskDetectionEngine / ChallengeSession / TrustChainManager / anti_debug_watchdog 接入编码状态机
- Pass 9 `ControlFlowOrchestrator` 策略编排 (`cff_policy.yaml`)
- 异构 dispatcher：switch / if-else / dual-rail / region

### Security
- Runtime salt 绑定、fail-closed 默认路径
- 避免 OLLVM 模板化特征

---

## [6.6] - 2025-12

### Added
- Pass 7 `AntiDebugInjector`：`__DATA,__cpr_adbg7` 编译期注入
- Pass 8 `InstructionSubstitution`：`__TEXT.__text` 1:1 等长语义等价替换
- 关键密码学路径被调试时静默毒化
- Watchdog 多维探针（SIGTRAP/csops/硬件断点/软件断点/异常分发超时/可疑线程/TTY/Developer Disk）
- `FridaModuleDetector`：image/section/字符串三路 Frida/Gum/Gadget 检测
- 新增 `software_breakpoint_detected` / `exception_delivery_timeout` 等信号

### Changed
- 反篡改检测顺序稳定随机化 (MutationStrategy.shuffleChecks)

---

## [6.5] - 2025-12

### Added
- 白盒 PRF 引擎：5 域 table-driven SPN，~160KB S-box 嵌入二进制，root key 不可逆提取
- `AppSigningIdentityDetector` 反重打包：TeamID/bundleID/entitlement 一致性 + 基线漂移检测
- 白盒 4 section 占位符：`__swift5_awbm/awbc/awbd/awbt`
- CRiskCore 白盒运行时：validate bundle → PRF evaluate → signing helper
- v2a 签名链白盒化

### Security
- Anchor/字符串/数据段/签名材料全链路白盒派生替代 legacy HMAC 路径

---

## [6.4] - 2025-11

### Changed
- SDK 由动态 framework 改为 `library.static`（消除 dyld 导出符号暴露面）
- Armor 壳对最终 app 二进制执行
- 全量 strip（STRIP_STYLE=all）清除所有本地符号
- IDA 中 SDK 函数全部显示为 `sub_XXXX`
- App bundle 不再包含 `Frameworks/` 目录

---

## [6.3] - 2025-11

### Added
- Pass 6 `SymbolStripper`：nlist 本地符号表 SDK 标记混淆
- `MetadataScrubber` 全类型混淆（移除 SDK 公开类型白名单）
- Codable 短别名 CodingKeys（80+ struct / 25+ 文件）

### Fixed
- ObjC selector 安全修复：仅混淆 SDK 方法名，系统 selector 保留

---

## [6.2] - 2025-10

### Added
- ABI v2 壳密码学重建：CLI 强制密钥注入 / HMAC-SHA256 认证标签 / 随机 nonce

### Fixed
- CRiskCore C 层 9 项边界安全加固
- 运行时反篡改 6 项纵深补强
- 配置降级 8 项封堵
- 18 项 Bug 修复

### Security
- IntegrityAnchor HMAC 绑定 rootKey
- Salt 动态派生、密码学安全 seed

---

## [6.1] - 2025-10

### Added
- Pass 1 全量敏感字符串加密 + 原位零化
- Pass 2 Metadata 抹除（Swift 类型名/反射字符串/ObjC 方法名混淆）
- Pass 3 多 Section 真实数据段加密（`__const`/`__cfstring`/`__swift5_fieldmd`）
- Pass 5 结构混淆（5-8 假 Section 注入 + 随机布局）
- 密钥安全清零 (`cprisk_secure_zero`)
- Anti-Dump 页面保护验证 (`vm_region_64`)
- 运行时完整性重校验 (`cprisk_recheck_integrity`)

### Fixed
- v2a 验签密钥派生修复
- 10 项 Bug 修复
- 385 测试全绿

---

## [6.0] - 2025-09

### Added
- `cprisk-armor` 编译后壳工具链（Pass 1 字符串加密 / Pass 3 数据段加密 / Pass 4 完整性锚点）
- CRiskCore 运行时解密消费链
- 内联 SHA-256 消除 CommonCrypto Hook 面
- 自包含 Mach-O 基址解析阻断 Clean Copy 攻击
- Section 伪装隐写
- 编译期 XOR 盐混淆
- Armor runtime material 渗透式毒化业务签名 (v2a)

### Fixed
- 9 项安全 Bug 修复

### Security
- 渗透式防护：篡改后密钥错误 → 解密失败 → 签名静默失效 → 无显式 crash

---

## [5.5] - 2025-08

### Fixed
- `RandomizedDetection` 父进程逻辑修复
- `ptrace` 错误处理修复
- `getentropy` buflen 校验

### Added
- `ExperimentConfig.random` 分桶
- `WhitelistRules` 语义化版本比较
- `PayloadFieldObfuscator` 反向映射

---

## [5.4] - 2025-07

### Changed
- RTLD_NEXT 下沉为 SVC 直调
- 时序动态比值基线
- `PhysicalSensorProbe` 预热缓存

### Added
- 服务端参考哈希
- `getpid/getppid/getuid/socket/connect` SVC 直调

---

## [5.3] - 2025-07

### Added
- SVC #0x80 直调 `ptrace(PT_DENY_ATTACH)` 绕过 Frida Hook
- CRiskCore C 模块
- 自保护 C/Swift 混合层

### Security
- 下一代 6.x 架构奠基

---

## [5.2] - 2025-06

### Added
- `DisplayMuxProvider`：录屏/推流、外接显示器检测
- `BiometricStateProvider`：生物特征未录入/不可用检测
- `AudioRouteProvider`：USB 音频、虚拟声卡检测
- `BasebandIsolationProvider`：无蜂窝、系统 App 阉割检测
- Impossible States：五信号组合强制拦截

---

## [5.1] - 2025-06

### Added
- `PhysicalSensorProbe`：CoreMotion 重力/加速度/陀螺仪/磁力计/气压计
- `EnvironmentConsistencyProvider`：热状态熵、电池状态转移、屏幕亮度熵
- `HardwareCapabilityProvider`：Haptic Engine、刷新率一致性、接近传感器
- `NetworkInterfaceProvider`：虚拟接口、MTU 异常、接口数量

---

## [5.0] - 2025-05

### Added
- `TrustChainManager` / `TrustLevel` / `KeyRotation` 端侧信任根链
- 内存语义压缩快速判决 (`CompressedVerdictRule`)
- 挑战式验证闭环
- 图风控联动：`GraphFeatureCollector` / `GraphNodeDescriptor`

---

## [4.9.2] - 2025-04

### Security
- `ConfigSignatureVerifier` 密钥 Keychain 按需加载
- `StorageIntegrityGuard`/`KeychainSalt`/`ReportEnvelope`/`ChallengeTrigger` 密钥用后清零
- `SignedRiskConclusion` 字符串插值 SecureScope
- `CPRiskKit`/`PolicyManager` 敏感状态清理
- Logger 敏感信息 DEBUG 限定

---

## [4.9] - 2025-04

### Fixed
- RTLD_NEXT fail-open 消除（安全路径失败不再回退普通 libc）
- `LibcPrologueGuard` 50% 概率 + 5s 时间衰减 + tampered 联动清缓存
- DeviceID ephemeral 标记修正
- Replay store 时间轴 systemUptime→Unix 对齐

### Security
- 完整性基线首启/升级环境检查（可疑环境拒绝建基线 + 高危信号）
- App Attest 静默降级消除（`requireAttestation` 强制模式 + attestation 一致性校验）

---

## [4.8] - 2025-03

### Fixed
- `LibcPrologueGuard` TOCTOU 消除（废弃静态缓存、30% 概率重扫）
- `ProcessInfo` 全面替换为 sysctl

### Security
- `SecureBuffer` 密钥内存安全擦除
- 越狱特征字符串全量混淆 (`ObfuscatedJailbreakStrings`)
- `DetectorRegistry` 统一 do-catch 容错 + 高危权重异常信号

---

## [4.7] - 2025-03

### Added
- `LibcPrologueGuard`：机器码入口校验（mach_vm_read_overwrite 检测 Dobby/Substrate 跳板）
- `KernelHookSideChannel`：四策略内核 Hook 检测（时序分布 / inode 一致性 / 时钟交叉 / 返回值熵）
- 金丝雀探针池 5→16 + 动态路径 3 条 + 子集 6 选
- `DualPathValidator` 三路验证（标准 / RTLD_NEXT / 入口完整性）

### Fixed
- SVC 0x80 声称为 Prologue Guard 实际机制修正

---

## [4.6] - 2025-02

### Fixed
- App Attest TOCTOU 竞态消除 + **attestationKeyId** 入签名域（注：assertion 字节内容当时仍在签名域外，参见 Unreleased v3 签名版本修复）
- CallStack RTLD_NEXT 双路 + vm_region 交叉校验
- 蜜罐三页分散 + handler/保护位自检
- 金丝雀 DualPath 双路 + 随机探针池
- ExpectedBaseline sysctl 双路版本
- payload_sha256 上下文绑定
- PAC vm_read_overwrite 安全读取

### Security
- 12 项漏洞全修复（第六轮红队审计）

---

## [4.4] - 2025-01

### Added
- Apple App Attest / Secure Enclave 硬件绑定签名
- 调用栈回溯 ROP/JOP 链检测
- Syscall Canary 探针致盲感知
- 蜜罐内存页 SIGBUS 反 Dump
- iOS 版本动态基线自适应
- gRPC 传输层升级

---

## [4.3] - 2024-12

### Fixed
- 锁屏 Keychain ACL 撕裂死锁修复
- `ConfigCache` 并发状态机锁绕过修复
- 内存 AES 密钥明文残影消除
- 时间跳跃重放绕过修复

### Added
- 线程级异常与硬件断点劫持检测
- 匿名内存隐写扫描
- ObjC Inline Hook 跳板拦截
- fsid 沙盒视图隔离探测
- 指令计数器时序侧信道双路校验
- 底层 SVC 0x80 原生系统调用接入

### Security
- 11 项极深层漏洞修复（第五轮红队审计）

---

## [4.2] - 2024-12

### Security
- 配置/策略双链 Release 禁 unverified fallback
- 安全地板扩展覆盖行为与越狱关键检测开关
- `DualPathValidator` 接入核心 Detector
- anti_tamper 结论消除分裂
- 基线首跑软信号化
- deviceID 漂移修复
- 历史时钟回拨防御
- `CPRiskStore` 暴露面收紧
- EnvelopeSignature Release 强制 v2（8 项漏洞全修复，第四轮红队审计）

---

## [4.1] - 2024-11

### Security
- 配置缓存来源验签
- HTTPS 强制
- Provider 实例锁定
- 首跑基线防投毒
- 存储加密 Fail-Closed
- `DeviceHistory` 迁移加密
- `ReportEnvelope` 元数据入签名域
- `DetectorRegistry` 封印（10 项结构性漏洞全修复，第三轮红队审计）

---

## [4.0] - 2024-10

### Fixed
- 竞态条件修复
- 时序侧信道消除
- 检测超时机制

### Security
- 存储加密
- 配置签名验证
- Provider 注册表强化
- 决策引擎加固
- 行为信号增强（22 项安全漏洞全修复，双轮红队审计）

---

## [3.7] - 2024-09

### Added
- 基线迁移 Keychain
- TLS 证书固定
- PLT 持久化
- ptrace 反调试
- DYLD Interpose 检测
- SDK 二进制校验
- 传感器回放检测
- GPU 深度探测
- isa swizzling 检测
- 消息转发检测
- Keychain ACL
- 多路径一致性
- 指纹突变检测
- 随机化检测

---

## [3.6] - 2024-08

### Added
- Frida 深度对抗（8 维全覆盖）：线程枚举异常、异常端口劫持、V8 堆特征、Stalker JIT 检测、ObjC Swizzle、Dispatch Queue 扫描、Unix Socket、时序侧信道

---

## [3.5.1] - 2024-08

### Added
- 账号/会话绑定
- 行为向量导出
- 图特征反哺

### Security
- `__TEXT` 段哈希校验

---

## [3.5] - 2024-07

### Added
- DRM 等级检测
- 电池物理熵
- RWX 内存扫描
- PLT 完整性校验
- HMAC 签名

### Security
- 字符串混淆
- SVC 直调

---

## [3.1] - 2024-07

### Added
- 关键符号扩展
- Trampoline 识别
- 路径判定强化

---

## [3.0] - 2024-06

### Added
- 四层检测体系：硬件指纹 / 一致性 / 行为熵 / 服务端聚合
- 场景化决策树
- 信号状态模型（硬信号 / 软信号 / 服务端信号）
- 架构从零重建
