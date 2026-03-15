<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-6.2.0-FF3B30?style=for-the-badge" alt="SDK">
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
| **5.3** | **自保护架构升级 + 内核直调** | SVC #0x80 直调 ptrace(PT_DENY_ATTACH) 绕过 Frida Hook、CRiskCore C 模块、自保护 C/Swift 混合层、下一代 6.x 架构奠基 |
| **5.4** | **四盲区修复 + 直调扩展** | RTLD_NEXT 下沉为 SVC 直调、时序动态比值基线、PhysicalSensorProbe 预热缓存、服务端参考哈希、getpid/getppid/getuid/socket/connect 直调 |
| **5.5** | **Bug 修复 + 实验分桶** | RandomizedDetection 父进程逻辑、ptrace 错误处理、ExperimentConfig.random 分桶、WhitelistRules 语义化版本比较、PayloadFieldObfuscator 反向映射、getentropy buflen 校验 |
| **6.0** | **自研壳保护 + 端云签名绑定** | cprisk-armor 编译后壳工具链（Pass 1 字符串加密 / Pass 3 数据段加密 / Pass 4 完整性锚点）、CRiskCore 运行时解密消费链、内联 SHA-256 消除 CommonCrypto Hook 面、自包含 Mach-O 基址解析阻断 Clean Copy 攻击、Section 伪装隐写、编译期 XOR 盐混淆、armor runtime material 渗透式毒化业务签名（v2a）、9 项安全 Bug 修复 |
| **6.1** | **壳工业化 + 运行时加固 + 全量回归** | Pass 1 全量敏感字符串加密 + 原位零化、Pass 2 Metadata 抹除（Swift 类型名/反射字符串/ObjC 方法名混淆）、Pass 3 多 Section 真实数据段加密（`__const`/`__cfstring`/`__swift5_fieldmd`）、Pass 5 结构混淆（5-8 假 Section 注入 + 随机布局）、密钥安全清零（`cprisk_secure_zero`）、Anti-Dump 页面保护验证（`vm_region_64`）、运行时完整性重校验（`cprisk_recheck_integrity`）、v2a 验签密钥派生修复、KDF 全链路测试（14 节点）、E2E 集成测试（6 场景）、10 项 Bug 修复、385 测试全绿 |
| **6.2** | **壳密码学重建 + 全栈安全加固 + 46 项漏洞修复** | ABI v2 壳密码学重建（CLI 强制密钥注入 / HMAC-SHA256 认证标签 / 随机 nonce / IntegrityAnchor HMAC 绑定 rootKey / salt 动态派生 / 密码学安全 seed）、CRiskCore C 层 9 项边界安全加固、运行时反篡改 6 项纵深补强、配置降级 8 项封堵、18 项 Bug 修复 |

## 架构概览

```
┌────────────────────────────────────────────────────────┐
│          Layer 0: 自研壳 (cprisk-armor) ABI v2           │
│   全量字符串加密+HMAC / 多 Section 数据段加密+HMAC       │
│   完整性锚点 HMAC / Metadata 抹除 / 结构混淆 / Anti-Dump │
│   强制密钥注入 / salt 动态派生 / armor material→毒化(v2a)│
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
源码 → swift build → SDK.framework (原始 Mach-O)
                          ↓
                    cprisk-armor CLI (5 Pass, ABI v2)
                    --key <hex> / --key-file / CPRISK_ARMOR_KEY
                    ┌─ Pass 4: IntegrityAnchor    (HMAC 完整性锚点)
                    ├─ Pass 1: StringEncryptor     (加密 + HMAC + nonce)
                    ├─ Pass 3: DataSegmentEncryptor(加密 + HMAC + nonce)
                    ├─ Pass 2: MetadataScrubber    (元数据抹除)
                    └─ Pass 5: StructureObfuscator (结构混淆, 安全随机)
                          ↓
                    SDK.framework (加固后 Mach-O)
                          ↓
                    运行时 CRiskCore
                    HMAC 验证 → 解密 + 完整性校验 + Anti-Dump
                    armor material → ReportEnvelope v2a
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
│   │   ├── ArmorCLI/                     # CLI 入口 (5 Pass 编排)
│   │   ├── MachOKit/                     # Mach-O 读写库
│   │   ├── StringEncryptor/              # Pass 1: 全量字符串加密
│   │   ├── MetadataScrubber/             # Pass 2: Metadata 抹除
│   │   ├── DataSegmentEncryptor/         # Pass 3: 多 Section 数据段加密
│   │   ├── IntegrityAnchor/              # Pass 4: 完整性锚点
│   │   └── StructureObfuscator/          # Pass 5: 结构混淆
│   └── Tests/                            # 85 项单元 + E2E + KDF 链测试
│
├── RiskDetectorApp/
│   ├── App/                              # SwiftUI 示例应用
│   ├── Sources/
│   │   ├── CRiskCore/                    # C 自保护核心
│   │   │   ├── cprisk_string_decrypt.c   # 运行时字符串解密
│   │   │   ├── cprisk_data_loader.c      # 运行时数据段加载/解密
│   │   │   ├── cprisk_integrity.c        # 完整性校验 + 主初始化
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

SDK 采用纵深防御架构：**cprisk-armor 自研壳（5 Pass / ABI v2）** 在编译后对二进制执行全量字符串加密（HMAC 认证 + 随机 nonce）、Metadata 抹除、多 Section 数据段加密（HMAC 认证）、完整性锚点（HMAC 绑定 rootKey）与结构混淆，强制密钥注入消除零密钥降级，消除静态分析与逆向还原特征；**Anti-Dump 页面保护**（`vm_region_64`）检测攻击者重映射，**密钥安全清零**覆盖全部中间态敏感材料；**内联 SHA-256 + 自包含 Mach-O 解析**消除 CommonCrypto 与 dyld API 的 Hook 攻击面，阻断 Clean Copy 攻击；**渗透式毒化**将壳完整性 material 绑定到 ReportEnvelope 签名派生链（v2a），篡改即签名失效而非 crash，攻击者无法定位防护点；**字符串全量混淆**（`ObfuscatedJailbreakStrings`）防止静态特征提取；**DualPathValidator 双路/三路验证**确保检测结果不被单点绕过；**HMAC-SHA256 签名**覆盖报告全字段防篡改，**SignedRiskConclusion v2** 将 signals 摘要纳入签名域；**Keychain + AES-GCM 加密存储**保护本地数据与历史记录，**Keychain 策略统一** `AfterFirstUnlockThisDeviceOnly`；**配置签名信任链**（远端 → 缓存 → 运行时）杜绝配置注入，**DEBUG/Release 行为对齐**消除调试放行路径；**__TEXT 段哈希 + SDK 二进制完整性校验 + 基线交叉验证**检测代码篡改与基线投毒；**Provider 注册表封印 + ConditionExpression 封印 + 实例锁定**防止运行时替换；**ServerSignals HMAC 来源校验 + Challenge HMAC 校验**防止注入伪造信号与中间人篡改挑战结果；**动态可疑特征列表**支持服务端热更新检测规则；**Frida 五维对抗**（线程 / 端口 / V8 堆 / Socket / 时序）全覆盖；**LibcPrologueGuard + KernelHookSideChannel** 实现 Inline Hook 穿透与内核级 Hook 侧信道检测；**IntegrityBaselineEnvCheck** 首启环境把关防止基线投毒；**App Attest 强制模式** 消除所有静默降级路径；**行为数据用后清零**防止内存 Dump 提取。

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
| 绕过全部 8 维 Frida 对抗 | 极高 | Frida 重编译、多维度绕过、时序侧信道消除 | 数周 |
| 物理层/传感器检测 | 架构级成本 | 需改造硬件或高保真 MEMS 仿真 | 无法绕过 |

**纵深防御的经济学意义**：攻击者若仅绕过单点（如 DYLD），仍会触发其他维度；若要全面绕过，需投入与维护成本呈指数级增长，使批量攻击在经济上不可行。

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

<p align="center"><sub>CloudPhoneRiskKit 6.2.0 — 壳密码学重建 (ABI v2) + 全栈安全加固 + 46 项漏洞修复</sub></p>
