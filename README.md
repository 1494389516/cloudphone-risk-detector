<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-4.2-FF3B30?style=for-the-badge" alt="SDK">
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
| 3.7 | **SDK 自保护加固 + 全面纵深** | 基线迁移 Keychain、TLS 证书固定、PLT 持久化、ptrace 反调试、DYLD Interpose、SDK 二进制校验、传感器回放检测、GPU 深度探测、isa swizzling、消息转发检测、Keychain ACL、多路径一致性、指纹突变、随机化检测 |
| **4.0** | **双轮红队审计 + 全栈安全加固** | 竞态条件修复、时序侧信道消除、存储加密、配置签名验证、Provider 注册表强化、决策引擎加固、行为信号增强、检测超时机制（22 项安全漏洞全修复） |
|| **4.1** | **第三轮红队审计 + 攻击链纵深封堵** | 配置缓存来源验签、HTTPS 强制、Provider 实例锁定、首跑基线防投毒、存储加密 Fail-Closed、DeviceHistory 迁移加密、ReportEnvelope 元数据入签名域、DetectorRegistry 封印（10 项结构性漏洞全修复） |
|| **4.2** | **第四轮红队审计 + 信任根全面收紧** | 配置/策略双链 Release 禁 unverified fallback、安全地板扩展覆盖行为与越狱关键检测开关、DualPathValidator 接入核心 Detector、anti_tamper 结论消除分裂、基线首跑软信号化、deviceID 漂移修复、历史时钟回拨防御、CPRiskStore 暴露面收紧、EnvelopeSignature Release 强制 v2（8 项漏洞全修复） |

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

## 4.2 新增能力 — 第四轮红队审计信任根全面收紧

4.2 版本基于第四轮红队审计，聚焦于 4.1 修复后仍存在的**信任根薄弱点与检测结论分裂**问题，共修复 **8 个漏洞**（2 个 P0-Critical、2 个 P1-High×2、3 个 P1-High、1 个 P2-Medium），覆盖配置信任链、运行时检测统一性、存储健壮性、上报边界四个维度。

### 4.2 安全加固全景

```
┌─────────────────────────────────────────────────────────────────┐
│                  4.2 信任根收紧矩阵                               │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│  配置信任链   │  运行时统一性  │   存储健壮性   │    上报边界         │
├──────────────┼──────────────┼──────────────┼────────────────────┤
│ Release禁止  │ DualPath接入  │ deviceID漂移  │ encryptionEnabled  │
│ unverified   │ FileDetector  │ Keychain重试  │ Release强制true    │
│ fallback     │ SysctlDetect  │ ephemeral前缀  │ 明文报告访问禁止   │
│ Policy同步   │ anti_tamper   │ 历史时钟回拨   │ (Release 403)      │
│ verified标志  │ 结论补强      │ 检测清除保护   │                   │
│ EnvelopeSig  │ 基线首跑      │ 未来时间戳检测  │                   │
│ Release强制v2 │ 软信号化      │               │                   │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

### 配置与策略信任链（P0-1 / P0-2）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **ConfigCache Release 禁 unverified fallback** | `loadLatestFromDisk()` 无验签条目时静默 fallback 未验签缓存，攻击者可注入旧配置 | Release 下无 verified 条目时返回 `nil`，不 fallback；DEBUG 保留 fallback 并打印日志 |
| **PolicyManager verified 标志** | `PolicyManager` 缓存无 verified/freshness 元数据，恢复时不区分来源 | 新增 `verifiedKey`；fetch 成功后写入 `isVerifiedByServer` 标志；Release 下 `loadFromCache()` 检查标志，未验签时返回 `nil` |
| **enforceSecurityFloor 扩展** | `enforceSecurityFloor()` 未覆盖 `enableBehaviorDetect`、`enableNetworkSignals` 及越狱关键开关，远程配置可将其关闭 | Release 下强制 `enableBehaviorDetect = true`、`enableNetworkSignals = true`、`enableFileDetect/DyldDetect/SysctlDetect/HookDetect = true` |
| **EnvelopeSignature Release 强制 v2** | 远程 `enableEnvelopeSignatureV2=false` 可将签名降级为 v1 | Release 下忽略远程配置，硬编码 `signatureVersion = "v2"`；DEBUG 保留可降级能力 |

### 运行时检测统一性（P0-3 / P1-4 / P1-5）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **FileDetector 接入 DualPathValidator** | 越狱文件检测依赖 `stat/access`，易被 Hook 统一致盲 | 对 5 个高价值越狱路径额外做 `stat/lstat/access` 三路比对；不一致记录 `dual_path_mismatch:<name>` + 每条 +20 分 |
| **SysctlDetector 接入 DualPathValidator** | `sysctlbyname` 可被 Hook 替换返回值，单路检测结果不可信 | 对 `hw.machine`、`hw.model`、`kern.osversion` 做双路（标准调用 vs RTLD_NEXT 下一跳）比对；不一致记录 `sysctl_dual_path_mismatch:<key>` + 每条 +25 分 |
| **anti_tamper 结论分裂修复** | `AntiTamperingSignalProvider` 结果仅作为 extraSignal，不反映到 `CPRiskReport.jailbreakIsJailbroken` / `jailbreakConfidence` / `detectedMethods` | `evaluate()` 末尾：过滤出 `category == "anti_tamper"/"integrity"` 的 `.tampered` 信号；若 `jailbreak.isJailbroken == false` 则加权补强 confidence 并追加 `anti_tamper:<id>` 到 `detectedMethods` |
| **基线首跑软信号化** | `SDKBinaryIntegrityChecker` 首次运行无 Keychain 记录时静默返回 `isIntact: true`，基线投毒窗口零感知 | 首次建基线时 `detail = "baseline_established"`；`asSignals()` 产出 `sdk_integrity_first_run` 软信号（score:0, confidence:0.3），服务端可感知安装/重装事件 |

### 存储健壮性（P1-6）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **KeychainDeviceID 漂移修复** | Keychain 保存失败时静默返回新 UUID，deviceID 在每次安装/重装时漂移 | 保存失败后先重试 `read()`（处理并发竞争）；仍失败则返回 `"ephemeral:<uuid>"` 前缀 ID，服务端可识别并限制高信任请求 |
| **RiskHistoryStore 时钟回拨防御** | 历史记录无新鲜度约束，可被整体回放；时钟回拨攻击可注入未来时间戳 | `loadStateLocked()` decode 后检测最新事件时间戳是否超出当前时钟 60s，超出则清除缓存并返回空，防时钟回拨 + 旧快照回放 |

### 上报边界（P2-8）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **CPRiskStore 暴露面收紧** | `encryptionEnabled` 公开可切换；`decryptReport(atPath:)` 允许直接读取明文 `.json` 报告 | `encryptionEnabled` 增加 `didSet`，Release 下强制回退 `true`；`decryptReport(atPath:)` 在 Release 下拒绝明文 `.json` 访问，返回 403 error |

### 4.2 新增信号 ID

| 信号 ID | 权重提示 | 触发条件 |
|---------|----------|----------|
| `dual_path_mismatch:<name>` | 80 | 越狱关键路径 stat/lstat/access 三路比对不一致（每条 +20 分） |
| `sysctl_dual_path_mismatch:<key>` | 85 | sysctl 双路结果不一致（每条 +25 分） |
| `anti_tamper:<signal_id>` | 85 | anti_tamper/integrity 信号触发，补强到 jailbreak 结论字段 |
| `sdk_integrity_first_run` | 30 | SDK 首次运行建立基线（软信号，score:0，服务端感知安装事件） |

> **接入注意**：4.2 `evaluate()` 在 anti_tamper 命中时会自动更新 `CPRiskReport.jailbreakIsJailbroken` 字段，请确保业务层判断逻辑已覆盖此字段。

---

## 4.1 新增能力 — 第三轮红队审计攻击链封堵

4.1 版本基于第三轮红队审计，聚焦于 4.0 修复后仍存在的**结构性攻击链**，共修复 **10 个漏洞**（4 个 Critical、4 个 High、2 个 Medium），从配置来源验证、运行时实例防护、存储加密健壮性、上报签名完备性四个维度全面加固。

### 4.1 安全加固全景

```
┌─────────────────────────────────────────────────────────────────┐
│                  4.1 攻击链纵深封堵矩阵                           │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│  配置信任链   │   运行时防护  │   存储安全    │    签名完备性        │
├──────────────┼──────────────┼──────────────┼────────────────────┤
│ 缓存来源验签  │ Provider实例  │ 加密Fail-Close│ Envelope元数据签名  │
│ HTTPS强制    │ 指针锁定      │ Magic Header  │ reportId/keyId覆盖  │
│ 签名Fail-Close│ 首跑基线防毒  │ DeviceHistory │ DetectorRegistry   │
│ 导入/回滚禁用 │ 异常→软信号   │ 加密+文件保护  │ 封印加锁            │
│ JSON注入禁用  │ 实例替换告警  │ App Support迁移│ enabledTypes生效   │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

### 配置信任链（P0-1 / P0-2）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **缓存来源真实性** | 本地恢复只验 HMAC，不验服务端签名来源；一次恶意写入可跨重启持久生效 | `CacheEntry` 新增 `isVerifiedByServer` 标志；`loadLatestFromDisk()` 优先已验签条目 |
| **危险写入路径禁用** | `rollback()` / `importCache()` / `update(fromJSON:)` 可注入旧配置 | Release 下完全禁用这三个路径，只在 DEBUG 保留 |
| **HTTPS 强制** | `configureRemoteConfigProvider()` 允许 HTTP，集成方漏配即退化为明文信任 | Release 下拒绝 `http://` 开头 URL，只允许 `https://` |
| **签名未配置警告** | 未配置 signing key 时无任何警告，配置面等同无验证 | 未配置时缓存条目标记 `isVerifiedByServer: false` 并打印明确告警日志 |

### 运行时防护（P0-3 / P0-4）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **Provider 实例指针锁定** | `seal()` 只锁类型，攻击者可注册同类型但配置更弱的实例替换真实 Provider | `seal()` 额外快照内部 Provider 实例指针（`ObjectIdentifier`）；后续 `register()` 同时校验类型 + 实例指针，替换时注入 `provider_instance_replaced` 信号（weightHint: 85） |
| **PLT 首跑基线防投毒** | `captureBaseline()` + `verify(baseline:)` 在同次运行内建基线，Hook 注入的脏状态会被写成可信基线 | 改为 `PLTIntegrityGuard.verifyWithPersistedBaseline()`，基线持久化到 Keychain，消除自基线化漏洞 |
| **完整性检测 Fail-Open** | `sdk_image_not_found` / `hash_failed` 静默返回空，攻击者可故意触发绕过完整性检测 | 两种异常路径均注入软信号，参与引擎加权评分 |

### 存储安全（P1-6 / P1-7）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **加密 Fail-Closed** | `(try? encrypt()) ?? plaintext` 加密失败回退明文；解密失败继续明文解析 | 引入 `0xAE` magic header 区分密文与明文；Release 下加密失败不写入、解密失败清除缓存 |
| **DeviceHistory 加密迁移** | 历史文件存于 `Documents`（可被外部访问），只有 HMAC 无加密 | 迁移到 `Application Support`；`NSFileProtectionComplete` 文件保护；`PayloadCrypto` 加密写入；自动清理旧 Documents 文件 |

### 签名完备性（P1-8 / P2-10）

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **ReportEnvelope 元数据入签名域** | `reportId` / `keyId` / `fieldMappingVersion` 不参与签名，可被篡改而签名不失效 | 签名格式扩展为 `sigVer｜nonce｜ts｜sessionToken｜reportId｜keyId｜fieldMappingVersion｜canonicalPayload` |
| **DetectorRegistry 封印** | 无锁、无 seal；`enabledTypes` 形参存在但实际未生效 | 新增 `NSLock` + `isSealed`；`register` / `unregister` 加锁加封印保护；`detectAll(enabledTypes:)` 真正按传入集合过滤 |

### 4.1 新增信号 ID

| 信号 ID | 权重提示 | 触发条件 |
|---------|----------|----------|
| `provider_instance_replaced` | 85 | sealed 后检测到内部 Provider 被同类型弱实例替换 |
| `sdk_image_missing` | 70 | SDK 动态库镜像在运行时消失（score=15, confidence=0.6） |
| `text_segment_hash_failed` | 60 | 代码段哈希计算失败（score=10, confidence=0.5） |

> **服务端注意**：4.1 `ReportEnvelope` 签名格式为 Breaking Change，服务端验签需同步更新，新增 `reportId｜keyId｜fieldMappingVersion` 三段，`fieldMappingVersion` 为空时填 `""`。

---

## 4.0 新增能力 — 双轮红队审计全栈安全加固

4.0 版本基于两轮系统性红队攻击审计，共修复 **22 个安全漏洞**（9 个 Critical、10 个 High、3 个 Medium），从密码学实现、存储安全、运行时防护、配置信任链四个维度全面加固。

### 4.0 安全加固全景

```
┌─────────────────────────────────────────────────────────────────┐
│                  4.0 全栈安全加固矩阵                            │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│   密码学层    │   存储层      │   运行时层    │    配置信任链        │
├──────────────┼──────────────┼──────────────┼────────────────────┤
│ 常量时间比较  │ 存储全加密    │ Provider 类型 │ 签名验证 Fail-Close │
│ 重放保护窗口  │ HMAC 域分离   │ 注册表强密封  │ 版本内容 Hash 对比  │
│ HKDF 参数修正 │ 竞态条件修复  │ 异常容错链    │ 安全地板强制执行    │
│ 随机盐值校验  │ DeviceHistory │ 检测超时机制  │ 关键权重下限保护    │
│ 信封降级防护  │ 完整性保护   │ 行为充足性    │ Config Fail-Close   │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

### 密码学层加固

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **常量时间签名验证** | `SignedRiskConclusion.verify()` 使用 `==` 短路比较，存在时序侧信道 | 改用 `HMAC<SHA256>.isValidAuthenticationCode`，CryptoKit 内部常量时间 |
| **Challenge 常量时间** | `ChallengeTrigger.verifyChallengePayloadSignature` 同样短路比较 | 新增 `timingSafeCompare`，XOR 累积全字节差异后判断 |
| **重放保护** | `SignedRiskConclusion` 无时间窗口校验，可无限重放旧签名 | 新增 `maxAgeSeconds`（默认 300s）timestamp 窗口校验 |
| **HKDF 参数修正** | KeychainSalt 混入 IKM 而非 HKDF salt 参数，违反设计意图 | 修正 salt 参数传递，info 字段版本化 |
| **随机盐值生成校验** | `SecRandomCopyBytes` 返回值被 `_ =` 忽略，失败时盐值全零 | 检查返回值，失败重试，仍失败则 UUID+uptime 组合 fallback |
| **RemoteConfig 版本回滚** | 同版本号不同内容可绕过回滚检查 | 增加 SHA-256 内容 hash 比对，同版本不同内容直接拒绝 |
| **信封签名降级** | `sigVer` 缺失时默认 v1，可被强制降级 | 服务端同时维护 v1/v2 校验链，移除客户端自动降级 |

### 存储层加固

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **UserDefaults 全面加密** | ConfigCache / PolicyManager / RiskHistoryStore 明文存储，越狱设备可读取所有阈值和规则 | 写入时先 `PayloadCrypto.encrypt()`，读取时先验 HMAC 再解密 |
| **HMAC 域分离** | `StorageIntegrityGuard.sign()` 拼接 `purpose\|data` 无分隔符，存在跨域伪造风险 | 添加 4 字节大端序长度前缀，彻底隔离不同 purpose 的签名空间 |
| **DeviceHistory 完整性** | `Analysis/DeviceHistory.swift` 明文 JSON 存储在 Documents 目录，无校验 | 接入 `StorageIntegrityGuard`，读时验签，篡改即清除 |
| **Keychain 竞态修复 — StorageIntegrityGuard** | `getOrCreateKey()` TOCTOU 竞态，并发调用产生多密钥 | 添加 `NSLock`，`errSecDuplicateItem` 时重新读取已有密钥 |
| **Keychain 竞态修复 — PayloadCrypto** | `symmetricKey()` 竞态，后写线程的 `SecItemUpdate` 覆盖先写线程密钥 | 添加 `NSLock`，`saveKey` 改为 add-only，duplicate 时读取已有 |
| **Keychain 竞态修复 — KeychainSalt** | `getOrCreate()` TOCTOU，同时两线程产生不同盐值 | 添加 `NSLock` + 重试读取逻辑 |
| **历史记录后门移除** | `RiskHistoryStore.append()` 中 `score==0 && summary=="clear"` 可清空所有历史 | 移除该隐藏路径，`append()` 只做追加 |

### 运行时层加固

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **Provider 类型锁定** | `seal()` 后攻击者可用内部 ID（如 `"anti_tampering"`）注册恶意 Provider 替换真实检测 | seal 时捕获 `ObjectIdentifier(type(of:))`，后续注册验证类型一致性 |
| **unregister 强化** | `unregister(id:)` sealed 后仍可移除内部 Provider，攻击者可剥除核心检测能力 | sealed 后拒绝移除 `internalProviderIDs`；尝试反注册时计数并注入 `provider_tamper_attempt` tampered 信号 |
| **Provider 异常容错** | 任意 Provider 的 `signals()` 崩溃中断整条链，后续所有 Provider 信号全部丢失 | `autoreleasepool` 隔离 + 历史活跃 Provider 突然返回空时注入 `signalCollectionFailed` 信号（score=80） |
| **检测器异常容错** | `JailbreakEngine` / `AntiTamperingSignalProvider` 中检测器崩溃导致后续全部跳过 | 每个检测器独立 do-catch 包裹，异常时记录方法名并累加可疑分数 |
| **检测超时机制** | `V2Config.detectionTimeout` 字段存在但从未使用，单个检测器死循环可阻塞整个引擎 | `DispatchSemaphore` 实现可配置超时（默认 5s），超时返回 empty 结果并记录日志 |
| **行为信号充足性** | 无用户交互时 `evaluate()` 返回零行为风险，攻击者可在无操作状态下快速触发评估 | 触摸/滑动总数 < 3 且采样 < 5 时注入 `insufficient_behavior_data` 软信号 |

### 配置信任链加固

| 修复项 | 漏洞 | 修复方式 |
|--------|------|----------|
| **ConfigSignatureVerifier Fail-Close** | 签名密钥未配置时 `verify()` 返回 `isValid: true`，等同于无验证 | Release 模式改为 `isValid: false`；DEBUG 保持放行便于开发者测试 |
| **评估安全地板** | `CPRiskConfig` 全部 `public var`，攻击者可 hook 禁用所有检测，阈值拉到 9999 | `evaluate()` 入口强制 `enforceSecurityFloor()`，关键检测不可禁用，threshold 不超过 100 |
| **关键信号权重下限** | `signalWeightOverrides` 可设为 `0.001` 实质清零关键信号 | 11 个关键信号 ID 设置最低权重（30-50），override 值用 `max(override, minWeight)` 钳位 |
| **决策树 fallthrough 修复** | `.next` / `.branch` 结果落入 `.allow`，攻击者让所有条件为 false 即可 allow | 改为按 score 与三级阈值梯度判定，消除默认 allow 路径 |
| **服务端配置签名验证** | RemoteConfig / ServerPolicy 通过网络下发，无内容签名，MITM 可注入任意配置 | 新增 `ConfigSignatureVerifier`，基于 `X-Config-Signature` Header 的 HMAC-SHA256 验证；新增 `CPRiskKit.configureServerSigningKey()` 公开配置入口 |

### 4.0 新增信号 ID

| 信号 ID | 权重 | 触发条件 |
|---------|------|----------|
| `insufficient_behavior_data` | 15 | 触摸/滑动数据不足，无法有效行为分析 |
| `provider_tamper_attempt` | 85 | sealed 后检测到恶意反注册内部 Provider |
| `signalCollectionFailed` | 80 | 历史活跃 Provider 突然返回空信号（疑似被 hook） |
| `detector_anomaly_*` | 5 | 检测器运行时异常（崩溃或返回无效值） |

---

## 3.5-3.7 能力回顾

### 3.5 新增能力

| 能力 | 优先级 | 层级 | 原理 |
|------|--------|------|------|
| **DRM 等级检测** | P0 | Layer 1 | FairPlay/AVContentKeySession 探测硬件安全解码能力，L3 或失败即高风险 |
| **电池 ChargeCounter** | P0 | Layer 1 | 硬件寄存器值 -1 或 0 = 未实现 = 云机特征，误杀率极低 |
| **电压时序方差** | P0 | Layer 3 | 100ms 间隔 5 次采样，方差接近 0 = 返回固定模拟值 |
| **匿名 RWX 内存扫描** | P0 | Layer 2 | `vm_region_64` 检测 Frida trampoline 页（匿名 + rwx） |
| **挂载点异常检测** | P1 | Layer 2 | `getmntinfo()` 双向校验：虚拟化 FS 黑名单 + 必需挂载白名单 |
| **字符串多段混淆** | P0 | — | 每个敏感字符串独立混淆（XOR / ROT13 / Caesar / Base64 / 逆序），不存在统一解密入口 |
| **SVC 直调加固** | P0 | — | `sysctlbyname` / `stat` 通过 RTLD_NEXT 绕过 PLT hook，双路验证检测篡改 |
| **PLT/GOT 完整性** | P0 | — | 10 个关键函数的地址基线校验，`dladdr` + Mach-O `.text` 段范围验证 |
| **HMAC 结论签名** | P1 | — | HKDF-SHA256 派生设备密钥 + HMAC-SHA256 签名，服务端验签防篡改 |

### 3.6 Frida 深度对抗（8 维全覆盖）

| 检测器 | 检测维度 | 绕过难度 | 原理 |
|--------|----------|----------|------|
| `FridaThreadDetector` | 线程枚举异常 | 高 | `task_threads()` + `pthread_getname_np()` 检测 Frida 特征线程；线程数 > 25 辅助判定 |
| `FridaThreadDetector` | 异常端口劫持 | 极高 | `task_get_exception_ports()` 检测非空异常处理端口 |
| `FridaHeapDetector` | V8/QuickJS 堆特征 | 高 | `vm_region_64` 扫描匿名 rw- 大内存段（> 15MB） |
| `FridaHeapDetector` | Stalker JIT 代码页 | 极高 | 检测匿名 r-x 页（不属于任何 dylib） |
| `ObjCSwizzleDetector` | ObjC 方法劫持 | 高 | `method_getImplementation()` + `dladdr()` 验证 IMP 归属 |
| `ObjCSwizzleDetector` | Dispatch Queue 扫描 | 中 | 线程队列标签匹配 Frida 特征 |
| `FridaSocketDetector` | Unix 域套接字 | 中 | `/tmp/frida-*` 路径探测 + `getsockname()` FD 扫描 |
| `FridaSocketDetector` | 时序侧信道 | 极高 | `mach_absolute_time()` 纳秒级计时，p95 > 3μs 即可判定 |

### 3.7 SDK 自保护加固

| 检测器 | 检测维度 | 权重 | 原理 |
|--------|----------|------|------|
| `DyldInterposeDetector` | DYLD_INTERPOSE section | 88 | 扫描已加载镜像的 `__DATA.__interpose` section |
| `DyldInterposeDetector` | DYLD 环境变量滥用 | 78 | 检测 `DYLD_FORCE_FLAT_NAMESPACE` 等危险环境变量 |
| `SDKBinaryIntegrityChecker` | SDK 二进制替换 | 95 | LC_UUID 与 Keychain 存储基线对比 |
| `SDKBinaryIntegrityChecker` | Segment 权限异常 | 85 | `__TEXT` 不可写、`__DATA` 不可执行 |
| `SensorReplayDetector` | 传感器噪声熵 | 72 | `mach_absolute_time` LSB 熵 < 2 bits = 虚拟/回放环境 |
| `GPURenderProbe` | GPU 计算延迟 | 75 | buffer 分配 > 10ms / 空 command buffer > 5ms = 软件渲染 |
| `IsaSwizzleDetector` | isa swizzling + 消息转发 | 82-85 | `object_getClass()` 一致性 + IMP 与 `_objc_msgForward` 比对 |

---

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

### 4.0 新增：服务端配置签名（推荐）

```swift
// 在 start() 之前配置服务端签名密钥
// 密钥由业务方服务端持有，客户端用于验证下发配置的合法性
CPRiskKit.configureServerSigningKey("your-server-hmac-key")

CPRiskKit.shared.start()

// 此后 RemoteConfig / ServerPolicy 下发时，
// SDK 校验 X-Config-Signature / X-Policy-Signature 响应头
// 验证失败的配置将被拒绝，防止 MITM 注入恶意配置
```

服务端在响应 RemoteConfig / Policy 请求时，在响应头中附加签名：

```
X-Config-Signature: <HMAC-SHA256-hex(responseBody, signingKey)>
X-Policy-Signature: <HMAC-SHA256-hex(responseBody, signingKey)>
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

### 账号绑定与图算法对接

```swift
// 用户登录后绑定账号
CPRiskKit.shared.bindAccount("user_12345", scene: "login")

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

### HMAC 签名验证

```swift
let report = CPRiskKit.shared.evaluate()

let deviceKey = DeviceKeyDeriver.deriveKey(
    deviceID: report.deviceID,
    hardwareMachine: "iPhone15,3",
    kernelVersion: "Darwin 23.0.0"
)

// 签名结论（含 timestamp + nonce，4.0 起支持重放校验）
let signed = SignedRiskConclusion.sign(report: report, deviceKey: deviceKey)

// 验签（maxAgeSeconds 默认 300 秒，超时自动拒绝）
let valid = signed.verify(deviceKey: deviceKey)
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

---

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
    │   │   └── Adapter/                    # 信号适配器（含异常容错链）
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
    │   │   ├── RiskConclusionSigner        # HMAC 签名 + 重放保护 (4.0)
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
    │   ├── Network/                        # VPN / 代理 / 证书固定
    │   ├── Device/                         # 设备指纹 / Keychain ID
    │   ├── Config/                         # 远程配置 + 签名验证 (4.0)
    │   └── Storage/                        # AES-GCM 加密存储 + 完整性保护 (4.0)
    └── CloudPhoneRiskAppCore/              # App 封装层
```

---

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

| 检测器 | 检测维度 | 版本 |
|--------|----------|------|
| `AntiTamperingDetector` | P_TRACED / 可疑父进程 / 调试环境变量 / 时序异常 | 3.x |
| `DebuggerDetector` | 调试器附加检测 | 3.x |
| `FridaDetector` | dylib 镜像 / 环境变量 / 端口 / 文件 | 3.x |
| `RWXMemoryScanner` | 匿名 RWX 内存段（Frida trampoline） | 3.5 |
| `CodeSignatureValidator` | LC_CODE_SIGNATURE 验证 | 3.x |
| `MemoryIntegrityChecker` | 内存完整性校验 | 3.x |
| `SDKIntegrityChecker` | DYLD 注入 / 可疑镜像 / Bundle 路径 / 代码签名 | 3.x |
| `PLTIntegrityGuard` | 10 个关键函数的 PLT 地址基线校验 | 3.5 |
| `TextSegmentIntegrityChecker` | `__TEXT.__text` SHA-256 代码段哈希基线校验 | 3.5.1 |
| `FridaThreadDetector` | 线程枚举异常 + Mach 异常端口劫持检测 | 3.6 |
| `FridaHeapDetector` | V8/QuickJS 堆特征 + Stalker JIT 代码页检测 | 3.6 |
| `ObjCSwizzleDetector` | ObjC 方法 IMP 劫持 + Dispatch Queue 名称扫描 | 3.6 |
| `FridaSocketDetector` | Unix 域套接字检测 + 时序侧信道分析 | 3.6 |
| `DyldInterposeDetector` | DYLD_INTERPOSE section + 环境变量滥用 + 镜像数量异常 | 3.7 |
| `SDKBinaryIntegrityChecker` | SDK 代码签名 + LC_UUID 一致性 + Segment 权限 + 大小校验 | 3.7 |
| `MultiPathFileDetector` | 多路径文件一致性（FileManager/stat/lstat/access/fopen） | 3.7 |
| `RandomizedDetection` | 时序异常 + 时钟反转 + 随机化环境检查 | 3.7 |
| `FingerprintDeobfuscation` | 模拟器 / 虚拟化痕迹 / 可疑硬件 / 指纹突变 | 3.7 |
| `SensorReplayDetector` | 传感器数据回放检测（时间戳/探针/噪声熵） | 3.7 |
| `GPURenderProbe` | Metal 设备特征 + GPU 计算延迟探测 | 3.7 |
| `IsaSwizzleDetector` | isa swizzling + 消息转发劫持 + 方法数量异常 | 3.7 |

### 设备 & 环境信号

| Provider | 检测维度 | 版本 |
|----------|----------|------|
| `DRMCapabilityProvider` | FairPlay DRM 等级 + 设备交叉验证 | 3.5 |
| `BatteryEntropyProvider` | ChargeCounter / EnergyCounter / 电压时序方差 | 3.5 |
| `MountPointProvider` | 虚拟化 FS 黑名单 + 必需挂载白名单 | 3.5 |
| `VPhoneHardwareProvider` | GPU 名称 / 设备型号 / Board ID / 内核版本 | 3.x |
| `LayeredConsistencyProvider` | Prologue 完整性 / Timing / 传感器熵 / 触摸熵 | 3.x |

---

## 配置参考

### CPRiskConfig

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `enableBehaviorDetect` | `true` | 行为采集（触摸 + 运动） |
| `enableNetworkSignals` | `true` | VPN / 代理检测 |
| `threshold` | `60` | 高风险判定阈值（4.0 起强制上限 100） |
| `enableRemoteConfig` | `true` | 远程配置拉取 |
| `defaultScenario` | `.default` | 默认业务场景 |
| `enableTemporalAnalysis` | `true` | 时序分析 |
| `enableAntiTamper` | `true` | 反篡改检测（4.0 起核心检测不可禁用） |

### 场景策略阈值

| 场景 | 中风险 | 高风险 | 严重 | 越狱处置 |
|------|--------|--------|------|----------|
| `default` | 30 | 55 | 80 | challenge |
| `login` | 35 | 60 | 85 | challenge |
| `register` | 25 | 50 | 75 | block |
| `payment` | 20 | 45 | 70 | block |
| `sensitiveAction` | 15 | 40 | 65 | block |

---

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

### HMAC 防篡改（4.0 加固）

```
客户端：score|isHighRisk|timestamp|nonce|tampered → HMAC-SHA256(deviceKey)
             ↑ 4.0 起：包含 timestamp 窗口校验（默认 300s），防止旧结论重放
攻击者：修改 score → 无法重算 HMAC（不知道 deviceKey 派生输入）
        重放旧签名 → timestamp 超出窗口，验签拒绝
服务端：验签失败 → 反而暴露攻击行为
验签实现：HMAC.isValidAuthenticationCode（常量时间，4.0 修复时序侧信道）
```

### 存储安全（4.0 + 4.1 加固）

```
UserDefaults 写入流程：
  原始 JSON → PayloadCrypto.encrypt(AES-GCM) → [0xAE magic | 密文]  ← 4.1：magic header 区分密文
  密文 → StorageIntegrityGuard.sign(HMAC-SHA256, purpose+len前缀) → 签名
  {密文, 签名} → UserDefaults

UserDefaults 读取流程：
  UserDefaults → {密文, 签名}
  StorageIntegrityGuard.verify() → 失败则清除并返回空（fail-closed）
  PayloadCrypto.decrypt()：检查 0xAE magic header → 不匹配直接 throw  ← 4.1：防明文误读
    Release：解密失败 → 清除缓存，不 fallback 明文                    ← 4.1：Fail-Closed
    Debug：解密失败 → fallback 到明文（兼容旧数据）

DeviceHistory（4.1 迁移）：
  存储路径：Documents → Application Support（防外部访问）
  文件保护：NSFileProtectionComplete（锁屏后密钥清除）
  数据加密：PayloadCrypto.encrypt，只有 HMAC 不够

目的：越狱设备直接读 plist 只能看到 AES-GCM 密文；即使解密，篡改后签名失效；
      加密失败不再静默降级为明文，防止对手主动破坏加密路径
```

### 配置信任链（4.0 新增）

```
服务端：RemoteConfig JSON → HMAC-SHA256(signingKey) → X-Config-Signature 响应头
SDK：收到响应 → ConfigSignatureVerifier.verify(body, header)
         ↓ 未配置 signingKey（Release）→ 拒绝（Fail-Close）
         ↓ 签名不匹配 → 拒绝，使用本地缓存
         ↓ 验证通过 → 应用配置
防 MITM：即使攻击者绕过 TLS Pinning，也无法伪造合法签名
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

### Provider 注册表安全（4.0 + 4.1 加固）

```
start() 调用后 → seal() 封锁注册表
sealed 状态下：
  register(id: "anti_tampering", type: EvilProvider)
    → ObjectIdentifier(EvilProvider) ≠ ObjectIdentifier(AntiTamperingSignalProvider)
    → 拒绝注册
  register(id: "anti_tampering", type: AntiTamperingSignalProvider) ← 同类型弱实例
    → ObjectIdentifier(弱实例) ≠ ObjectIdentifier(原实例)         ← 4.1 新增
    → 拒绝注册，注入 provider_instance_replaced 信号（weightHint: 85）
  unregister(id: "vphone_hardware")
    → id 在 internalProviderIDs → 拒绝，注入 provider_tamper_attempt 信号
  Provider.signals() 崩溃
    → autoreleasepool 隔离，注入 signalCollectionFailed 信号（score=80）
```

### Frida 五维对抗

```
进程层：task_threads → 线程名/数量异常 → 不可隐藏（Frida 核心线程无法关闭）
内存层：vm_region_64 → V8 堆 / JIT 代码页 → 无法避免（JS 引擎必须分配内存）
运行时层：method_getImplementation + dladdr → IMP 重定向 → 无法绕过（hook 本质就是改 IMP）
网络层：getsockname / 目录遍历 → Unix Socket → 可绕过但需修改 Frida 源码
时序层：mach_absolute_time → 纳秒级延迟 → 物理定律无法绕过（额外指令必然消耗时间）
```

### SDK 自保护纵深

```
存储层：基线 + 指纹存入 Keychain + ACL 保护 → 删除/导出双重防护
        UserDefaults 全加密 + HMAC（4.0 新增）→ 明文不可读，篡改即失效
通信层：TLS 证书固定 + 服务端配置签名（4.0 新增）→ 中间人无法篡改配置/策略
反调试层：ptrace(PT_DENY_ATTACH) → 调试器附加直接失败 / 暴露已附加状态
注入层：DYLD_INTERPOSE + PLT 持久化基线 → hook 在先也能检测
完整性层：SDK UUID + 签名 + 权限 + 大小四重校验 → 整体替换 SDK 必被发现
多路径层：FileManager / stat / lstat / access / fopen 五路交叉 → 单路 hook 立即暴露
随机化层：检测顺序 + 延迟随机 → 攻击者无法针对固定顺序编写绕过脚本
运行时层：isa swizzle + 消息转发 + 方法数量 → ObjC runtime 深度攻击无处遁形
          Provider 类型锁定（4.0 新增）→ 内部 Provider ID 欺骗无效
硬件层：GPU Metal 探测 + 传感器噪声熵 → 云手机软件模拟/数据回放无法伪装
决策层：安全地板强制 + 关键权重下限 + 决策树 fallthrough 修复（4.0 新增）
```

---

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

<p align="center"><sub>CloudPhoneRiskKit 4.2 — Quad Red Team Audit + Trust Root Hardening</sub></p>
