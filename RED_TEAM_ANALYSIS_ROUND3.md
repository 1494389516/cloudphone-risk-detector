# CloudPhoneRiskKit 第三轮红队分析

## 结论

本轮重点不再是单个 detector 的漏检，而是 4.0 修复后仍然存在的三类结构性攻击链：

1. 配置面失守后，可通过缓存、回滚、导入等路径把弱化配置持久化。
2. 运行时编排层仍可被“弱实例替换”或“首跑投毒”打出整片检测盲区。
3. 本地状态与上报签名面仍有回滚、降级和元数据未覆盖问题，可作为二阶段扩大战果。

本报告按真实可打性排序，更偏向移动端对抗和 SDK 红队，而不是理论完美性。

## 威胁模型分层

- `网络攻击者`：可控链路、可做 MITM、可重放历史响应，但不能在客户端执行任意代码。
- `宿主误配 / 弱集成`：业务方未强制配置签名密钥、允许 HTTP、错误暴露调试或导入接口。
- `本地对手 / 注入对手`：越狱、重打包、Frida、恶意三方 SDK、同进程代码执行。

## 攻击链摘要

### 链路 A：配置投毒持久化

`弱远程入口 -> 恶意配置被写入缓存 -> 重启后继续生效 -> 关闭 challengeBinding / 降级 envelope / 放宽阈值`

### 链路 B：运行时弱实例替换 + 基线投毒

`start 后窗口注入 -> 替换内部 Provider 为弱配置实例 -> 基线由当前运行态建立 -> 后续验证自洽`

### 链路 C：本地状态回滚 + 上报域分离遗漏

`回滚旧历史 / 旧缓存 -> 降低时序与行为侧记忆 -> 修改 envelope 元数据而不破坏签名 -> 增加服务端解析与审计混淆`

## Findings

### P0-1 配置缓存只校验本地完整性，不校验来源真实性与新鲜度

- 严重性：Critical
- 真实可打性：高
- 威胁模型：宿主误配、本地对手、一次性网络突破后的持久化

成因：

- `RemoteConfigProvider` 在验签通过后会直接 `cache.save(config)`。
- `ConfigCache`、`PolicyManager` 从本地恢复时，只验证 `StorageIntegrityGuard` 的本地 HMAC，不验证“这份缓存最初是否来自合法服务端签名”。
- `rollback(to:)`、`importCache(from:)`、`update(fromJSON:)` 等路径都可把旧数据重新放回活跃状态。

影响：

- 一次恶意配置写入即可跨重启长期生效。
- 可重新打开弱配置，如关闭 `enableChallengeBinding`、退回 `v1` envelope、降低阈值、弱化字段混淆。
- 即便后续补上 signing key 或修正 endpoint，也可能先吃到已投毒缓存。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/RemoteConfigProvider.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/ConfigCache.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Decision/ServerRiskPolicy.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`

建议：

- 缓存条目中显式记录“来源已验签”状态、服务端签名摘要、签发时间和单调版本。
- 缓存恢复时不只验本地 HMAC，还要验服务端来源约束。
- 禁用 release 下的 `importCache` / `rollback` / `update(fromJSON:)`，或至少做能力隔离。

### P0-2 远程配置入口未强制 HTTPS 且签名校验是可选项

- 严重性：Critical
- 真实可打性：高
- 威胁模型：网络攻击者、宿主误配

成因：

- `configureRemoteConfigProvider(urlString:)` 允许 `https` 和 `http`。
- `RemoteConfigProvider.fetchLatest()` 与 `PolicyManager.fetchLatestPolicy()` 只有在 `ConfigSignatureVerifier.isConfigured` 为真时才做签名校验。
- 当前安全底线没有做到“release 必须 HTTPS + 必须配置签名密钥”。

影响：

- 集成方一旦漏配 signing key 或错误使用 HTTP，配置面直接退化成纯传输信任。
- 结合 P0-1 可把临时网络突破扩展为持久化控制。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/RemoteConfigProvider.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Decision/ServerRiskPolicy.swift`

建议：

- release 构建下只允许 `https`。
- 未配置 signing key 时，远程配置与策略拉取整体 fail-closed，而不是只在 verifier 内部做条件判断。
- 为 pinning hash 提供不可省略的生产配置路径。

### P0-3 sealed 只锁 Provider 类型，不锁实例与配置

- 严重性：Critical
- 真实可打性：中高
- 威胁模型：本地对手 / 注入对手

成因：

- `RiskSignalProviderRegistry.seal()` 记录的是 `ObjectIdentifier(type(of: provider))`。
- `register(_:)` 在 sealed 后，只比较类型是否一致，不比较实例、构造参数、配置强度。
- `AntiTamperingSignalProvider` 是公开类型，可被重新构造为更弱配置实例后替换原实例。

影响：

- 攻击者可在 `start()` 之后、首次评估之前，替换掉内部 provider 为“同类弱实例”。
- 这不是简单移除 provider，而是保留合法 `id` 和类型前提下，静默缩减检测覆盖面。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/RiskSignalProvider.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/Adapter/AntiTamperingSignalProvider.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`

建议：

- sealed 后同时校验实例指针或配置摘要，而非只校验类型。
- 内部 provider 改为不可由外部任意构造的封装工厂。
- 对关键 provider 追加“配置强度地板”。

### P0-4 完整性检测仍存在首跑投毒和运行时自基线化问题

- 严重性：Critical
- 真实可打性：中高
- 威胁模型：本地对手 / 注入对手

成因：

- `AntiTamperingSignalProvider` 的 PLT 检测路径里，先 `captureBaseline()` 再 `verify(baseline:)`，基线来自当前运行态。
- `TextSegmentIntegrityChecker` 在 `baseline_established`、`version_changed` 两个路径上都会直接信任当前哈希并重建基线。
- `sdk_image_not_found`、`hash_failed`、`encrypted_skip` 最终不产出风险信号。

影响：

- 攻击者若能在首次校验前完成 hook 或 patch，就可以把“脏状态”写成可信基线。
- 通过重签、版本切换、镜像隐藏等方式，还能诱导重新建基线或静默跳过。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/Adapter/AntiTamperingSignalProvider.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/AntiBypass/SDKIntegrityChecker.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/AntiBypass/TextSegmentIntegrityChecker.swift`

建议：

- 统一使用持久化可信基线，禁止“当前态即基线”的主链路。
- 首次建基线应绑定安装态、签名态、版本态，并限制重建条件。
- 对 `sdk_image_not_found` / `hash_failed` 增加 tampered 或 degraded 信号，而不是静默。

### P1-5 多个检测器共享同一批可被统一 hook 的底层原语，双路径校验未真正进入主链

- 严重性：High
- 真实可打性：中高
- 威胁模型：本地对手 / 注入对手

成因：

- 大量 detector 依赖 `_dyld_image_count`、`_dyld_get_image_name`、`getenv`、`stat`、`sysctlbyname`、`dlsym` 等少数底层原语。
- `SVCDirectCall` 与 `DualPathValidator` 已实现，但当前主检测链里没有形成真正强制的“双路径信任根”。

影响：

- 攻击者只需统一伪造底层视图，就能同时影响多组 detector。
- 这会导致“看起来很多 detector，实际共享一个可污染视图”。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Util/SVCDirectCall.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/AntiTampering/*`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Jailbreak/Detectors/*`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Providers/LayeredConsistencyProvider.swift`

建议：

- 把 `DualPathValidator` 真正接入关键检测链。
- 给高价值 detector 增加“libc 路径 + RTLD_NEXT 路径 + Mach-O 视图路径”三方交叉。
- 单点原语异常时，提升整组 detector 的怀疑权重。

### P1-6 加密失败与解密失败都会静默降级为明文路径

- 严重性：High
- 真实可打性：中
- 威胁模型：本地对手 / 注入对手

成因：

- `RiskHistoryStore`、`ConfigCache`、`PolicyManager` 保存时均使用 `(try? PayloadCrypto.encrypt(encoded)) ?? encoded`。
- 读取时均先尝试 `decrypt(stored)`，失败则直接 `data = stored` 继续按明文解码。
- 这意味着一旦加密层出错，系统不是 fail-closed，而是回落为“只有 HMAC，没有保密”。

影响：

- 对手可通过破坏加密路径把敏感缓存稳定降级为明文。
- 因 HMAC 是对 `stored` 本体做的，明文与密文都能成为“合法格式”。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Util/PayloadCrypto.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Storage/RiskHistoryStore.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/ConfigCache.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Decision/ServerRiskPolicy.swift`

建议：

- 为存储格式增加显式版本头和加密标记。
- release 下加密失败应 fail-closed，而不是自动回退明文。
- 必要时将存储与解密异常上报为高权重 tampered 信号。

### P1-7 DeviceHistory 可被回滚，且仍落在 Documents 明文路径

- 严重性：High
- 真实可打性：中高
- 威胁模型：本地对手 / 注入对手

成因：

- `DeviceHistory` 现在有 HMAC 完整性保护，但没有反回滚约束。
- 文件仍存储于 `documentDirectory`，持久化时直接 `data.write`，未见加密和文件保护属性。

影响：

- 旧的合法历史快照可被整体回放，削弱时序分析、设备年龄、越狱轨迹记忆。
- 本地对手可以直接读取该文件，获得行为与风险判定节奏的情报。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Analysis/DeviceHistory.swift`

建议：

- 迁移到 `Application Support` 并启用文件保护。
- 给历史状态增加单调计数器、最新时间戳水位、或服务端回执绑定。
- 若历史用于高价值策略，应考虑加密而不只是 HMAC。

### P1-8 ReportEnvelope 的 `reportId` / `keyId` / `fieldMappingVersion` 不在签名域内

- 严重性：High
- 真实可打性：中
- 威胁模型：本地对手、服务端解析链复杂场景

成因：

- `buildSignatureInput(...)` 只覆盖 `sigVer|nonce|ts|sessionToken|canonicalPayload`。
- `reportId`、`keyId`、`fieldMappingVersion` 被放入 envelope，但不参与签名。

影响：

- 攻击者可修改这些元数据而不破坏签名。
- 若服务端使用 `keyId` 做验签路由、用 `fieldMappingVersion` 做反混淆映射、用 `reportId` 做幂等或审计关联，则可能出现解析歧义、审计污染或局部 DoS。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/ReportEnvelope.swift`

建议：

- 把 `reportId`、`keyId`、`fieldMappingVersion` 纳入签名输入。
- 服务端对这些字段增加严格一致性校验，避免把它们当作不可信外层元数据。

### P1-9 blind challenge 仍偏客户端自证，缺少强服务端一次性绑定

- 严重性：High
- 真实可打性：中
- 威胁模型：本地对手 / 注入对手

成因：

- `buildChallengeBindingIfNeeded()` 与 `buildBlindChallenge()` 说明 challenge 的核心内容由客户端基于服务端策略参数本地构造。
- 这更像“客户端自生成 challenge 绑定信息”，而不是服务端逐次签发、登记、消费的一次性 challenge-response。

影响：

- 一旦配置面或运行时被控制，攻击者更容易生成自洽但不强 server-bound 的 challenge 数据。
- 若服务端没有 challenge ledger，则 replay 和伪造成本仍偏低。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Decision/ServerRiskPolicy.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/ChallengeTrigger.swift`

建议：

- 将 blind challenge 升级为服务端签发、服务端登记、客户端消费的 challenge-response。
- 服务端记录 challengeId、过期时间、探针选择与消费状态。

### P2-10 DetectorRegistry 是潜在的未来注入面

- 严重性：Medium
- 真实可打性：当前中低，未来中高
- 威胁模型：本地对手 / 注入对手

成因：

- `DetectorRegistry` 是公开可变注册表，无 seal、无锁。
- `detectAll(enabledTypes:)` 形参存在，但当前实现并未真正按传入集合过滤执行。

影响：

- 若未来主链切到这套 V2 registry，攻击者可注册替代 detector、移除 detector，或制造并发不稳定面。
- 当前更像 latent injection point，而不是现在线上主链直接可打点。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/Adapter/DetectorRegistry.swift`

建议：

- 在接入主路径前先做 seal、锁、白名单与能力约束。
- 修复 `enabledTypes` 未生效问题，避免错误安全预期。

## 4.1 优先修复建议

### 第一优先级

- P0-1 配置缓存来源真实性与新鲜度缺失
- P0-2 远程配置入口未强制 HTTPS + 必配签名
- P0-3 Provider 同类型弱实例替换
- P0-4 基线首跑投毒 / 当前态自基线化

### 第二优先级

- P1-6 存储加密静默降级
- P1-7 DeviceHistory 回滚与明文暴露
- P1-8 ReportEnvelope 元数据未签名

### 第三优先级

- P1-9 blind challenge 强绑定不足
- P2-10 DetectorRegistry 未来注入面

## 建议的验证脚本方向

### Case 1：配置持久化降级

- 注入一份弱化 `RemoteConfig`
- 确认其被 `ConfigCache.save()` 写入
- 重启后不走网络，验证 `currentConfig` 是否仍采用弱化配置
- 检查 `buildSecureReportEnvelope()` 是否真的移除了 `challengeBinding` 或退回 `v1`

### Case 2：Provider 弱实例替换

- 在 `start()` 之后、首次 `evaluate()` 之前，重新注册 `anti_tampering`
- 使用弱配置实例观察关键检测器是否减少
- 核对 registry 是否只做类型比较而未拒绝实例替换

### Case 3：首跑基线投毒

- 在首次完整性校验前预先 hook 关键符号
- 观察 `PLTIntegrityGuard` / `TextSegmentIntegrityChecker` 是否把当前脏态写成基线
- 再次评估是否仍认为“完整”

### Case 4：明文降级

- 让 `PayloadCrypto.encrypt()` 或 `decrypt()` 人工失败
- 观察缓存是否回退到明文写入 / 明文读取
- 验证 HMAC 仍通过，功能继续运行

## 备注

本轮主要为代码级红队审计与攻击链重建，尚未补充完整的设备侧 PoC 脚本。若进入第四轮，建议直接围绕上面的 4 个验证 case 做真机或越狱环境复现。
