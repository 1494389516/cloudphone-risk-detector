# CloudPhoneRiskKit 第四轮红队分析

## 结论

本轮重点从第三轮的“结构性攻击链”继续下钻，验证 4.1 之后仍残留的五类核心风险：

1. 配置与策略链路仍存在“未验签 fallback”与“合法弱配置降级”空间。
2. 运行时检测仍有较大的“统一 hook 致盲面”，多个 detector 共享少数底层原语。
3. `anti_tamper` 与 legacy `jailbreak` 结论分离，可能让宿主误读风险状态。
4. 本地历史、设备身份与 challenge 绑定仍缺乏足够强的新鲜度/信任锚。
5. SDK 本地 anti-replay 与报告存储接口边界偏宽，存在误用和情报泄露面。

本轮更偏向“宿主误配 + 注入对手 + 有限本地能力”的真实攻防，而不是理论上最强对手。

## 威胁模型

- `宿主误配`：未配置签名 key、未接 pinning、误把联调接口当生产安全能力。
- `本地注入对手`：Frida / 越狱 / 同进程 hook，可统一伪造 libc / dyld / ObjC runtime 视图。
- `本地存储对手`：可回放旧缓存、旧历史、旧 envelope，但不一定能破解 AES-GCM。

## Findings

### P0-1 RemoteConfig 与 Policy 仍允许未验签 fallback 成为活跃配置

- 严重性：Critical
- 可打性：高

成因：

- `RemoteConfigProvider.fetchLatest()` 在未配置 `ConfigSignatureVerifier` 时仍会接收配置，只是标记为 `verifiedByServer=false`。
- `ConfigCache.loadLatestFromDisk()` 在没有已验签条目时仍会 fallback 到未验签条目。
- `PolicyManager.fetchLatestPolicy()` 同样只有配置 key 时才验签，缓存恢复只验本地 HMAC，不验来源真实性。

影响：

- 集成方漏配 signing key、初始化顺序错误、首跑遭遇弱网络劫持时，恶意配置/策略仍可跨重启长期生效。
- 风险阈值、hardening 开关、blind challenge 配置可被持久化降级。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/RemoteConfigProvider.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/ConfigCache.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Decision/ServerRiskPolicy.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`

### P0-2 合法签名配置仍可关闭关键 hardening，形成“签名后降级”

- 严重性：Critical
- 可打性：中高

成因：

- `RemoteConfig.toRiskConfig()` 允许远程关闭 `enableBehaviorDetect`、`enableNetworkSignals`、多类 jailbreak detector。
- `SecurityHardeningConfig` 中 `enableEnvelopeSignatureV2`、`enableChallengeBinding`、`killSwitchEnabled` 都是远程可控位。
- `enforceSecurityFloor()` 只恢复了少数检测开关，安全地板还不够宽。

影响：

- 一旦后台配置权失守或签名 key 泄露，攻击者可下发“合法但更弱”的配置，把核心检测链缩到可绕过水平。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Config/RemoteConfig.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`

### P0-3 运行时仍存在统一 hook 致盲面

- 严重性：Critical
- 可打性：中高

成因：

- `FileDetector`、`SysctlDetector`、`FridaDetector`、`PointerValidationDetector`、`IndirectSymbolPointerDetector` 等仍主要依赖 `stat/access/sysctl/dlsym/dladdr/_dyld_*`。
- 仓库已有 `SVCDirectCall` / `DualPathValidator`，但尚未大规模接入高价值 detector 主链。

影响：

- 攻击者若先统一控制这批底层原语，可一次性压低越狱、hook、Frida、完整性多条检测链命中率。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Jailbreak/Detectors/FileDetector.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Jailbreak/Detectors/SysctlDetector.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Jailbreak/Detectors/PointerValidationDetector.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Jailbreak/Detectors/IndirectSymbolPointerDetector.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Util/SVCDirectCall.swift`

### P1-4 anti_tamper 命中后不会同步抬高 legacy jailbreak 结论

- 严重性：High
- 可打性：高

成因：

- 主流程 `buildRiskContext()` 仍使用 `jailbreakEngine.detect(config:)` 作为 `context.jailbreak`。
- `AntiTamperingSignalProvider` 只是额外 signal 注入，没有回写 `jailbreakConfidence` / `jailbreakIsJailbroken` / `detectedMethods`。

影响：

- 宿主若只消费 legacy `jailbreak` 字段，可能误以为设备“未越狱 / 未被篡改”，而忽略额外 tamper 信号。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/RiskReport.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/Adapter/AntiTamperingSignalProvider.swift`

### P1-5 基线仍偏 TOFU，首启/重装/版本切换存在投毒窗口

- 严重性：High
- 可打性：中

成因：

- `PLTIntegrityGuard.verifyWithPersistedBaseline()` 在无基线时仍信任当前态并立即建基线。
- `SDKBinaryIntegrityChecker` 在首次运行、UUID 变化、size 变化时会自动写入新的 Keychain 基线。

影响：

- 若攻击发生在首启前、重装后、清 Keychain 后或版本切换窗口，脏状态仍可能固化成新基线。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/AntiBypass/SDKIntegrityChecker.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/AntiBypass/SDKBinaryIntegrityChecker.swift`

### P1-6 历史状态与设备身份仍可被“合法回放 / 静默漂移”

- 严重性：High
- 可打性：中高

成因：

- `RiskHistoryStore` / `DeviceHistory` 只保证“未篡改”，不保证“最新”。
- `KeychainDeviceID.getOrCreate()` 在保存失败时仍直接返回新 UUID，设备身份不是 fail-closed。

影响：

- 攻击者可通过回放旧历史洗白设备记忆，或通过 deviceID 漂移切断与旧风险画像的关联。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Storage/RiskHistoryStore.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Analysis/DeviceHistory.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Device/KeychainDeviceID.swift`

### P1-7 challengeBinding 仍偏客户端自生成，local replay protection 仅内存态

- 严重性：High
- 可打性：中

成因：

- `buildBlindChallenge()` 仍由客户端基于服务端参数本地生成 `challengeId/seed/probeIds/expiresAt`。
- `LocalEnvelopeReplayStore` 底层是 `InMemoryNonceReplayStore`，重启即失忆。

影响：

- challenge 更像客户端自证材料，而不是严格的 server-issued challenge-response。
- 若宿主误把本地校验当作生产 anti-replay，会被简单进程重启绕过。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskKit.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Detection/ChallengeTrigger.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/SecureEnvelopeValidator.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Risk/ReportEnvelope.swift`

### P2-8 本地报告存储仍有宽边界暴露面

- 严重性：Medium
- 可打性：中

成因：

- `CPRiskStore.encryptionEnabled` 是公开可切换开关。
- `decryptReport(atPath:)` 是公开 API，容易被宿主或调试面滥用。

影响：

- 风险报告可被离线收集、复盘、逆向，从而帮助攻击者微调绕过策略。

关键文件：

- `RiskDetectorApp/Sources/CloudPhoneRiskKit/Storage/CPRiskStore.swift`
- `RiskDetectorApp/Sources/CloudPhoneRiskKit/CloudPhoneRiskAppCore/RiskDetectionService.swift`

## 4.2 优先修复建议

### 第一优先级

- P0-1 未验签 fallback 与 Policy/RemoteConfig 信任链不一致
- P0-2 合法签名弱配置降级
- P0-3 统一 hook 致盲面

### 第二优先级

- P1-4 anti_tamper 与 legacy jailbreak 结论分裂
- P1-5 TOFU 基线投毒窗口
- P1-6 历史回放与 deviceID 漂移
- P1-7 challengeBinding / local replay 边界

### 第三优先级

- P2-8 本地报告暴露面

## 验证建议

- Case 1：未配置 signing key 时，验证是否仍会采用未验签 RemoteConfig / Policy 缓存。
- Case 2：下发合法签名但关闭关键 hardening 的配置，验证安全地板能否拦截。
- Case 3：统一 hook `stat/sysctl/dlsym/dladdr/_dyld_*` 后，观察多 detector 是否同步失明。
- Case 4：让 anti_tamper 触发但 legacy jailbreak 保持低分，验证宿主字段是否分裂。
- Case 5：删除 Keychain 基线或重装后首启，验证完整性当前态是否再次被信任。
- Case 6：回放旧 `RiskHistoryStore` / `DeviceHistory` 数据，验证设备记忆是否回退。
- Case 7：重启进程后重放同一 secure envelope，验证本地 anti-replay 是否失效。

## 备注

本轮仍以代码级红队审计为主，尚未补充完整的真机注入脚本。若进入第五轮，建议转向“定制 Frida / Hook 工具链 + 真机复现”验证本轮修复的真实抗打性。
