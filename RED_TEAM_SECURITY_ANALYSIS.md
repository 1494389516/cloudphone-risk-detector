# CloudPhoneRiskKit 红队安全审计报告

> 审计范围：Storage/、Risk/、Util/、Device/、Config/、Network/ 及 PolicyManager
> 审计视角：密钥管理、硬编码秘密、证书固定、加密/签名、存储篡改、配置注入、可 Hook API

---

## 一、密钥管理弱点 (Key Management Weaknesses)

### 1.1 PayloadCrypto 本地加密密钥

**位置**：`Util/PayloadCrypto.swift` L6-7, L39-51

```swift
private static let keyService = "CloudPhoneRiskKit"
private static let keyAccount = "aes_gcm_key_v1"
```

**问题**：
- Keychain 的 `service` 和 `account` 为**硬编码常量**，攻击者可直接构造相同 query 读取密钥
- 密钥无设备绑定（无 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 的 ACL 强化），备份可导出
- 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`，设备首次解锁后密钥常驻内存

**绕过方法**：
1. 在越狱设备上通过 Keychain 导出工具（如 keychain-dumper）读取 `CloudPhoneRiskKit` / `aes_gcm_key_v1`
2. Hook `SecItemCopyMatching` 返回伪造密钥，或直接 Hook `PayloadCrypto.symmetricKey()` 返回攻击者控制的 key
3. 备份提取：从 iTunes/Finder 备份中解析 Keychain 数据（需设备密码）

---

### 1.2 RiskConclusionSigner / DeviceKeyDeriver 密钥派生

**位置**：`Risk/RiskConclusionSigner.swift` L38-59

```swift
let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)"
let hash = SHA256.hash(data: combinedData)
let derivedKey = HKDF<SHA256>.deriveKey(...)
```

**问题**：
- 派生输入全部来自**可 Hook 的 API**：`deviceID`（Keychain）、`hardwareMachine`（sysctl）、`kernelVersion`（sysctl）
- 无服务端参与，攻击者只需伪造这三项即可推导出相同 `deviceKey`
- `info` 固定为 `"CloudPhoneRiskKit.DeviceKey"`，无版本/场景区分

**绕过方法**：
1. Hook `KeychainDeviceID.getOrCreate()` 返回固定 UUID
2. Hook `Sysctl.string("hw.machine")` 返回目标设备型号（如 `iPhone14,2`）
3. Hook `Sysctl.string("hw.model")` 或 kernel 相关 sysctl
4. 用相同算法在攻击侧计算 `deviceKey`，伪造 `SignedRiskConclusion`

---

### 1.3 ReportEnvelope 签名密钥

**位置**：`Risk/ReportEnvelope.swift` L155-156, L178-181, L411-420

**问题**：
- `signingKey` 由调用方传入，若业务侧硬编码或从配置下发，存在泄露风险
- **测试用硬编码密钥**：`createForTesting` 使用 `signingKey: "default-test-key"`，若生产误用则完全可伪造
- 无密钥轮换的客户端强制校验（keyId 可被伪造，若服务端不严格校验 keyId 则易被降级）

**绕过方法**：
1. 若生产环境误用 `createForTesting` 或类似硬编码 key，直接使用 `"default-test-key"` 伪造签名
2. 若 signingKey 从 RemoteConfig 下发，通过配置注入（见 6.x）获取或篡改

---

## 二、硬编码秘密与可预测值 (Hardcoded Secrets)

### 2.1 ObfuscatedStrings 混淆密钥

**位置**：`Util/ObfuscatedStrings.swift` L4-6, L49-64, L74-76

```swift
static func xorDecode(_ bytes: [UInt8], key: UInt8) -> String { ... }
// 示例：key: 0x42, 0x37, 0x65, 0x25, 0x24, 0x45
```

**问题**：
- XOR/ROT13/Caesar 等为**弱混淆**，密钥和算法均在二进制中，静态分析即可还原
- Frida 路径、Cydia 路径、hook 框架名等敏感字符串虽混淆，但解密逻辑固定，逆向可批量还原

**绕过方法**：
1. 静态分析：提取 `StringDeobfuscator` 及 `ObfuscatedConstants` 的字节数组与 key，本地还原
2. 运行时 Hook `StringDeobfuscator.xorDecode` 等，打印解密结果
3. 获取还原后的路径列表，用于绕过越狱/云手机检测（如伪造 `/usr/sbin/frida-server` 不存在）

---

### 2.2 DecoyFieldInjector / RuntimeFieldMapping 种子与字段

**位置**：`Risk/DecoyFieldInjector.swift` L10-11, L44, L50-58

```swift
private static let shortCodeChars = "abcdefghijklmnopqrstuvwxyz0123456789"
private static let semanticFields: [String] = [
    "jailbreak_score", "vm_detected", "imu_variance", ...
]
```

**问题**：
- `SeededRNG` 使用固定 LCG 参数（`6364136223846793005`, `1442695040888963407`），种子可预测时输出可复现
- `semanticFields` 硬编码，字段混淆的映射可被穷举或从版本+种子推导
- `RuntimeFieldMapping.generate(seed:version)` 的 seed 若来自可预测源（如时间戳），映射可被还原

**绕过方法**：
1. 若 seed 来自 `Date().timeIntervalSince1970` 或类似，可缩小搜索空间
2. 已知 version 时，暴力枚举 seed 或逆向 `SeededRNG` 还原 mapping
3. 服务端若依赖字段混淆防爬，客户端还原后可构造合法格式请求

---

### 2.3 ReportEnvelope 测试密钥

**位置**：`Risk/ReportEnvelope.swift` L411-420

```swift
public static func createForTesting(...) throws -> ReportEnvelope {
    try create(..., sessionToken: "test-token", signingKey: "default-test-key")
}
```

**问题**：生产构建若未移除或误用，攻击者可直接用 `"default-test-key"` 伪造任意信封。

---

## 三、可绕过的证书固定 (Bypassable Certificate Pinning)

### 3.1 RemoteConfigProvider 未使用证书固定

**位置**：`Config/RemoteConfigProvider.swift` L82-83

```swift
URLSession.shared.dataTask(with: request) { ... }
```

**问题**：
- 使用 `URLSession.shared`，**完全未启用证书固定**
- 远程配置可被 MITM 篡改，进而控制阈值、检测开关、白名单、payloadFieldMapping、signingKey 等

**绕过方法**：
1. 代理 + 自签名证书（Charles/Burp + 安装 CA）
2. 替换为恶意 RemoteConfig：如 `threshold: 100`（永不触发）、`jailbreakEnableFileDetect: false`、`whitelist.deviceIDs: [攻击者设备ID]`
3. 若配置中含 signingKey 或 keyResolver 相关数据，可同时获取签名密钥

---

### 3.2 PolicyManager 未使用证书固定

**位置**：`Decision/ServerRiskPolicy.swift` L168-172

```swift
public func fetchLatestPolicy(from url: URL) async throws -> ServerRiskPolicy {
    let (data, _) = try await URLSession.shared.data(from: url)
    ...
}
```

**问题**：策略拉取同样使用 `URLSession.shared`，无证书固定，MITM 可注入任意策略。

**绕过方法**：与 3.1 相同，MITM 下发恶意策略（如 blocklist 置空、threshold 调高、关闭关键检测）。

---

### 3.3 CertificatePinningSessionDelegate 设计问题

**位置**：`Network/CertificatePinningSessionDelegate.swift` L18-21, L89-94

**问题**：
- `allowsSystemCA: true` 时，pin 不匹配会**回退到系统 CA**，等同于无固定
- 若 `pinnedHashes` 为空，直接 `performDefaultHandling`，等同于未启用
- 当前 **RemoteConfigProvider 和 PolicyManager 均未使用** 此 delegate，pinning 代码形同虚设

**绕过方法**：
1. 若集成方误设 `allowsSystemCA: true`，任意有效证书均可通过
2. 不传入 `pinnedHashes` 或传空 Set，同样绕过

---

## 四、弱加密与签名 (Weak Encryption/Signing)

### 4.1 ObfuscatedStrings 弱混淆

**位置**：`Util/ObfuscatedStrings.swift` 全文

**问题**：XOR、ROT13、字节反转、Caesar 等均为**非加密**混淆，仅增加逆向成本，无法抵御主动攻击。

---

### 4.2 SignedRiskConclusion 签名算法

**位置**：`Risk/RiskConclusionSigner.swift` L12-26, L29-35

```swift
let input = "\(report.score)|\(report.isHighRisk)|\(timestamp)|\(nonce)|\(report.tampered)"
let hmac = HMAC<SHA256>.authenticationCode(for: data, using: deviceKey)
```

**问题**：
- HMAC-SHA256 本身安全，但 `deviceKey` 派生自可伪造的 deviceID/hw.machine/kernel（见 1.2）
- 签名输入为明文拼接，无绑定 payload 哈希，若存在多用途则可能被滥用

---

### 4.3 ReportEnvelope 签名

**位置**：`Risk/ReportEnvelope.swift` L325-336, L354-358

**问题**：
- HMAC-SHA256 实现正确，含 `timingSafeCompare` 防时序攻击
- 风险仍在于密钥来源（见 1.3）及配置/网络侧泄露

---

## 五、可篡改的存储 (Tamperable Storage)

### 5.1 RiskHistoryStore — UserDefaults 明文

**位置**：`Storage/RiskHistoryStore.swift` L21-22, L84-91

```swift
private let key = "cloudphone_risk_history_v1"
defaults.set(data, forKey: diskKey)  // UserDefaults
```

**问题**：
- 历史事件存于 **UserDefaults**，无加密、无完整性校验
- 攻击者可修改 `cloudphone_risk_history_v1`，伪造 `TimePattern`（如 `nightRatio24h`、`events24h`）影响风控

**绕过方法**：
1. 越狱设备直接写 UserDefaults plist
2. 备份/还原时篡改
3. 注入空数组或低风险模式事件，降低时序风险分

---

### 5.2 ConfigCache — UserDefaults 明文

**位置**：`Config/ConfigCache.swift` L35-37, L188-199

```swift
self.diskKey = "com.cloudphone.riskkit.remote_config_cache"
UserDefaults.standard.set(data, forKey: diskKey)
```

**问题**：
- RemoteConfig 完整 JSON 存于 UserDefaults，无签名校验
- 攻击者可替换为恶意配置，实现持久化配置注入

**绕过方法**：
1. 解码 `CacheEntry` 结构，构造恶意 `RemoteConfig` 写入
2. 设置 `killSwitchEnabled: true` 关闭拦截，或 `threshold: 100` 等

---

### 5.3 PolicyManager — UserDefaults 明文

**位置**：`Decision/ServerRiskPolicy.swift` L130, L175-182

```swift
private let cacheKey = "com.cloudphone.riskkit.policy.v3"
UserDefaults.standard.set(data, forKey: cacheKey)
```

**问题**：策略 JSON 明文存储，无完整性保护，可被篡改。

---

### 5.4 CPRiskStore 加密存储

**位置**：`Storage/CPRiskStore.swift` L9, L23-24, L54-58

**问题**：
- `encryptionEnabled = false` 时存明文 JSON，敏感信息泄露
- 加密时依赖 PayloadCrypto，其密钥管理存在 1.1 所述问题
- 文件路径固定：`Application Support/CloudPhoneRiskKit/reports/`，可被枚举

**绕过方法**：
1. 若 `encryptionEnabled == false`，直接读取 .json 文件
2. 若加密，通过 1.1 获取 Keychain 密钥后解密

---

## 六、配置注入可能 (Config Injection)

### 6.1 本地策略注入（DEBUG）

**位置**：`CloudPhoneRiskKit.swift` L46-51, L177-186

```swift
private static let localPolicyInjectionAllowed: Bool = {
    #if DEBUG
    return true
    #else
    return false
    #endif
}()
public func setServerRiskPolicyJSON(_ json: String) -> Bool
```

**问题**：DEBUG 下允许 `setServerRiskPolicyJSON` 注入任意策略；若 Release 包误用 DEBUG 宏或存在其他注入入口，则风险存在。

---

### 6.2 远程配置注入（MITM）

**位置**：`Config/RemoteConfigProvider.swift` L76-124

**问题**：无证书固定，MITM 可替换为恶意 RemoteConfig，控制：
- `policy.threshold`、`detector.*` 检测开关
- `whitelist.deviceIDs` 将攻击设备加入白名单
- `payloadFieldMapping`、`securityHardening` 等

---

### 6.3 环境变量控制

**位置**：`CloudPhoneRiskKit.swift` L53-59

```swift
ProcessInfo.processInfo.environment["CPRISKKIT_ALLOW_CONFIG_ROLLBACK"] == "1"
```

**问题**：Release 下可通过环境变量开启配置回滚，若攻击者能控制进程环境（如调试、注入），可触发非预期行为。

---

### 6.4 ConfigCache.importCache 无签名校验

**位置**：`Config/ConfigCache.swift` L169-174

```swift
public func importCache(from data: Data) throws {
    let decoded = try JSONDecoder().decode(CacheExport.self, from: data)
    for entry in decoded.entries {
        save(entry.config)
    }
}
```

**问题**：若存在调用 `importCache` 的入口（如调试、迁移），攻击者可传入恶意 `CacheExport` 注入配置，无签名校验。

---

## 七、来自可 Hook API 的派生值 (Hookable API-Derived Values)

### 7.1 DeviceFingerprint

**位置**：`Device/DeviceFingerprint.swift` L28-58

| API | 用途 | Hook 影响 |
|-----|------|-----------|
| `UIDevice.current.systemName/Version/model` | 系统信息 | 伪造设备型号、系统版本 |
| `UIScreen.main.bounds/scale` | 屏幕参数 | 伪造分辨率 |
| `Locale.current`, `TimeZone.current` | 地区时区 | 伪造地域 |
| `Sysctl.string("hw.machine")` | 硬件型号 | 伪造 iPhone 型号 |
| `device.identifierForVendor` | 厂商 ID | 影响设备标识稳定性 |

**绕过方法**：Hook 上述 API 返回“干净设备”特征，降低云手机/模拟器相关风险分。

---

### 7.2 KeychainDeviceID

**位置**：`Device/KeychainDeviceID.swift` L12-17

```swift
func getOrCreate() -> String {
    if let existing = read() { return existing }
    let newID = UUID().uuidString
    _ = save(newID)
    return newID
}
```

**问题**：Hook `read()` 返回固定 ID，或 Hook `getOrCreate()` 直接返回指定值，可稳定设备身份用于白名单或重放。

---

### 7.3 NetworkSignals

**位置**：`Network/NetworkSignals.swift` L47-80

| API | 用途 | Hook 影响 |
|-----|------|-----------|
| `NWPathMonitor` | 网络类型、expensive、constrained | 伪造 WiFi、非蜂窝 |
| `getifaddrs` | VPN 隧道接口 | 隐藏 utun/ppp/ipsec |
| `CFNetworkCopySystemProxySettings` | 代理配置 | 隐藏代理 |

**绕过方法**：Hook 使 `vpn.detected=false`、`proxy.detected=false`，消除网络风险分。

---

### 7.4 Sysctl / SVCDirectCall

**位置**：`Util/Sysctl.swift`, `Util/SVCDirectCall.swift`

**问题**：
- `Sysctl.string` 走标准 `sysctlbyname`，可被 PLT Hook
- `SVCDirectCall.secureSysctlbyname` 用 `dlsym(RTLD_NEXT)` 绕过当前进程 PLT，但若 Hook 在更底层（如内核、dyld 注入），仍可能被绕过
- `DualPathValidator` 依赖 std vs secure 不一致检测 tamper，若两端均被 Hook 为相同伪造值，则检测失效

**绕过方法**：
1. 内核级或更早注入，使 `sysctlbyname` 和 `dlsym` 下一跳均返回伪造值
2. 同时 Hook `Sysctl.string` 和 `SVCDirectCall.secureSysctlbyname` 返回一致伪造结果

---

### 7.5 Date / ISO8601 / 时间戳

**位置**：`Util/ISO8601.swift` L10-12, `Risk/ReportEnvelope.swift` L339-341

```swift
formatter.string(from: Date())
Int64(Date().timeIntervalSince1970 * 1000)
```

**问题**：`Date()` 可被 Hook（如通过 `clock_gettime`、`gettimeofday`），影响时间戳、nonce 过期判断、时序分析。

---

## 八、其他攻击面

### 8.1 RiskSignalProviderRegistry 可注册恶意 Provider

**位置**：`Risk/RiskSignalProvider.swift` L28-32

```swift
func register(_ provider: RiskSignalProvider) {
    providers.removeAll { $0.id == provider.id }
    providers.append(provider)
}
```

**问题**：若攻击者能执行代码（如越狱注入），可注册恶意 Provider 注入低风险或伪造信号，影响评分。

---

### 8.2 SecureBuffer / SecureString 清零时机

**位置**：`Util/SecureBuffer.swift` L13-22, L37-42

**问题**：`use` 闭包内若发生复制（如 `String` 传参、编译器优化），敏感数据可能残留在栈或堆，dump 内存可能恢复。

---

### 8.3 Logger 信息泄露

**位置**：`Util/Logger.swift` L6-8

**问题**：`isEnabled = true` 时，`Logger.log` 输出大量内部状态（路径、信号、分数等），可被调试或日志收集获取，辅助逆向与绕过。

---

## 九、修复建议优先级

| 优先级 | 建议 |
|--------|------|
| P0 | RemoteConfigProvider、PolicyManager 使用带证书固定的 URLSession |
| P0 | 移除或严格限制 `createForTesting`，禁止生产使用 `default-test-key` |
| P1 | DeviceKeyDeriver 引入服务端参与或不可伪造的绑定因子 |
| P1 | ConfigCache、PolicyManager、RiskHistoryStore 增加完整性校验（如 HMAC） |
| P1 | PayloadCrypto Keychain 使用 ACL（kSecAttrAccessibleWhenUnlockedThisDeviceOnly）并考虑设备绑定 |
| P2 | 远程配置与策略增加服务端签名，客户端验签后再应用 |
| P2 | 生产环境默认 `Logger.isEnabled = false` 并避免输出敏感字段 |
| P2 | 评估多路径校验（DualPathValidator）对底层 Hook 的抵御能力，考虑增加服务端校验 |

---

## 十、总结

从红队视角，当前主要风险集中在：

1. **网络层**：远程配置与策略拉取未做证书固定，MITM 可完全控制配置与策略。
2. **密钥与派生**：设备密钥派生依赖可伪造的本地输入，且存在测试用硬编码密钥。
3. **存储**：UserDefaults 存敏感配置与历史，无加密与完整性保护，可被篡改。
4. **可 Hook 性**：设备指纹、网络、sysctl、时间等均依赖可 Hook API，在越狱/注入环境下可系统性伪造。

在越狱或可注入环境中，攻击者可组合上述手段，实现：设备身份伪造、风险分压制、配置/策略注入、签名伪造等，从而绕过风控检测。
