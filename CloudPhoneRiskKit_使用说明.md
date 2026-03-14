# CloudPhoneRiskKit 5.2 使用与构建说明

iOS 端「云手机 / 远程控制 / 越狱」风险本地采集与评分 SDK，输出结构化 JSON 报告，支持场景化决策、App Attest 硬件信任根、可插拔 Provider 扩展。

---

## 1. 环境要求

| 项目 | 最低版本 |
|------|---------|
| macOS | 14.0+ |
| Xcode | 15.0+ |
| iOS 部署目标 | 14.0+ |
| Swift | 5.9+ |

---

## 2. 构建方式

### 2.1 SPM 命令行构建

```bash
cd RiskDetectorApp
swift build
```

### 2.2 XcodeGen 生成工程

```bash
cd RiskDetectorApp
brew install xcodegen   # 如已安装可跳过
xcodegen generate
open RiskDetectorApp.xcodeproj
```

### 2.3 Xcode 直接打开

用 Xcode 打开 `RiskDetectorApp/Package.swift`，Xcode 会自动识别为 SwiftPM 工程并解析依赖。

### 2.4 真机 vs 模拟器

**推荐真机调试。** 模拟器下以下检测器返回 `unavailable`：
- DRM 能力检测（FairPlay）
- 电池熵检测（无真实电池硬件）
- 部分越狱 / 挂载点检测（沙盒行为不同）

模拟器适合做接入验证和 JSON 结构检查；越狱强度回归 & 行为指纹精度测试请用真机。

---

## 3. 接入方式（SwiftPM）

**方式 A — Xcode GUI**

Xcode → Project → Package Dependencies → **Add Local…** → 选择 `RiskDetectorApp` 目录（包含 `Package.swift`）。

**方式 B — Package.swift 声明**

```swift
dependencies: [
    .package(path: "../cloudphone-risk-detector/RiskDetectorApp")
]
// target
.target(name: "YourApp", dependencies: [
    .product(name: "CloudPhoneRiskKit", package: "CloudPhoneRiskKit"),
])
```

---

## 4. 快速上手

```swift
import CloudPhoneRiskKit

// 1) 启动采集（建议在 didFinishLaunching 尽早调用）
CPRiskKit.shared.start()

// 2) 同步评估
// 支付场景：建议 start() 后至少 0.5 秒再 evaluate，以便 PhysicalSensorProbe 预热完成；缓存命中时零阻塞
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
#if DEBUG
print(report.score, report.isHighRisk, report.summary)
#endif

// 3) 异步评估（completion 回到主线程）
CPRiskKit.shared.evaluateAsync { report in
    #if DEBUG
    print(report.score)
    #endif
}

// 4) async/await（iOS 13+）
let report = await CPRiskKit.shared.evaluateAsync(config: .default, scenario: .login)

// 5) 停止采集
CPRiskKit.shared.stop()
```

---

## 5. ObjC 兼容

```objc
#import <CloudPhoneRiskKit/CloudPhoneRiskKit-Swift.h>

[[CPRiskKit shared] start];
CPRiskReport *report = [[CPRiskKit shared] evaluateWithConfig:[CPRiskConfig default]
                                                     scenario:[RiskScenario payment]];
NSLog(@"score=%f high=%d", report.score, report.isHighRisk);

[[CPRiskKit shared] evaluateAsyncWithCompletion:^(CPRiskReport *report) {
    NSLog(@"score=%f", report.score);
}];
```

---

## 6. 场景化决策

支持的 `RiskScenario`：

| 场景标识 | 说明 |
|---------|------|
| `.login` | 登录 |
| `.payment` | 支付 |
| `.register` | 注册 |
| `.accountChange` | 账号变更 |
| `.sensitiveAction` | 敏感操作 |
| `.apiAccess` | API 访问 |

```swift
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
// 不同场景有独立的阈值、权重和 combo 规则
```

---

## 7. 服务端配置签名（推荐）

配置 HMAC 签名密钥后，SDK 会验证远程配置的签名完整性，防止中间人篡改：

```swift
CPRiskKit.configureServerSigningKey("your-server-hmac-key")
CPRiskKit.shared.start()
```

---

## 8. App Attest 硬件信任根（4.9 更新）

4.9 新增 `requireAttestation` 参数（默认 `true`），不支持或失败时 **抛错而非静默降级**：

```swift
let envelope = try await CPRiskKit.shared.buildSecureReportEnvelopeWithAttestation(
    report: report,
    sessionToken: sessionToken,
    signingKey: signingKey,
    requireAttestation: true   // 强制硬件信任根，失败即 throw
)
// envelope.hasHardwareAttestation == true 时表示已附加硬件断言
```

- 需在 Xcode → Signing & Capabilities 中开启 **App Attest**。
- `requireAttestation: false` 时允许降级，调用方应检查 `envelope.hasHardwareAttestation`。

---

## 9. 服务端信号注入

将服务端聚合结果（IP / ASN / 聚合度等）回注 SDK，参与本地评分：

```swift
CPRiskKit.setExternalServerSignals(
    publicIP: "1.2.3.4",
    asn: "AS4134",
    asOrg: "CHINANET",
    isDatacenter: 1,
    ipDeviceAgg: 120,
    ipAccountAgg: 500,
    geoCountry: "CN",
    geoRegion: "GD",
    riskTags: ["dc_ip", "ip_shared"]
)
```

---

## 10. 本地加密存储

报告使用 **AES-GCM** 加密 + **HMAC** 完整性保护，密钥存于 Keychain（`ThisDeviceOnly`）。

```swift
// 保存
let path = CPRiskStore.shared.save(report, error: nil)

// 解密读取
let json = CPRiskStore.shared.decryptReport(atPath: path, error: nil)
```

---

## 11. 可插拔 Provider 扩展

实现 `RiskSignalProvider` 协议，注册后每次 `evaluate()` 自动参与评分：

```swift
final class MyProvider: RiskSignalProvider {
    let id = "my_custom"
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        // 基于 snapshot 产出自定义信号
        return []
    }
}

CPRiskKit.register(provider: MyProvider())
```

---

## 12. 配置项速查

`CPRiskConfig` 常用配置：

| 配置项 | 类型 | 默认值 | 说明 |
|-------|------|--------|------|
| `threshold` | `Double` | `60` | 高风险总分阈值 |
| `enableBehaviorDetect` | `Bool` | `true` | 行为指纹采集 |
| `enableNetworkSignals` | `Bool` | `true` | 网络信号采集 |
| `enableAntiTamper` | `Bool` | `true` | 反篡改 / Hook 检测 |
| `enableTemporalAnalysis` | `Bool` | `false` | 时序模式分析 |
| `enableRemoteConfig` | `Bool` | `false` | 远程配置拉取 |
| `defaultScenario` | `RiskScenario` | `.default` | 默认评估场景 |
| `jailbreak.*` | — | — | 越狱检测子开关（file/dyld/sysctl/env/scheme/hook） |

> Release 构建下，核心检测开关（file/dyld/sysctl/hook/behavior/network）由 SDK 强制开启，不可被远程配置或调用方关闭。

---

## 13. 盲区四：代码段哈希校验与 textSegmentHashReference 配置

### 13.1 配置说明

`RemoteConfig.textSegmentHashReference` 为 `sdkVersion -> expectedHash` 映射表，由服务端下发。客户端优先使用该参考哈希校验 `__TEXT.__text` 段完整性，无下发时回退到 Keychain 本地基线。

**配置格式示例**（JSON）：

```json
{
  "textSegmentHashReference": {
    "5.2.0": "a1b2c3d4e5f6...",
    "5.3.0": "f6e5d4c3b2a1..."
  }
}
```

- **Key**：SDK 版本号（如 `Version.current`）
- **Value**：该版本 `__TEXT.__text` 段的 SHA-256 十六进制摘要（64 字符）

### 13.2 客户端上报结构

风险报告 `Payload` 中的 `textSegmentIntegrity` 字段结构：

| 字段 | 类型 | 说明 |
|------|------|------|
| `currentHash` | String | 当前设备上 SDK 镜像的 `__TEXT.__text` SHA-256 摘要 |
| `sdkVersion` | String | SDK 版本号，供服务端查表 |
| `referenceSource` | String? | 客户端本次参考哈希来源，如 `remote_config` / `custom` / `keychain_baseline` |
| `referenceVersion` | String? | 参考哈希版本，如 RemoteConfig 版本号或业务参考表版本号 |
| `usedServerReference` | Bool | 客户端本次是否命中了服务端参考哈希路径 |
| `clientDetail` | String? | 客户端本地结论（如 `intact`/`tampered`/`baseline_established`），仅供观测 |

当哈希计算失败（如镜像未找到、加密跳过）时，`textSegmentIntegrity` 为 `null`，不上报。

### 13.3 服务端校验流程

1. 解析上报 JSON，读取 `payload.textSegmentIntegrity`
2. 若为 `null`，跳过校验（或按业务策略处理）
3. 用 `sdkVersion` 在服务端映射表中查询 `expectedHash`
4. 若该版本无映射，记录并跳过（新版本尚未入库）
5. 将 `currentHash` 与 `expectedHash` 做大小写不敏感比较
6. 不一致则判定为篡改，可叠加风险分或触发拦截

**注意**：服务端应独立维护映射表，不信任客户端本地结论；`referenceSource/referenceVersion/clientDetail` 只用于排障与审计，不应替代服务端独立查表。Keychain 被越狱篡改时，服务端参考哈希仍可信。

### 13.4 可选扩展点：自定义参考哈希解析器

若业务方已有独立的签名配置中心，不想把参考哈希放进 `RemoteConfig`，可实现 `TextSegmentReferenceResolving` 并注入到 `CPRiskKit`：

```swift
final class SignedReferenceResolver: TextSegmentReferenceResolving {
    func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference? {
        guard let entry = SignedReferenceCache.shared.lookup(version: sdkVersion) else {
            return nil
        }
        return TextSegmentReference(
            expectedHash: entry.expectedHash,
            source: "signed_reference_cache",
            version: entry.policyVersion
        )
    }
}

CPRiskKit.shared.setTextSegmentReferenceResolver(SignedReferenceResolver())
```

返回 `nil` 时，SDK 会自动回退到 `RemoteConfig.textSegmentHashReference`，因此不会破坏现有接入方式。

---

## 14. 注意事项

1. **模拟器限制**：越狱检测在模拟器无实际意义，DRM / 电池 / 部分挂载点检测返回 `unavailable`。
2. **SchemeDetector**：需在宿主 App 的 `Info.plist` 添加 `LSApplicationQueriesSchemes`（如 `cydia`、`sileo`、`filza` 等），否则 `canOpenURL` 始终返回 `false`。
3. **弱信号原则**：SDK 将不可用 / 无法获取的信号视为弱信号，不会因系统限制直接判定高风险。**强结论建议放在服务端做聚合判断**（IP 聚合、ASN、设备图谱、长连接流量模式等）。
4. **日志开关**：`CPRiskKit.setLogEnabled(true)` 仅在 `DEBUG` 构建下生效。

---

## 15. 服务端参考哈希下发协议（Text Segment Reference Hash Distribution Protocol）

本章描述盲区四（代码段哈希校验）中，服务端作为可信锚点下发 `__TEXT.__text` 参考哈希的完整协议设计，涵盖发版入库、下发、客户端消费与服务端二次校验全链路。

### 15.1 设计目标

| 目标 | 说明 |
|------|------|
| **对抗 Keychain 篡改** | 越狱后 Keychain 可被替换，本地基线不可信；服务端参考哈希作为不可篡改的锚点 |
| **信任根转移** | 信任根从本地 Keychain 转移到服务端；客户端只做本地比对与上报，最终判定权在服务端 |
| **职责分离** | 客户端：计算 `currentHash`、对比、上报；服务端：维护映射表、独立查表、做最终风险决策 |

### 15.2 发版入库流程

#### 15.2.1 从 SDK 产物提取 `__TEXT.__text` SHA-256

CI/CD 发版时，从 SDK 的 Mach-O 产物（如 `CloudPhoneRiskKit.framework/CloudPhoneRiskKit` 或 XCFramework 中的对应二进制）中提取 `__TEXT.__text` 段并计算 SHA-256。

**方式一：otool + xxd + shasum（需处理 otool 输出格式）**

```bash
# otool -t 输出 __TEXT.__text 的十六进制，格式为 "地址 字节..."
# 需先提取纯十六进制字节再计算哈希，以下为简化示例（otool 输出格式因版本而异，建议用 Python 脚本）
otool -t path/to/CloudPhoneRiskKit | tail -n +2 | awk '{$1=""; print}' | tr -d ' \n' | xxd -r -p | shasum -a 256
```

**方式二：Python 脚本（推荐，精确解析 Mach-O）**

```python
#!/usr/bin/env python3
"""从 Mach-O 中提取 __TEXT.__text 段并计算 SHA-256。"""
import hashlib
import struct
import sys

def read_mach_o_section(path: str, segname: str, sectname: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    offset = 0
    magic = struct.unpack("<I", data[offset:offset+4])[0]
    if magic not in (0xFEEDFACF, 0xFEEDFACE, 0xCFFAEDFE, 0xCEFAEDFE):
        raise ValueError("Not a valid Mach-O (thin binary only)")
    is_64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    header_size = 32 if is_64 else 28
    offset = header_size
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", data[offset:offset+8])
        if cmd == 0x19:  # LC_SEGMENT_64
            seg = data[offset:offset+cmdsize]
            segname_raw = seg[8:24].rstrip(b"\x00").decode("ascii", errors="ignore")
            if segname_raw == segname:
                nsects = struct.unpack("<I", seg[72:76])[0]
                for i in range(nsects):
                    sect_start = 80 + i * 80  # segment_command_64=80, section_64=80
                    sectname_raw = seg[sect_start:sect_start+16].rstrip(b"\x00").decode("ascii", errors="ignore")
                    if sectname_raw == sectname:
                        fileoff = struct.unpack("<I", seg[sect_start+48:sect_start+52])[0]
                        filesize = struct.unpack("<Q", seg[sect_start+40:sect_start+48])[0]
                        return data[fileoff:fileoff+filesize]
        offset += cmdsize
    raise ValueError(f"Section {segname},{sectname} not found")

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "CloudPhoneRiskKit"
    raw = read_mach_o_section(path, "__TEXT", "__text")
    h = hashlib.sha256(raw).hexdigest()
    print(h)

if __name__ == "__main__":
    main()
```

使用示例：

```bash
# 若为 XCFramework/Fat 二进制，需先提取目标架构（如 arm64）
# lipo -thin arm64 -output CloudPhoneRiskKit_arm64 CloudPhoneRiskKit
python3 extract_text_hash.py path/to/CloudPhoneRiskKit.framework/CloudPhoneRiskKit
# 输出：a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

#### 15.2.2 主键设计

| 粒度 | 主键 | 适用场景 |
|------|------|----------|
| **最小可用** | `sdkVersion`（如 `5.2.0`） | 单渠道、单构建变体 |
| **扩展** | `sdkVersion + buildFlavor + platform` | 多渠道、Debug/Release 分离 |
| **更精确** | `LC_UUID`（二进制 UUID 十六进制） | 同版本多构建需区分时 |

当前协议以 `sdkVersion` 为最小可用粒度；若未来需要区分渠道或构建变体，可扩展主键格式（如 `5.2.0:release:ios`）。

#### 15.2.3 入库目标

通用建议：任何 KV 存储或配置中心均可，例如：

- Redis / etcd
- 配置中心（Apollo、Nacos 等）
- 数据库表（`sdk_version` → `expected_hash`）
- 与 RemoteConfig 后端共用存储，在生成配置时合并 `textSegmentHashReference` 字段

### 15.3 下发协议

#### 15.3.1 承载通道

复用 `RemoteConfig` 的 `textSegmentHashReference` 字段，通过现有配置拉取接口下发。

#### 15.3.2 HTTP 响应示例

```json
{
  "version": 42,
  "timestamp": 1710000000,
  "environment": "production",
  "policy": { ... },
  "detector": { ... },
  "whitelist": { ... },
  "experiments": { ... },
  "textSegmentHashReference": {
    "5.2.0": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
    "5.3.0": "f6e5d4c3b2a1987654321098765432109876543210fedcba09876543210fedcba"
  }
}
```

响应头需包含 HMAC 签名：

```
X-Config-Signature: <HMAC-SHA256(body, serverSigningKey) 的十六进制>
```

#### 15.3.3 签名校验

`ConfigSignatureVerifier` 验签流程：

1. 客户端调用 `CPRiskKit.configureServerSigningKey("your-server-hmac-key")` 配置与服务端一致的 HMAC 密钥
2. 拉取配置时，服务端对 **响应 Body 原始字节** 计算 `HMAC-SHA256`，将十六进制结果放入 `X-Config-Signature` 头
3. 客户端用 `ConfigSignatureVerifier.verify(payload: data, signatureHex: signatureHex)` 校验
4. 验签失败则拒绝配置，不更新缓存

#### 15.3.4 缓存策略

- **Release 构建**：`ConfigCache` 只接受 `verifiedByServer == true` 且未过期的缓存
- 验签通过后调用 `cache.save(config, verifiedByServer: true)` 写入
- 未配置签名密钥时，Release 下不使用未验签缓存

#### 15.3.5 证书 Pinning

通过 `CPRiskKit.configurePinnedCertificateHashes(_ hashes: [String])` 配置服务端证书哈希，`RemoteConfigProvider` 使用 `CertificatePinningSessionDelegate.pinnedSession` 防中间人篡改。

### 15.4 客户端消费链路

#### 15.4.1 配置刷新时机

- `CPRiskKit.start()` 时若已配置 `remoteConfigURLString`，会初始化 `RemoteConfigProvider` 并拉取配置
- `evaluate()` 时若 `config.enableRemoteConfig == true`，会使用 `currentRemoteConfig()` 作为运行时配置
- 配置更新通过 `RemoteConfigProvider.fetchLatest` 周期性拉取或手动调用 `updateRemoteConfig(completion:)`

#### 15.4.2 解析优先级

`resolveTextSegmentReference(for:)` 的解析顺序：

1. **自定义 resolver**：若通过 `setTextSegmentReferenceResolver(_:)` 注入了 `TextSegmentReferenceResolving`，优先调用
2. **RemoteConfig**：`config.textSegmentHashReference?[sdkVersion]`
3. **Keychain**：以上均返回 `nil` 时，回退到 Keychain 本地基线（向后兼容）

#### 15.4.3 决策树

`TextSegmentIntegrityChecker.verify()` 的完整决策流程：

```
1. 镜像未找到 / 加密跳过 / 哈希计算失败
   → 返回特殊 result（detail: sdk_image_not_found / encrypted_skip / hash_failed），textSegmentIntegrity 为 null 时不上报

2. 服务端参考命中（resolveTextSegmentReference 返回非 nil）
   → 用 expectedHash 与 currentHash 对比（大小写不敏感）
   → 命中：usedServerReference=true, referenceSource=remote_config|custom, referenceVersion=config.version
   → 上报 TextSegmentIntegrityPayload

3. 服务端参考未命中
   → 回退 Keychain 本地基线
   → 有基线且 UUID 匹配：对比，usedServerReference=false, referenceSource=keychain_baseline
   → 有基线但 UUID 变化 / 首启建基线：按现有逻辑处理
   → 上报 TextSegmentIntegrityPayload
```

### 15.5 服务端二次校验

#### 15.5.1 独立查表

服务端收到上报后，用 `currentHash + sdkVersion` 在自有映射表中独立查表：

```
expectedHash = mappingTable[sdkVersion]
if expectedHash == nil → 版本缺失，按策略处理
else if currentHash.lower() != expectedHash.lower() → 篡改
else → 完整
```

#### 15.5.2 不信任客户端结论

`clientDetail`、`usedServerReference` 等为观测字段，**不可作为最终判定依据**。越狱环境下客户端可能被篡改，服务端必须独立查表。

#### 15.5.3 异常处置建议

| 情况 | 建议 |
|------|------|
| 哈希不匹配 | 叠加风险分、触发人工审核、高敏场景拦截 |
| 版本缺失 | 见 15.5.4 |
| 正常匹配 | 可降低相关风险权重或忽略 |

#### 15.5.4 版本缺失策略

| 策略 | 说明 |
|------|------|
| **fail-open** | 不拦截，叠加软风险分；适合新版本刚发布、映射表尚未全量 |
| **fail-close** | 视为不可信，提高风险分或拦截；适合强合规场景 |

### 15.6 操作 Runbook

#### 15.6.1 新版本发布

1. CI/CD 从 SDK 产物提取 `__TEXT.__text` SHA-256
2. 入库：`mappingTable["5.4.0"] = "<hash>"`
3. 灰度：先对部分流量下发含新版本的 `textSegmentHashReference`
4. 全量：确认无异常后全量下发

#### 15.6.2 版本回滚与多版本并存

- 保留历史版本映射，避免老版本客户端上报时查表失败
- 建议保留最近 N 个主版本的映射（如 3～5 个）

#### 15.6.3 紧急：清除某版本参考哈希

发现某版本误报（如构建差异导致哈希不同）时：

1. 从映射表中删除该版本条目，或
2. 下发不含该 `sdkVersion` key 的配置
3. 客户端将回退到 Keychain 基线，不再使用服务端参考

### 15.7 待决策项

| 项 | 选项 | 说明 |
|----|------|------|
| **主键粒度** | 仅 sdkVersion / sdkVersion+渠道+构建变体 | 多渠道或 Debug/Release 分离时需扩展 |
| **参考缺失策略** | fail-open / fail-close | 见 15.5.4 |
| **独立信号** | 是否新增 `text_segment_server_reference_missing` | 服务端有参考但客户端未命中时，可打独立信号便于分析 |
| **上报扩展** | binaryUUID / build fingerprint | 更精确的版本区分，便于服务端多主键查表 |
