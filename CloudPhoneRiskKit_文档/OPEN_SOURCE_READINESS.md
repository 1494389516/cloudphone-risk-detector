# CloudPhoneRiskKit 开源发布与可验证性清单

> 文档定位：面向开源用户、审计者、接入方的项目入口说明。
> 目标：让外部开发者在 10 分钟内判断 SDK 的能力边界、接入成本、验证方式和剩余风险。
> 当前状态：仓库尚未提供正式 `LICENSE` 文件，因此对外发布前应先确认开源协议。README badge 暂标为 `License TBD`，避免把源码可见误写成已经完成开源授权。

---

## 1. 一句话定位

`CloudPhoneRiskKit` 是一个 iOS 端环境风险检测 SDK，核心目标是识别越狱、Hook、Frida/Gum/Gadget 注入、重签名、云手机、虚拟化、设备能力异常和运行时篡改，并把本地检测结果融合为可解释的风险报告。

它不是单点 detector，而是一套端侧风控管线：

- 检测层：越狱、反调试、动态插桩、模块白名单、签名身份、运行时完整性、设备/环境一致性。
- 决策层：场景策略、信号权重、硬信号/软信号/服务端信号融合、challenge/block 建议。
- 存储层：加密状态、HMAC 完整性、新鲜度锚、配置缓存和回滚保护。
- 加固层：`cprisk-armor` 编译后保护、白盒派生、检测链证明、静默毒化。
- 工程层：Swift Package、示例 App、Objective-C bridge、隐私声明、性能基准、单元测试。

---

## 2. 三分钟验证

在仓库根目录执行：

```bash
cd RiskDetectorApp
swift test --disable-sandbox \
  --scratch-path "${TMPDIR:-/tmp}/cloudphone-risk-detector-riskdetector-tests"
```

当前基线验证结果：

```text
Executed 1041 tests, with 4 tests skipped and 0 failures
```

说明：

- macOS SwiftPM / XCTest 环境下，Keychain、Application Support、secure store 可能出现权限受限日志；测试已覆盖这些沙盒降级路径。
- `armor runtime` 在未加固测试二进制中会走 debug fallback，部分 active-path armor 用例会跳过，这是环境性跳过，不代表核心 SDK 不能构建。
- 真机性能与命中率应以 Release 构建、真实设备和可复现实验矩阵为准，模拟器只适合趋势观察。

---

## 3. 最小接入路径

### Swift

```swift
import CloudPhoneRiskKit

CPRiskKit.shared.start()

let report = CPRiskKit.shared.evaluate(scenario: .payment)

switch report.action {
case .allow:
    break
case .challenge:
    // 触发短信、人脸、App Attest 或服务端挑战
    break
case .block:
    // 拦截高风险请求
    break
}

let envelope = try CPRiskKit.shared.buildSecureReportEnvelope(report: report)
```

### Objective-C

```objc
#import <CloudPhoneRiskKit/CloudPhoneRiskKit-Swift.h>

CPRiskKitObjCBridge *bridge = [[CPRiskKitObjCBridge alloc] init];
[bridge startWithConfig:nil];
[bridge evaluateAsyncWithScenario:CPRiskScenarioObjCPayment
                       completion:^(CPEvaluationResult *result) {
    NSLog(@"score=%ld level=%@", (long)result.score, result.levelName);
}];
```

完整接入方式见：

- `CloudPhoneRiskKit_文档/INTEGRATION_GUIDE.md`
- `CloudPhoneRiskKit_文档/XCFRAMEWORK_BUILD.md`
- `CloudPhoneRiskKit_文档/INTEGRATION_COST.md`

---

## 4. 能力模式

| 模式 | 推荐场景 | 默认能力 | 注意事项 |
|------|----------|----------|----------|
| `App Store Safe` | 常规 App Store / TestFlight 分发 | 风险信号采集、越狱/环境检测、低侵入 anti-tamper、隐私 manifest 对齐 | 宿主 App 仍需承接 `DeviceID`、`UserDefaults`、`SystemBootTime` 声明 |
| `Enhanced` | 登录、支付、补贴、设备绑定等高风险链路 | 更完整的 anti-tamper、服务端信号、策略安全地板、配置签名验证 | 应配套服务端策略，不建议只靠本地结论做永久封禁 |
| `Research / Enterprise` | 企业包、研究包、内部分发、红队环境 | 更强反调试、动态插桩、watchdog、运行时完整性和实验性探针 | 需要明确审核、合规和用户告知边界 |
| `Armored Release` | 高价值生产包、攻防对抗强业务 | `cprisk-armor` 13 pass、白盒密钥链、签名材料毒化、检测链证明 | 应建立 CI 构建产物签名、回滚和密钥轮换流程 |

推荐默认路径：

1. App Store 业务先接入 `App Store Safe`。
2. 对支付、提现、补贴、注册等链路打开 `Enhanced`。
3. 企业包或研究包再评估 `Research / Enterprise`。
4. 对抗强度足够高时，再把 `Armored Release` 纳入发布流水线。

---

## 5. 检测能力矩阵

| 检测域 | 代表能力 | 可验证方式 |
|--------|----------|------------|
| 越狱与 rootless | 文件路径、URL Scheme、dyld、挂载点、沙盒写入、多路径一致性 | 单元测试 + 越狱/rootless 真机样本 |
| Frida / Gum / Gadget | 端口、Socket、模块、堆签名、线程、协议指纹、运行时共识 | 本地 Frida 注入脚本 + 进程内模块样本 |
| 反调试 | `ptrace`、`sysctl`、`csops`、TTY、异常端口、硬件/软件断点、watchdog | LLDB attach、断点扫描、异常分发实验 |
| 代码与运行时完整性 | `__TEXT` 哈希、PLT/GOT、ObjC IMP、inline hook、签名身份、SDK 二进制校验 | 重签名包、inline patch、hook 桩样本 |
| 云手机/虚拟化 | GPU、Board ID、基带、显示、网络接口、传感器、时区/区域一致性 | 云手机供应商样本 + 真实设备对照组 |
| 行为与传感器 | 触摸熵、运动能量、传感器回放、行为耦合 | 自动化脚本、真实用户采样、回放样本 |
| 服务端融合 | IP/ASN、机房属性、设备聚合、图特征、远程策略 | mock 服务 + 灰度线上数据 |
| 存储和配置安全 | AES/HMAC、freshness anchor、配置签名、回滚保护、失败 fail-closed | 沙盒写失败、旧版本配置、篡改缓存样本 |

这张表不是“绝对安全承诺”，而是告诉使用者：每个检测域应该怎么被复现、怎么被回归、怎么被灰度验证。

---

## 6. 推荐公开基准

要让项目在开源环境里有说服力，建议后续把测试结果整理成公开矩阵，而不是只写能力名称。

| 样本组 | 建议数量 | 指标 |
|--------|----------|------|
| 普通真机 | 20+ | 误报率、P50/P95 耗时、电量影响 |
| App Store 模拟器 | 5+ | 兼容性、环境性跳过、CI 趋势 |
| 越狱真机 | 5+ | jailbreak TPR、rootless 覆盖率 |
| Frida/LLDB 环境 | 10+ | attach / spawn / gadget / hook 命中率 |
| 云手机/远控环境 | 5+ | 云手机 TPR、误伤真实低端机情况 |
| 重签/注入包 | 10+ | 签名链、dylib 注入、module whitelist 命中率 |
| 低端设备 | 5+ | 性能 P95、内存增量、超时比例 |

公开报告建议包含：

- SDK 版本、commit、构建方式、Xcode/iOS 版本。
- 设备型号和样本类别，但不要公开真实用户标识。
- 每个场景的命中信号、风险等级、建议 action。
- 误报样本的 root cause 和修复版本。
- 性能数据和测试脚本入口。

---

## 7. 发布前清单

### 必做

- [ ] 添加正式 `LICENSE` 文件，并在 README badge 中替换 `License TBD`。
- [ ] 确认仓库中没有真实密钥、token、证书、客户域名或生产策略。
- [ ] 检查 `CloudPhoneRiskKit_文档/INTEGRATION_GUIDE.md` 中示例 GitHub URL、版本号、Release 地址是否为真实发布地址。
- [ ] 提供最小 Demo App 运行截图或录屏，展示 start/evaluate/report 三步。
- [ ] 在 README 中保留“检测结果是风险信号，不是绝对防护”的边界声明。
- [ ] 提供 CI badge 或最少提供最近一次测试摘要。
- [ ] 明确 App Store Safe / Enhanced / Research / Armored Release 四种模式的默认开关。

### 推荐

- [ ] 发布 `examples/` 或精简 sample target，避免外部用户必须读完整 App 才能接入。
- [ ] 提供 `SECURITY.md`，说明漏洞报告方式、响应时间和安全联系人。
- [ ] 提供 `CONTRIBUTING.md`，说明测试命令、代码风格、如何新增 detector。
- [ ] 提供 `CHANGELOG.md` 的最新版本区块，和 README 当前版本一致。
- [ ] 输出一份公开 benchmark JSON 或 Markdown 报告。
- [ ] 给高风险 API 标注 App Store / Enterprise / Research 可用范围。

### 不建议开源前保留

- 明文生产密钥、真实客户策略、生产 pin hash。
- 未说明用途的强反调试默认开关。
- 只在本机路径可用的构建脚本。
- 会让外部用户误以为“百分百不可绕过”的营销话术。

---

## 8. 安全边界与剩余风险

端侧 SDK 面对的是潜在敌对环境。攻击者可能拥有越狱权限、调试器、Frida、内核 hook、重签名能力，甚至能控制云手机平台。

因此，本 SDK 的正确定位是：

- 提高绕过成本。
- 增加攻击者不确定性。
- 输出可解释风险信号。
- 为服务端策略提供上下文。
- 对批量化攻击形成检测和拦截压力。

本 SDK 不承诺：

- 在攻击者完全控制本地设备时永远不可绕过。
- 单靠本地检测完成最终风控裁决。
- 对所有云手机供应商保持永久命中。
- 对未知 iOS 版本、未知芯片能力给出未经验证的强保证。

高价值业务建议组合使用：

1. 端侧风险评估。
2. 服务端设备/账号/IP/行为画像。
3. 挑战式验证。
4. 灰度策略和人工复核。
5. 持续样本回归。

---

## 9. 维护者建议

要把这个项目真正打成开源标杆，优先级建议是：

1. 先补 `LICENSE`、`SECURITY.md`、`CONTRIBUTING.md`。
2. 把 README 的“能力很强”变成“外部可复现”。
3. 把测试和 benchmark 接到 CI。
4. 每个 detector 新增时同步写：威胁、信号、误报条件、测试样本。
5. 定期发布公开红队报告，记录已修复问题和剩余风险。

一句话：检测点决定上限，文档、基准和可复现性决定开源信任度。
