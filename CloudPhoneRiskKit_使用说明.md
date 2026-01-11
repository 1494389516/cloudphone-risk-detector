# CloudPhoneRiskKit（iOS 14+）使用说明

这是一个“云手机/远程控制风险 + 越狱风险”的本地采集与评分插件（SwiftPM），默认输出可直接上报的 JSON（加密你后面再接）。

## 接入（SwiftPM）

- Xcode → Project → Package Dependencies → Add Local… → 选择目录：`RiskDetectorApp`（包含 `Package.swift`）
- App 工程里 `import CloudPhoneRiskKit`

## 启动采集（全局自动模式 B）

建议在 App 启动尽早调用（会 swizzle `UIApplication.sendEvent`，用于全局触摸行为采集）：

Swift：
```swift
CPRiskKit.shared.start()
```

ObjC：
```objc
[[CPRiskKit shared] start];
```

## 生成报告（JSON）

Swift：
```swift
let report = CPRiskKit.shared.evaluate()
let json = report.jsonString(prettyPrinted: true)
```

如需避免在主线程做重活（越狱扫描/Provider 汇总等），用异步版本（completion 回到主线程）：
```swift
CPRiskKit.shared.evaluateAsync { report in
  print(report.score)
}
```

ObjC：
```objc
CPRiskReport *report = [[CPRiskKit shared] evaluateWithConfig:[CPRiskConfig default]];
NSString *json = [report jsonStringWithPrettyPrinted:YES];
```

ObjC 异步版本：
```objc
[[CPRiskKit shared] evaluateAsyncWithCompletion:^(CPRiskReport * _Nonnull report) {
  NSLog(@"score=%f", report.score);
}];
```

## 本地加密保存（方案 3）

默认使用 `AES-GCM` 加密后保存到 `Application Support/CloudPhoneRiskKit/reports/`，密钥保存在 Keychain（`ThisDeviceOnly`）。

Swift：
```swift
let report = CPRiskKit.shared.evaluate()
let path = CPRiskStore.shared.save(report, error: nil)
```

ObjC：
```objc
NSError *err = nil;
NSString *path = [[CPRiskStore shared] saveReport:report error:&err];
```

如需在同机调试验证解密（取出文件后能解密）：

Swift：
```swift
let json = CPRiskStore.shared.decryptReport(atPath: path, error: nil)
```

ObjC：
```objc
NSError *err = nil;
NSString *json = [[CPRiskStore shared] decryptReportAtPath:path error:&err];
```

## 预留字段：IP 聚合度 / ASN（以后接云端用）

本地没云端数据时不用调用；未来你有服务端/离线脚本时可以把聚合结果写进 JSON 的 `server` 节点：

Swift：
```swift
report.setServerSignals(
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

也可以用全局注入（会自动写入 JSON 的 `server`，并通过内置 provider 参与评分）：
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

## 扩展机制（B2：可插拔 Provider）

你可以注册自定义 `RiskSignalProvider`，在每次 `evaluate()` 时基于 `RiskSnapshot` 产出额外 `signals[]`，并自动参与评分与 JSON 输出。

Swift：
```swift
final class ExampleProvider: RiskSignalProvider {
  let id = "example"
  func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
    if snapshot.network.isVPNActive {
      return [RiskSignal(id: "vpn_boost", category: "custom", score: 5, evidence: ["reason":"vpn"])]
    }
    return []
  }
}

CPRiskKit.register(provider: ExampleProvider())
```

## 内置 Providers（默认注册）

- `server_aggregate`：未来云端聚合信号注入（IP/ASN/聚合度）与评分
- `device_hardware`：硬件标识采集（`hw.machine`）/ Simulator 标记
- `device_age`：老机型风险启发式（基于 `hw.machine` 的 iPhone family）
- `time_pattern`：本地 24h 活跃模式（频率/夜间占比/覆盖小时数）

## 本地时间模式字段（JSON）

每次 `evaluate()` 后会把本地滚动窗口的统计写进 JSON：`local.timePattern`。

## 可调配置

- `CPRiskConfig.threshold`：总风险阈值（默认 `60`）
- 越狱相关开关在 `CPRiskConfig.jailbreak*` 字段里
- 每次 `evaluate` 会“截取并清空”当前行为窗口（触摸/传感器），避免长时间运行导致指标被历史数据稀释

## 注意事项（兼容性）

- 模拟器：越狱检测在模拟器环境不具备真实意义（系统能力/沙盒行为不同）。建议用模拟器做“接入与 JSON 结构”验证；越狱强度回归请用真机。
- `SchemeDetector`：如果你想让 `canOpenURL` 生效，需要在宿主 App 的 `Info.plist` 增加 `LSApplicationQueriesSchemes`（例如 `cydia/sileo/filza/...`），否则该项会一直为 false（不会崩溃）。
- 本插件把不可用/看不到的东西当作“弱信号/无信号”，不会因为系统限制直接判定高风险；强结论建议放在服务端做聚合判断（IP 聚合、ASN、长连接流量模式等）。
