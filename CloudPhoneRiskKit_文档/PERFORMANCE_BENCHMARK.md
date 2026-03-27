# CloudPhoneRiskKit 性能基准报告

> 本文档定义性能测试方法论、设备矩阵、关键指标和回归检测规则。

## 测试设备矩阵

| 设备 | 芯片 | RAM | iOS 版本 | 分类 |
|------|------|-----|---------|------|
| iPhone 16 Pro | A18 Pro | 8 GB | 18.x | 旗舰 |
| iPhone 15 | A16 | 6 GB | 17.x | 主流 |
| iPhone 13 mini | A15 | 4 GB | 17.x | 中端 |
| iPhone SE (3rd) | A15 | 4 GB | 16.x | 低端入门 |
| iPad Pro M2 | M2 | 8 GB | 17.x | 平板 |
| iPhone 11 | A13 | 4 GB | 16.x | 旧设备基准 |

> 模拟器性能数据仅供趋势参考，不作为回归基线。

---

## 关键性能指标

### 1. SDK 初始化 (`start()`)

| 指标 | 目标 (旗舰) | 目标 (低端) | 说明 |
|------|-----------|-----------|------|
| 冷启动耗时 | ≤ 50 ms | ≤ 120 ms | 从 `start()` 调用到返回 |
| Armor runtime init | ≤ 15 ms | ≤ 40 ms | `cprisk_init_protection` 耗时 |
| Anti-debug watchdog start | ≤ 5 ms | ≤ 15 ms | `cprisk_start_anti_debug_watchdog` |
| Provider registration | ≤ 5 ms | ≤ 10 ms | 所有内置 provider 注册 |
| 内存增量 | ≤ 2 MB | ≤ 3 MB | start() 前后 RSS 差值 |

### 2. 风险评估 (`evaluate()`)

| 指标 | 目标 (旗舰) | 目标 (低端) | 说明 |
|------|-----------|-----------|------|
| 同步评估耗时 (P50) | ≤ 25 ms | ≤ 60 ms | 含信号采集 + 决策 |
| 同步评估耗时 (P95) | ≤ 50 ms | ≤ 100 ms | 含远程配置查询 |
| 同步评估耗时 (P99) | ≤ 80 ms | ≤ 150 ms | 极端场景 |
| 信号采集阶段 | ≤ 10 ms | ≤ 30 ms | provider signals + capability probe |
| 决策引擎阶段 | ≤ 5 ms | ≤ 15 ms | RiskDetectionEngine.evaluate() |
| JailbreakEngine.detect() | ≤ 8 ms | ≤ 20 ms | 11 检测器全量扫描 |
| 内存峰值增量 | ≤ 1 MB | ≤ 2 MB | 评估期间瞬时峰值 |

### 3. 报告构建 (`buildSecureReportEnvelope`)

| 指标 | 目标 (旗舰) | 目标 (低端) | 说明 |
|------|-----------|-----------|------|
| Envelope 构建耗时 | ≤ 10 ms | ≤ 25 ms | HMAC 签名 + JSON 序列化 |
| Armor 签名 (v2a) | ≤ 5 ms | ≤ 15 ms | `cprisk_sign_with_derived_key` |
| Payload 大小 | ≤ 8 KB | ≤ 12 KB | 典型报告 payload |

### 4. 单项检测器性能

| 检测器 | 目标 (P50) | 目标 (P95) | 说明 |
|--------|-----------|-----------|------|
| FileDetector | ≤ 3 ms | ≤ 8 ms | 文件系统探测 |
| DyldDetector | ≤ 2 ms | ≤ 5 ms | dyld image list 扫描 |
| FridaDetector | ≤ 3 ms | ≤ 10 ms | Frida 端口/套接字检测 |
| FridaHeapDetector | ≤ 5 ms | ≤ 15 ms | 堆内存签名扫描 |
| FridaModuleDetector | ≤ 4 ms | ≤ 12 ms | Frida 模块特征扫描 |
| ObjCSwizzleDetector | ≤ 2 ms | ≤ 6 ms | ObjC IMP 一致性检查 |
| RWXMemoryScanner | ≤ 3 ms | ≤ 8 ms | RWX 内存区域扫描 |
| TextSegmentIntegrityChecker | ≤ 5 ms | ≤ 15 ms | __TEXT 段完整性哈希 |
| CodeSignatureValidator | ≤ 4 ms | ≤ 10 ms | 代码签名校验 |
| CapabilityProbeEngine | ≤ 5 ms | ≤ 12 ms | 能力探测全量 |
| KernelHookSideChannel | ≤ 3 ms | ≤ 10 ms | 内核 hook 侧信道 |

---

## 测试方法论

### 测试环境准备

1. **Release 模式编译**：所有性能测试在 Release (-O) 配置下运行
2. **设备温度稳定**：开始前静置 2 分钟，确保 thermal throttle 不影响结果
3. **排除后台干扰**：关闭其他 App、蓝牙、推送通知
4. **多轮测量**：每项指标至少运行 10 次 `measure {}` 迭代（XCTest 默认）
5. **冷/热启动区分**：首次调用与后续调用分开统计

### XCTest measure{} 使用规范

```swift
func testEvaluatePerformance() {
    let kit = CPRiskKit.shared
    kit.start()

    measure {
        _ = kit.evaluate()
    }
}
```

### 统计方法

- **P50/P95/P99** 从 XCTest 报告的 `averageTime` 和 `standardDeviation` 推算
- **内存指标** 使用 `mach_task_basic_info` 获取 RSS
- **CPU 指标** 使用 `thread_info` / Instruments Time Profiler

---

## 基准估算值（模拟器参考）

> 以下为 macOS 模拟器上的估算值，仅供 CI 趋势参考，不作为真机回归阈值。

| 操作 | 模拟器估算 (ms) | 说明 |
|------|----------------|------|
| `start()` | 30-80 | 含 Armor init（debug fallback key） |
| `evaluate()` | 15-45 | 不含真实传感器数据 |
| `JailbreakEngine.detect()` | 5-15 | 模拟器路径简化 |
| `buildSecureReportEnvelope()` | 5-15 | HMAC 签名 |

---

## 回归检测规则

### 触发条件

| 规则 | 阈值 | 动作 |
|------|------|------|
| P50 超过目标 50%+ | 如旗舰 evaluate P50 > 37.5ms | ⚠️ Warning |
| P95 超过目标 | 如旗舰 evaluate P95 > 50ms | 🔴 Block merge |
| 连续 3 次 CI run P50 上升 10%+ | 趋势检测 | ⚠️ Investigate |
| 内存增量超过目标 2x | 如 start() 增量 > 4MB | 🔴 Block merge |

### CI 集成建议

1. 在 CI 中使用固定设备或 macOS runner + 模拟器
2. 将 `measure {}` 结果写入 JSON baseline 文件
3. 每次 PR 比较当前结果与 baseline
4. 超过阈值时自动添加 PR comment

---

## 性能优化检查清单

- [ ] 避免在 `evaluate()` 主路径做 I/O（磁盘读写、网络请求）
- [ ] 信号采集阶段并发化（provider 之间无依赖）
- [ ] Jailbreak 检测器按权重排序，高分检测器优先短路
- [ ] Armor HMAC 使用 `__attribute__((always_inline))` 避免函数调用开销
- [ ] RemoteConfig 解析结果缓存，避免每次 evaluate 重复反序列化
- [ ] 大型 Set 查找使用 Bloom filter 预过滤（highRiskSignalIds）
- [ ] adaptive throttle 缓存命中时直接返回，跳过全部计算

---

## 变更日志

| 日期 | 版本 | 变更 |
|------|------|------|
| 2026-03-27 | 1.0 | 初始性能基准文档 |
