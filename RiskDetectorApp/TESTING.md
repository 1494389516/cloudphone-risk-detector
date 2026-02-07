# CloudPhoneRiskKit 测试文档

## 概述

本文档描述 CloudPhoneRiskKit SDK 2.0 的测试策略、测试用例和执行方法。

## 测试架构

```
Tests/CloudPhoneRiskKitTests/
├── ProviderTests.swift           # 信号提供者测试
├── RiskScoringTests.swift        # 风险评分测试
├── DeviceAgeProviderTests.swift  # 设备年龄提供者测试
├── NetworkSignalsJSONTests.swift # 网络信号 JSON 测试
├── RiskHistoryStoreTests.swift   # 历史存储测试
├── BehaviorCouplingTests.swift   # 行为耦合测试
├── FileDetectorTests.swift       # 文件检测器测试（新增）
├── HookDetectorTests.swift       # Hook 检测器测试（新增）
├── DecisionEngineTests.swift     # 决策引擎测试（新增）
├── TemporalAnalysisTests.swift   # 时序分析测试（新增）
└── TestSimulators.swift          # 测试模拟器工具（新增）
```

## 测试分类

### 1. 单元测试

#### 检测器测试

| 测试文件 | 测试内容 | 覆盖场景 |
|---------|---------|---------|
| `FileDetectorTests.swift` | 文件系统检测 | 越狱应用、Hook 框架、Rootless 路径、系统配置 |
| `HookDetectorTests.swift` | Hook 检测 | ObjC 类、符号地址、子检测器、异常检测 |

#### 评分引擎测试

| 测试文件 | 测试内容 | 覆盖场景 |
|---------|---------|---------|
| `RiskScoringTests.swift` | 风险评分 | 正常设备、越狱设备、网络信号 |
| `DecisionEngineTests.swift` | 决策引擎 | 阈值判定、组合规则、配置影响、信号去重 |

#### 时序分析测试

| 测试文件 | 测试内容 | 覆盖场景 |
|---------|---------|---------|
| `TemporalAnalysisTests.swift` | 时序分析 | 事件存储、时间窗口、小时分布、异常检测 |

### 2. 集成测试

| 测试场景 | 描述 | 验证点 |
|---------|------|-------|
| 端到端检测 | 完整的检测流程 | 各模块协同工作 |
| 远程配置更新 | 配置下发和应用 | 配置正确应用 |
| 存储与加密 | 数据持久化 | 数据安全存储 |

### 3. 性能测试

| 测试项 | 目标 | 方法 |
|-------|------|------|
| 检测耗时 | < 200ms | PerformanceTest.measure |
| 内存占用 | < 5MB | PerformanceTest.measureMemory |
| 并发处理 | 无数据竞争 | 多线程测试 |

## 测试工具

### TestSimulators

提供各种测试场景的模拟环境：

```swift
// 越狱环境模拟
let jbResult = TestSimulators.JailbreakSimulator.simulate(type: .checkra1n)

// 网络信号模拟
let network = TestSimulators.NetworkSimulator.simulate(scenario: .vpnOnly)

// 行为数据模拟
let behavior = TestSimulators.BehaviorSimulator.simulate(scenario: .bot)

// 性能测试
let result = TestSimulators.PerformanceTest.measure("检测耗时") {
    // 执行检测
}
```

## 运行测试

### 命令行运行

```bash
# 基础运行
./run_tests.sh

# 详细输出
./run_tests.sh -v

# 生成覆盖率报告
./run_tests.sh -c

# 使用 Xcode 构建
./run_tests.sh -x
```

### Xcode 运行

1. 打开项目
2. 选择测试目标
3. 按 `Cmd + U` 运行所有测试
4. 按 `Cmd + Shift + U` 运行特定测试

## 测试覆盖率目标

| 模块 | 目标覆盖率 | 当前状态 |
|------|----------|---------|
| 检测器 | 85% | 🟢 |
| 评分引擎 | 90% | 🟢 |
| 时序分析 | 80% | 🟡 |
| 网络检测 | 75% | 🟡 |
| 行为分析 | 70% | 🟡 |

## 测试场景矩阵

### 设备状态场景

| 场景 | 越狱 | VPN | 代理 | 行为异常 | 预期评分 |
|-----|------|-----|------|---------|---------|
| 正常设备 | ✗ | ✗ | ✗ | ✗ | 0-29 |
| VPN 用户 | ✗ | ✓ | ✗ | ✗ | 10-38 |
| 越狱设备 | ✓ | - | - | - | ≥ 60 |
| 机器人 | ✗ | ✗ | ✗ | ✓ | 30-59 |
| 云手机 | ✗ | ✗ | ✗ | ✓ | 40-69 |

### 越狱类型场景

| 越狱类型 | 检测方法 | 置信度 |
|---------|---------|-------|
| checkra1n | 文件 + Dyld + Hook | 85% |
| unc0ver | 文件 + Dyld + APT | 90% |
| palera1n (rootless) | /var/jb 路径 | 75% |
| Dopamine | /var/jb + ElleKit | 80% |
| 部分Hook | 仅 Frida | 35% |

## 持续集成

测试在 CI/CD 流水线中的执行：

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: ./run_tests.sh -c
```

## 最佳实践

1. **测试隔离**: 每个测试独立运行，不依赖其他测试
2. **Mock 数据**: 使用模拟器生成可控的测试数据
3. **边界测试**: 测试边界值和异常情况
4. **性能验证**: 关键路径包含性能测试
5. **定期更新**: 新功能必须包含对应测试

## 问题排查

### 常见问题

**Q: 测试在模拟器上失败**
A: 某些检测在模拟器上不可用，使用环境变量模拟

**Q: 时间相关测试不稳定**
A: 使用固定的测试时间戳，避免依赖真实时间

**Q: 文件系统检测测试失败**
A: 检查测试环境权限，使用 Mock 文件系统

## 贡献指南

添加新测试时：

1. 在对应的测试文件中添加测试方法
2. 使用 `test` 前缀命名
3. 添加清晰的注释说明测试目的
4. 更新本文档的测试场景矩阵
5. 确保测试覆盖率不降低

---

*最后更新: 2024-02-06*
*版本: 2.0*
