# iOS 越狱检测框架设计文档

> 代码与示例 App 已整合在子目录：`RiskDetectorApp/`（内含 `Package.swift`、`Sources/`、`Tests/`、以及 SwiftUI 检测 App 源码 `App/`）。

> **项目目标**: 构建一个可扩展、易维护的 iOS 越狱检测框架
> **技术栈**: Swift
> **作者**: [你的名字]
> **日期**: 2024-12

---

## 目录

- [项目概述](#项目概述)
- [架构设计](#架构设计)
- [核心代码](#核心代码)
- [检测模块](#检测模块)
- [实施计划](#实施计划)
- [API 文档](#api-文档)

---

## 项目概述

### 目标

构建一个生产级 iOS 越狱检测框架，支持：

- ✅ 多维度检测（文件、dyld、环境变量、系统调用）
- ✅ 置信度评分机制
- ✅ 灵活配置
- ✅ 易于扩展

### 使用场景

| 场景 | 配置 | 检测时间 |
|-----|------|---------|
| App 启动时 | `.light` | ~100ms |
| 支付/高风险操作 | `.default` | ~500ms |
| 后台定时检测 | `.medium` | ~300ms |

---

## 架构设计

### 项目结构

```
JailbreakDetector/
├── JailbreakDetector.swift       // 主检测器
├── Models/
│   ├── DetectionResult.swift     // 检测结果模型
│   └── JailbreakConfig.swift     // 配置模型
├── Detectors/
│   ├── FileDetector.swift        // 文件检测
│   ├── DyldDetector.swift        // dyld 检测
│   ├── EnvDetector.swift         // 环境变量检测
│   ├── SysctlDetector.swift      // 系统调用检测
│   ├── SchemeDetector.swift      // URL Scheme 检测
│   └── HookDetector.swift        // Hook 检测
├── Extensions/
│   ├── String+Extensions.swift
│   └── Logger.swift              // 日志工具
└── Example/
    └── ViewController.swift      // 使用示例
```

### 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    JailbreakDetector                        │
│                        (主入口)                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ FileDetector│  │ DyldDetector│  │ EnvDetector │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │SysctlDetector│  │SchemeDetector│  │HookDetector│         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                               │
├─────────────────────────────────────────────────────────────┤
│                      JailbreakConfig                         │
│                     (配置管理)                                │
├─────────────────────────────────────────────────────────────┤
│                     DetectionResult                          │
│                    (结果聚合)                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 核心代码

### 主检测器

```swift
import Foundation

// MARK: - 主检测器
class JailbreakDetector {

    static let shared = JailbreakDetector()

    private init() {}

    /// 执行检测
    /// - Parameter config: 检测配置
    /// - Returns: 检测结果
    func detect(config: JailbreakConfig = .default) -> DetectionResult {
        var score: Double = 0
        var methods: [String] = []

        // 按优先级执行检测
        if config.enableFileDetect {
            let result = FileDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if config.enableDyldDetect {
            let result = DyldDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if config.enableEnvDetect {
            let result = EnvDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if config.enableSysctlDetect {
            let result = SysctlDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        // 去重
        methods = Array(Set(methods))

        // 判断是否越狱
        let isJailbroken = score >= config.threshold

        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: min(score, 100),
            detectedMethods: methods,
            details: generateDetails(methods: methods, score: score)
        )
    }

    /// 快速检测（轻量模式）
    func quickDetect() -> Bool {
        return detect(config: .light).isJailbroken
    }

    private func generateDetails(methods: [String], score: Double) -> String {
        return """
        检测完成
        置信度分数: \(min(score, 100))
        命中检测: \(methods.count) 项
        检测方法: \(methods.joined(separator: ", "))
        """
    }
}
```

### 检测结果模型

```swift
// MARK: - 检测结果
struct DetectionResult {
    /// 是否判定为越狱
    let isJailbroken: Bool

    /// 置信度 (0-100)
    let confidence: Double

    /// 命中的检测方法列表
    let detectedMethods: [String]

    /// 详细信息
    let details: String
}

// MARK: - 单次检测结果
struct DetectionResultItem {
    /// 该次检测的分数
    let score: Double

    /// 命中的方法列表
    let methods: [String]
}
```

### 配置模型

```swift
// MARK: - 检测器配置
struct JailbreakConfig {
    /// 启用文件检测
    var enableFileDetect: Bool = true

    /// 启用 dyld 检测
    var enableDyldDetect: Bool = true

    /// 启用环境变量检测
    var enableEnvDetect: Bool = true

    /// 启用系统调用检测
    var enableSysctlDetect: Bool = true

    /// 启用 URL Scheme 检测
    var enableSchemeDetect: Bool = true

    /// 启用 Hook 检测
    var enableHookDetect: Bool = false  // 默认关闭，耗时较长

    /// 判定阈值 (0-100)
    var threshold: Double = 50.0

    // MARK: - 预设配置

    /// 默认配置（全部检测）
    static let `default` = JailbreakConfig()

    /// 轻量配置（快速检测）
    static let light = JailbreakConfig(
        enableFileDetect: true,
        enableDyldDetect: true,
        enableEnvDetect: false,
        enableSysctlDetect: false,
        enableSchemeDetect: false,
        enableHookDetect: false,
        threshold: 60.0
    )

    /// 中等配置（平衡）
    static let medium = JailbreakConfig(
        enableFileDetect: true,
        enableDyldDetect: true,
        enableEnvDetect: true,
        enableSysctlDetect: false,
        enableSchemeDetect: false,
        enableHookDetect: false,
        threshold: 50.0
    )

    /// 完整配置（全部检测）
    static let full = JailbreakConfig(
        enableFileDetect: true,
        enableDyldDetect: true,
        enableEnvDetect: true,
        enableSysctlDetect: true,
        enableSchemeDetect: true,
        enableHookDetect: true,
        threshold: 40.0  // 更敏感
    )
}
```

---

## 检测模块

### Detector 协议

```swift
// MARK: - Detector 协议
protocol Detector {
    func detect() -> DetectionResultItem
}
```

### 1. FileDetector - 文件检测

```swift
import Foundation

struct FileDetector: Detector {

    private let suspiciousPaths: [(path: String, score: Double)] = [
        // 包管理器
        ("/Applications/Cydia.app", 30),
        ("/Applications/Sileo.app", 30),
        ("/Applications/Zebra.app", 25),
        ("/Applications/Filza.app", 20),

        // 越狱框架
        ("/Library/MobileSubstrate/MobileSubstrate.dylib", 25),
        ("/usr/lib/substitute", 25),
        ("/usr/lib/ElleKit.dylib", 25),
        ("/Library/Frameworks/CydiaSubstrate.framework", 25),

        // 命令行工具
        ("/bin/bash", 15),
        ("/usr/sbin/sshd", 15),
        ("/usr/bin/ssh", 10),
        ("/bin/sh", 5),
    ]

    func detect() -> DetectionResultItem {
        var score: Double = 0
        var methods: [String] = []

        for item in suspiciousPaths {
            if checkFileExists(item.path) {
                score += item.score
                methods.append("file:\(item.path)")
                Logger.log("检测到越狱文件: \(item.path)")
            }
        }

        return DetectionResultItem(score: score, methods: methods)
    }

    private func checkFileExists(_ path: String) -> Bool {
        var st = stat()
        return stat(path, &st) == 0
    }
}
```

### 2. DyldDetector - dyld 检测

```swift
import Foundation

struct DyldDetector: Detector {

    private let suspiciousLibraries = [
        "Frida",
        "MobileSubstrate",
        "Substitute",
        "cycript",
        "libhooker",
        "ElleKit",
        "SSLKillSwitch",
        "PreferenceLoader"
    ]

    func detect() -> DetectionResultItem {
        var score: Double = 0
        var methods: [String] = []

        let count = _dyld_image_count()

        // 检查库数量异常
        if count > 500 {
            score += 20
            methods.append("dylib_count:\(count)")
            Logger.log("动态库数量异常: \(count)")
        }

        // 检查可疑库名
        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let libName = String(cString: name)

            for lib in suspiciousLibraries {
                if libName.lowercased().contains(lib.lowercased()) {
                    score += 30
                    methods.append("dylib:\(lib)")
                    Logger.log("检测到可疑库: \(libName)")
                }
            }
        }

        return DetectionResultItem(score: score, methods: methods)
    }
}
```

### 3. EnvDetector - 环境变量检测

```swift
import Foundation

struct EnvDetector: Detector {

    private let suspiciousVars: [(name: String, score: Double)] = [
        ("DYLD_INSERT_LIBRARIES", 50),
        ("DYLD_LIBRARY_PATH", 25),
        ("DYLD_FALLBACK_LIBRARY_PATH", 20),
        ("DYLD_PRINT_LIBRARIES", 15),
        ("LD_LIBRARY_PATH", 20),
        ("LD_PRELOAD", 25),
    ]

    func detect() -> DetectionResultItem {
        var score: Double = 0
        var methods: [String] = []

        // 方法1: getenv
        for item in suspiciousVars {
            if let value = getenv(item.name) {
                let valueStr = String(cString: value)
                score += item.score
                methods.append("env:\(item.name)")
                Logger.log("检测到环境变量: \(item.name)=\(valueStr)")
            }
        }

        // 方法2: _NSGetEnviron 直接读取
        if let envPtr = _NSGetEnviron(),
           let environ = envPtr.pointee {

            var i = 0
            while let envEntry = environ[i] {
                let entry = String(cString: envEntry)

                if let range = entry.range(of: "=") {
                    let varName = String(entry[..<range.lowerBound])

                    if suspiciousVars.contains(where: { $0.name == varName }) {
                        // 已在 getenv 检测中，跳过
                    } else if varName.contains("DYLD") {
                        score += 10
                        methods.append("env_direct:\(varName)")
                    }
                }

                i += 1
            }
        }

        return DetectionResultItem(score: score, methods: methods)
    }
}
```

### 4. SysctlDetector - 系统调用检测

```swift
import Foundation

struct SysctlDetector: Detector {

    func detect() -> DetectionResultItem {
        var score: Double = 0
        var methods: [String] = []

        // fork 检测
        if canFork() {
            score += 40
            methods.append("fork_success")
            Logger.log("检测到 fork 成功")
        }

        // 进程列表检测
        if canReadProcessList() {
            score += 20
            methods.append("sysctl:process_list_access")
        }

        // 父进程检测
        if let parentName = getParentProcessName() {
            let suspiciousParents = ["cydia", "sileo", "frida", "debugserver"]
            if suspiciousParents.contains(where: { parentName.lowercased().contains($0) }) {
                score += 30
                methods.append("parent_process:\(parentName)")
            }
        }

        return DetectionResultItem(score: score, methods: methods)
    }

    private func canFork() -> Bool {
        let pid = fork()
        if pid >= 0 {
            if pid == 0 {
                _exit(0)
            }
            waitpid(pid, nil, 0)
            return true
        }
        return false
    }

    private func canReadProcessList() -> Bool {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var length = 0

        if sysctl(&mib, 4, nil, &length, nil, 0) != 0 {
            return false
        }

        return length > 0
    }

    private func getParentProcessName() -> String? {
        let ppid = getppid()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid]
        var info = kinfo_proc()
        var length = MemoryLayout<kinfo_proc>.size

        if sysctl(&mib, 4, &info, &length, nil, 0) != 0 {
            return nil
        }

        var name = [Int8](repeating: 0, count: 256)
        proc_name(ppid, &name, 256)

        return String(cString: name)
    }
}
```

### 5. SchemeDetector - URL Scheme 检测

```swift
import Foundation

struct SchemeDetector: Detector {

    private let schemes: [(scheme: String, score: Double)] = [
        ("cydia://", 20),
        ("sileo://", 20),
        ("filza://", 15),
        ("activator://", 15),
        ("undecimus://", 20),
    ]

    func detect() -> DetectionResultItem {
        var score: Double = 0
        var methods: [String] = []

        for item in schemes {
            if let url = URL(string: item.scheme) {
                if UIApplication.shared.canOpenURL(url) {
                    score += item.score
                    methods.append("scheme:\(item.scheme)")
                    Logger.log("检测到 URL Scheme: \(item.scheme)")
                }
            }
        }

        return DetectionResultItem(score: score, methods: methods)
    }
}
```

---

## 使用示例

```swift
import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        // 快速检测
        if JailbreakDetector.shared.quickDetect() {
            showAlert("检测到越狱设备")
            return
        }

        // 完整检测
        let result = JailbreakDetector.shared.detect()

        print("是否越狱: \(result.isJailbroken)")
        print("置信度: \(result.confidence)%")
        print("命中方法: \(result.detectedMethods)")

        if result.isJailbroken {
            // 处理越狱设备
            handleJailbrokenDevice(result)
        }
    }

    func handleJailbrokenDevice(_ result: DetectionResult) {
        // 根据业务需求处理
        // 1. 限制功能
        // 2. 要求额外验证
        // 3. 上报风控
    }

    func showAlert(_ message: String) {
        let alert = UIAlertController(title: "提示", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "确定", style: .default))
        present(alert, animated: true)
    }
}
```

---

## 实施计划

### 阶段一：基础框架（1-2天）

- [ ] 创建 Xcode 项目
- [ ] 搭建目录结构
- [ ] 实现 `DetectionResult` 模型
- [ ] 实现 `JailbreakConfig` 配置
- [ ] 实现 `Logger` 日志工具

### 阶段二：核心检测模块（3-5天）

优先级排序：

**P0（必须）**：
- [ ] `FileDetector` - 文件检测
- [ ] `DyldDetector` - dyld 检测

**P1（重要）**：
- [ ] `EnvDetector` - 环境变量检测
- [ ] `SysctlDetector` - 系统调用检测

**P2（可选）**：
- [ ] `SchemeDetector` - URL Scheme 检测
- [ ] `HookDetector` - Hook 检测

### 阶段三：整合与优化（1-2天）

- [ ] 实现主检测器
- [ ] 优化评分算法
- [ ] 异步检测支持
- [ ] 性能优化

### 阶段四：测试与文档（1天）

- [ ] 编写使用示例
- [ ] 单元测试
- [ ] 更新文档

---

## API 文档

### JailbreakDetector

```swift
class JailbreakDetector {
    /// 单例
    static let shared: JailbreakDetector

    /// 执行检测
    /// - Parameter config: 检测配置
    /// - Returns: 检测结果
    func detect(config: JailbreakConfig = .default) -> DetectionResult

    /// 快速检测
    /// - Returns: 是否越狱
    func quickDetect() -> Bool
}
```

### JailbreakConfig

```swift
struct JailbreakConfig {
    var enableFileDetect: Bool
    var enableDyldDetect: Bool
    var enableEnvDetect: Bool
    var enableSysctlDetect: Bool
    var enableSchemeDetect: Bool
    var enableHookDetect: Bool
    var threshold: Double

    static let `default`: JailbreakConfig
    static let light: JailbreakConfig
    static let medium: JailbreakConfig
    static let full: JailbreakConfig
}
```

### DetectionResult

```swift
struct DetectionResult {
    let isJailbroken: Bool
    let confidence: Double
    let detectedMethods: [String]
    let details: String
}
```

---

## Info.plist 配置

如需使用 URL Scheme 检测，需在 `Info.plist` 中添加：

```xml
<key>LSApplicationQueriesSchemes</key>
<array>
    <string>cydia</string>
    <string>sileo</string>
    <string>filza</string>
    <string>activator</string>
    <string>undecimus</string>
</array>
```

---

## 许可证

未指定（内部项目）。

---

## 更新日志

| 日期 | 版本 | 更新内容 |
|------|------|---------|
| 2024-12 | 1.0 | 初始版本 |
