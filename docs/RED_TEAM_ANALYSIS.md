# CloudPhone Risk Detector — 红队分析报告

> 对 Providers、Jailbreak、Behavior、CloudPhone 四大模块的检测机制进行逆向与绕过策略分析。

---

## 一、Providers 模块

### 1.1 DRMCapabilityProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | `AVContentKeySession(keySystem: .fairPlayStreaming)` (AVFoundation) |
| **SVC 直调** | 否，仅用 UIKit/AVFoundation 高层 API |
| **硬编码阈值** | `vphoneModelPatterns`: `["iphone99","vresearch","paravirtual"]`；`newVPhonePatterns` 可远程下发 |
| **时序窗口** | 无，单次 probe 即判定 |
| **缓存/篡改** | 无缓存；`probe.probeDRMLevel()` 每次调用 |
| **传感器回放** | 不涉及传感器 |

**绕过策略：**
1. **Hook AVContentKeySession**：拦截 `AVContentKeySession.init`，返回伪造的硬件 Secure 能力。
2. **伪造 hw.machine**：`hardware_machine` 来自 `snapshot.device.hardwareMachine`（sysctl），若 hook sysctl 返回 `iPhone14,2` 等真实机型，可避免 vphone 模式匹配。
3. **双路径绕过**：同时 hook `AVContentKeySession` 与 sysctl，保证 DRM=hardwareSecure 且 machine 不含 vphone 关键词。

---

### 1.2 BatteryEntropyProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | iOS: `UIDevice.current.batteryLevel`；macOS: `IOPSCopyPowerSourcesInfo`, `IOPSGetPowerSourceDescription`；`Thread.sleep` |
| **SVC 直调** | 否，全部 libc/UIKit/IOKit |
| **硬编码阈值** | `samples: 5`, `interval: 0.1`；variance: `<0.001→0.9`, `<0.01→0.7`, `<0.1→0.5`；charge_counter/energy_counter: `-1` 或 `0` 判云手机 |
| **时序窗口** | 采样约 0.5s (5×0.1s) |
| **缓存/篡改** | 无缓存，每次 `signals()` 重新采集 |
| **传感器回放** | 电压序列可重放：若云手机能注入 `UIDevice.batteryLevel` 或 IOKit 返回值，可伪造有波动的序列 |

**绕过策略：**
1. **Hook UIDevice.batteryLevel**：返回带微小波动的值（如 0.85, 0.851, 0.849），使 variance 落在 0.01–0.1 区间，confidence 降到 0.5。
2. **Hook IOKit**：`IOPSCopyPowerSourcesInfo` / `IOPSGetPowerSourceDescription` 返回非 -1/0 的 ChargeCounter/EnergyCounter。
3. **阈值学习**：variance 0.001–0.1 对应 confidence 0.2–0.9，可针对性注入使 variance≈0.005，confidence≈0.7，降低权重影响。
4. **采样时序**：5 样本 × 0.1s 固定，可在检测前短暂等待，避免在明显异常时段被采样。

---

### 1.3 MountPointProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | `getmntinfo(&mntbuf, MNT_NOWAIT)` (Darwin libc) |
| **SVC 直调** | 否，标准 libc |
| **硬编码阈值** | `virtualFSBlacklist`: virtfs, 9p, virtiofs, fuse, overlay, aufs, vboxsf, vmhgfs；mountCount: `<2` 或 `>30`；必须有 apfs 和 `/` |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook getmntinfo**：返回伪造的 `statfs` 数组，包含 apfs、`/`，且 mountCount 在 2–30，无虚拟 FS 类型。
2. **内核级篡改**：若可修改 VFS 层，使 `getmntinfo` 看到“正常”挂载布局（需 root）。
3. **黑名单规避**：云手机若使用未在黑名单中的虚拟 FS 名称（如自定义 `myvfs`），可绕过；但需改内核/驱动。

---

### 1.4 DeviceHardwareProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | 仅读取 `snapshot.device`（来自 `DeviceFingerprint.current()`） |
| **SVC 直调** | 间接：`DeviceFingerprint` 使用 `Sysctl.string("hw.machine")` |
| **硬编码阈值** | 无，仅透传 machine 等字段 |
| **时序窗口** | 无 |
| **缓存/篡改** | `DeviceFingerprint.current()` 每次评估时调用，无长期缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook sysctlbyname**：对 `hw.machine` 返回真实机型字符串（如 `iPhone14,2`）。
2. **注意**：`DeviceFingerprint` 使用 `Sysctl.string`（标准 libc），未用 `SVCDirectCall.secureSysctlbyname`，易被 Frida/fishhook 拦截。

---

### 1.5 VPhoneHardwareProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | `MTLCreateSystemDefaultDevice()?.name` (Metal)；`IOServiceGetMatchingService`, `IORegistryEntryCreateCFProperty` (IOKit)；`uname(&info)`；`Sysctl.string("hw.machine")` |
| **SVC 直调** | 否，全部高层 API |
| **硬编码阈值** | `knownVirtualGPUKeywords`: apple paravirtual, llvmpipe, llvm；`vphoneModelPatterns`: iphone99, vresearch, paravirtual；`realChipLike`: apple a/m/gpu |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook Metal**：`MTLCreateSystemDefaultDevice` 返回的 device.name 改为 `Apple A15 GPU` 等真实芯片名。
2. **Hook IOKit**：`IORegistryEntryCreateCFProperty(service, "model")` 返回与 sysctl 一致的机型字符串。
3. **Hook uname**：`utsname.version` 不含 paravirtual 等关键词。
4. **一致性攻击**：sysctl、IOKit、uname 必须一致，否则触发 `hardware_inconsistency`；需统一伪造三处。

---

### 1.6 TimePatternProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | `RiskHistoryStore.shared.pattern()`（本地存储聚合） |
| **SVC 直调** | 否 |
| **硬编码阈值** | events24h: `>=500→15`, `>=200→8`；uniqueHours24h `>=18` 且 events `>=80`→12；nightRatio `>0.4` 且 events `>=80`→10；avgInterval `<8` 且 events `>=80`→8 |
| **时序窗口** | 24h 滑动窗口 |
| **缓存/篡改** | `RiskHistoryStore` 持久化，可被篡改 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **篡改 RiskHistoryStore**：若可写本地存储，将 events24h 压到 <200，uniqueHours <18，nightRatio ≤0.4，avgInterval ≥8。
2. **Hook RiskHistoryStore.pattern()**：直接返回“正常”的 TimePattern。
3. **行为模拟**：控制 24h 内请求分布，避免高频率、全时段、夜间集中。

---

### 1.7 LayeredConsistencyProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | `dlsym(RTLD_DEFAULT, symbol)`；`sysctlbyname("hw.machine", ...)`；`mach_absolute_time()`；`vm_region_64`；读取 `snapshot.behavior` |
| **SVC 直调** | 否，但 `mach_absolute_time` 为 Mach 调用，可视为准内核 |
| **硬编码阈值** | Prologue: 0x14/0x17/0xD6/0x00 等字节；timing: medianUs `>50`；sensor: energy `<1e-7`, stillness `>0.999`；touch: forceVar `<1e-10`, radiusVar `<0.01` |
| **时序窗口** | sysctl 采样 24 次；行为依赖 snapshot 内 motion/touch 窗口 |
| **缓存/篡改** | 无缓存；行为数据来自 TouchCapture/MotionSampler 的 snapshot |
| **传感器回放** | motion/touch 可重放：若能在 snapshot 前注入“正常”的 motion/touch 数据 |

**绕过策略：**
1. **Prologue 检测**：LayeredConsistencyProvider 用 `dlsym` 取 sysctlbyname 等符号，检查前几条指令。可改用 **inline hook** 或 **SVC 直调**，使 dlsym 拿到的是未 hook 的实现；或 hook `dlsym` 返回指向“干净”实现的指针。
2. **时序检测**：`measureSysctlMedianMicroseconds` 用 `mach_absolute_time` 测 sysctl 延迟。若 hook 增加延迟，medianUs 会 >50。策略：a) 使 hook 极轻量；b) 在 sysctl 内部做分支，对 `hw.machine` 等检测用 key 快速返回；c) 用 SVC 直调替代 libc sysctl，避免走 hook 路径。
3. **Sensor/Touch entropy**：需 `motion.sampleCount>0`、`touch.sampleCount>=10`。可注入带波动的 motion（energy>1e-7）和 touch（forceVar>1e-10, radiusVar>0.01）。
4. **关键符号**：`sysctlbyname`、`sysctl`、`getenv`、`dlopen`、`ptrace` 被检查；hook 时需保证 prologue 不是 B/BL/BR/BLR 或 LDR+BR 形态。

---

### 1.8 DeviceAgeProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | 仅读 `snapshot.device.hardwareMachine` |
| **SVC 直调** | 间接通过 Sysctl |
| **硬编码阈值** | family `<10`→18, `10..11`→12, `12..13`→6；`parseIPhoneFamily` 解析 `iPhone` 前缀数字 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook sysctl**：`hw.machine` 返回 `iPhone14,2` 等新机型，family≥14，score=0。
2. **解析规则**：仅识别 `iPhone` 前缀，可返回 `iPhone15,1` 等避免高分。

---

### 1.9 ExternalServerAggregateProvider

| 维度 | 分析 |
|------|------|
| **系统 API** | `set()` / `setGraphFeatures()` 由外部注入，无直接系统调用 |
| **SVC 直调** | 否 |
| **硬编码阈值** | ipDeviceAgg: `>=200→25`, `>=50→15`, `>=20→8`；ipAccountAgg: `>=500→25`, `>=100→15`, `>=30→8`；communityRiskDensity: `>80→20`, `>65→12`, `>50→5`；hwProfileDegree: `>=100→20`, `>=50→15`, `>=10→8` |
| **时序窗口** | 服务端聚合窗口，客户端无控制 |
| **缓存/篡改** | `current`、`graphFeatures` 在内存中，`NSLock` 保护；可被内存篡改 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **内存篡改**：若可写进程内存，修改 `current` / `graphFeatures` 为低风险值。
2. **服务端绕过**：需在服务端降低 IP/设备/账号聚合度、社区风险密度等，客户端无法直接控制。

---

## 二、Jailbreak 模块

### 2.1 FileDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `FileManager.default.fileExists`；`lstat`；`access`；`opendir`/`readdir`/`closedir`；`stat`；`readlink`；`String(contentsOfFile:)` |
| **SVC 直调** | 否，全部 libc/Foundation |
| **硬编码阈值** | 60+ 条路径及分数；fileExists 与 low-level 不一致时 +8；listApplications +15；canWriteOutsideSandbox +35；preboot jb +20 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook FileManager.fileExists**：对越狱路径统一返回 false（常见 bypass）。
2. **Hook lstat/stat/access**：对相同路径返回 -1/ENOENT，与 FileManager 一致，避免 mismatch 检测。
3. **注意 fileExistsMismatch**：若 FileManager 说 false 而 lstat/access 说 true，会 +8。需同时 hook 高层与低层，保持一致。
4. **listApplicationsShowsJailbreakApps**：用 `opendir("/Applications")` + `readdir`，需 hook `readdir` 过滤 sileo/cydia 等。
5. **canWriteOutsideSandbox**：尝试写 `/private/jb_test_*`，成功则 +35。需 hook `write`/`unlink` 或让沙盒阻止写入。
6. **SystemConfigDetector**：检查 /etc/hosts、fstab、apt、symlink；需 hook `stat`、`readlink`、`String(contentsOfFile:)` 或底层 open/read。

---

### 2.2 SysctlDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `sysctl(&mib, 4, ...)` 其中 `KERN_PROC_ALL`、`KERN_PROC_PID`；`getppid()`；`getpid()` |
| **SVC 直调** | 否，标准 sysctl(2) |
| **硬编码阈值** | process_list_access +20；process_count>400 +10；suspicious_processes +22；suspicious_parent +20；debugger P_TRACED +10；suspiciousProcessNeedles/suspiciousParentNeedles 列表 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook sysctl**：对 `CTL_KERN, KERN_PROC, KERN_PROC_ALL` 返回空或过滤后的进程列表（不含 frida/cydia 等）。
2. **Hook sysctl (KERN_PROC_PID)**：对当前进程，清除 `p_flag` 中的 `P_TRACED`，避免 debugger 检测。
3. **进程名过滤**：`suspiciousProcessNeedles` 含 frida、cydia、sshd 等；可重命名 Frida 进程或从 sysctl 返回中剔除。
4. **父进程**：`getppid()` + `readProcessInfo`，若父进程为 lldb/gdb 等会 +20；可 hook 使父进程显示为 SpringBoard 等。

---

### 2.3 HookDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `NSClassFromString`；`dlsym`；`dladdr`；`objc_copyClassList`；`class_getInstanceMethod`；`method_getImplementation`；`vm_region_64` |
| **SVC 直调** | 否 |
| **硬编码阈值** | 多个 ObjC 类名、符号名、image token；PointerValidationDetector、HookFrameworkSymbolDetector、PrologueBranchDetector、IndirectSymbolPointerDetector、ObjCIMPDetector、ObjCMetadataDetector 的分数 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **ObjC 类**：`NSClassFromString` 检测 Cydia、Frida 等类。可 a) 不加载这些类；b) hook `NSClassFromString` 对敏感类返回 nil。
2. **symbolImageChecks**：用 `dlsym`+`dladdr` 查 open/stat/sysctl 等符号所在 image。若来自非系统库会加分。策略：确保 hook 库在 `isTrustedSystemImagePath` 的白名单内，或 hook `dladdr` 返回系统路径。
3. **PrologueBranchDetector**：检查函数前几条指令，BR/BLR 等判为 hook。需用 **inline hook** 保持原 prologue，或 **SVC 直调** 完全绕过 PLT。
4. **IndirectSymbolPointerDetector**：扫描 Mach-O 间接符号表，若指针指向非系统 image 则判 fishhook。需保证 rebind 后的目标仍在系统库，或不对这些符号做 fishhook。
5. **ObjCIMPDetector**：检查 NSFileManager.fileExists、UIApplication.canOpenURL 等 IMP 所在 image。Swizzle 时替换的 IMP 需指向系统库内的代码，或 hook `dladdr` 伪造路径。
6. **HookFrameworkSymbolDetector**：检测 MSHookFunction、rebind_symbols、frida_agent_main 等导出符号。可隐藏这些符号或 hook `dlsym` 返回 NULL。

---

### 2.4 EnvDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `getenv`；`_NSGetEnviron()` 读 environ 表 |
| **SVC 直调** | 否 |
| **硬编码阈值** | DYLD_INSERT_LIBRARIES +50；getenv 与 environ 不一致时 +12 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook getenv**：对 DYLD_INSERT_LIBRARIES 等返回 NULL。
2. **environ 一致性**：`readEnvironMap` 直接读 `_NSGetEnviron()`，若 getenv 返回 nil 而 environ 有值，会 +12。需同时清空 environ 中对应项，或 hook `_NSGetEnviron` 返回修改后的表。
3. **注入方式**：若用 Frida spawn 注入，可避免 DYLD_*；attach 模式则需清环境变量或 hook。

---

### 2.5 DyldDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `_dyld_image_count()`；`_dyld_get_image_name()` |
| **SVC 直调** | 否，dyld 私有 API |
| **硬编码阈值** | count>500 +15；suspiciousLibraries 含 frida、gadget、substrate 等；每个命中 +25，≥3 个再 +10 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook _dyld_get_image_name**：对包含 frida/gadget 等路径返回伪造名（如 `/usr/lib/system/libsystem_c.dylib`）。
2. **减少 image 数量**：若可能，避免加载过多 dylib，使 count≤500。
3. **重命名 dylib**：将 Frida 库改名为不包含 suspiciousLibraries 的名称（如 `libhelper.dylib`），需改二进制。

---

### 2.6 SchemeDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `UIApplication.shared.canOpenURL(_:)` |
| **SVC 直调** | 否 |
| **硬编码阈值** | cydia:// +20, sileo:// +20, zbra:// +10, filza:// +15, undecimus:// +20 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **Hook canOpenURL**：对 cydia://、sileo:// 等返回 false。
2. **注意**：与 ObjCIMPDetector 重叠，若 canOpenURL 的 IMP 被 swizzle 到非系统库，会触发 IMP 检测；需保证 IMP 的 dladdr 路径为系统库。

---

### 2.7 PrologueBranchDetector

| 维度 | 分析 |
|------|------|
| **系统 API** | `dlsym`；`vm_region_64`；直接读内存 `p.loadUnaligned(as: UInt32.self)` |
| **SVC 直调** | 否 |
| **硬编码阈值** | 检测 B/BL (0x000101/0x100101)、BR/BLR (0xD61F0000/0xD63F0000)、LDR literal+BR；24 个符号 |
| **时序窗口** | 无 |
| **缓存/篡改** | 无缓存 |
| **传感器回放** | 不适用 |

**绕过策略：**
1. **不修改 prologue**：用 **inline hook** 在函数内部跳转，保持前几条指令为原始指令。
2. **SVC 直调**：对 open/stat/sysctl 等，在检测逻辑中直接发 SVC，不经过 PLT，避免被 prologue 检测。
3. **Hook dlsym**：对检测的符号返回“干净”实现的地址（如从 libsystem_c 取），但需保证该实现未被 hook。
4. **vm_region_64**：用于判断地址可读；若页不可读会走 fallbackScore，可考虑使检测代码访问的地址不可读以干扰，但可能引发崩溃。

---

### 2.8 PointerValidationDetector / IndirectSymbolPointerDetector / HookFrameworkSymbolDetector / ObjCIMPDetector

（见 HookDetector 部分，逻辑一致）

---

## 三、Behavior 模块

### 3.1 TouchCapture

| 维度 | 分析 |
|------|------|
| **系统 API** | `UIApplication.sendEvent(_:)`（通过 method swizzle）；`UITouch.location`、`force`、`majorRadius`、`phase`、`timestamp` |
| **SVC 直调** | 否 |
| **硬编码阈值** | 无直接阈值，输出 coordinateSpread、intervalCV、linearity、forceVariance、majorRadiusVariance |
| **时序窗口** | 累积至 `snapshotAndReset()` 调用，上限 5000 points、2000 taps、2000 swipes |
| **缓存/篡改** | 数据在内存，`snapshotAndReset()` 后清空；可被内存篡改 |
| **传感器回放** | 可重放：若 hook `sendEvent` 或 swizzle 后的 `cprk_sendEvent`，可注入伪造 touch 事件 |

**绕过策略：**
1. **Hook sendEvent / cprk_sendEvent**：在调用原实现前注入“正常”的 touch 序列，使 coordinateSpread、intervalCV、forceVariance、radiusVariance 落在非云手机区间。
2. **伪造 UITouch**：创建 UITouch 对象，设置合理的 force、majorRadius、location 变化，模拟真人滑动。
3. **Swizzle 顺序**：TouchCapture 通过 `UIApplicationSendEventSwizzler.swizzleOnce` 交换 `sendEvent`；若在更早阶段 swizzle，可先于 CPRK 处理事件并篡改。
4. **内存篡改**：在 `snapshotDetailAndReset()` 前修改 `touchPoints`、`forces`、`majorRadii` 等，使方差、线性度等满足阈值。

---

### 3.2 MotionSampler

| 维度 | 分析 |
|------|------|
| **系统 API** | `CMMotionManager.startDeviceMotionUpdates`；`CMDeviceMotion.userAcceleration`；`magnitude` |
| **SVC 直调** | 否，CoreMotion 高层 API |
| **硬编码阈值** | `magnitude < 0.02` 计为 still；`deviceMotionUpdateInterval = 1/20` |
| **时序窗口** | 持续采样，`snapshotAndReset()` 时输出并清空；seriesMax=2000 |
| **缓存/篡改** | 数据在内存，可篡改 |
| **传感器回放** | 可重放：CoreMotion 数据可被注入（需私有 API 或驱动） |

**绕过策略：**
1. **Hook CMMotionManager**：拦截 `startDeviceMotionUpdates` 的回调，注入带波动的 userAcceleration（magnitude 略 >0.02），降低 stillnessRatio。
2. **物理模拟**：云手机若支持，可模拟轻微震动/倾斜，使加速度有自然波动。
3. **内存篡改**：修改 `energySum`、`stillCount`、`series`，使 stillnessRatio<0.98，motionEnergy>1e-7。
4. **注意**：LayeredConsistencyProvider 的 `detectSensorEntropy` 要求 `motion.sampleCount>0`，完全屏蔽 motion 会变为 unavailable，可能触发跨层一致性检测。

---

### 3.3 BehaviorCoupling

| 维度 | 分析 |
|------|------|
| **系统 API** | 纯计算，无系统调用 |
| **SVC 直调** | 否 |
| **硬编码阈值** | actionTimestamps≥6，motion≥40，span≥4，bucketCount≥4；输出 Pearson 相关系数 |
| **时序窗口** | 依赖 touch 的 actionTimestamps 与 motion 的 series 时间重叠 |
| **缓存/篡改** | 输入来自 TouchCapture 与 MotionSampler，可篡改 |
| **传感器回放** | touch 与 motion 需时间对齐，可联合重放 |

**绕过策略：**
1. **时间对齐**：在 touch 的 actionTimestamps 与 motion 的 timestamp 重叠区间内，使 motion 的 energy 与 touch 密度正相关，提高 Pearson 相关系数。
2. **联合注入**：同时伪造 touch 与 motion，保证两者在时间上相关，correlation >0.10，避免 touchMotionWeakCoupling。

---

## 四、CloudPhone 模块

### 4.1 CloudPhoneLocalSignals

| 维度 | 分析 |
|------|------|
| **系统 API** | 无直接调用，依赖 DeviceFingerprint、BehaviorSignals、TimePattern |
| **SVC 直调** | 否 |
| **硬编码阈值** | touchSpread: 2.0/10.0；intervalCV: 0.2/0.6；linearity: 0.98/0.90；stillness: 0.98；correlation: 0.10；minTaps/minSwipes/minActions: 6/3/10；time: events 80/200/500, uniqueHours 18, nightRatio 0.4, avgInterval 8 |
| **时序窗口** | 与 Behavior、Time 一致 |
| **缓存/篡改** | 输入来自各 Provider，无独立缓存 |
| **传感器回放** | 同 Behavior |

**绕过策略：**
1. 与 Behavior、TimePattern、Device 的绕过策略一致。
2. **阈值汇总**：spread 保持在 2–10；intervalCV 在 0.2–0.6；linearity 在 0.90–0.98；stillness <0.98；correlation >0.10；控制 24h 内事件分布。

---

## 五、SVCDirectCall 与 Sysctl 使用情况

| 位置 | 使用方式 | Hook 难度 |
|------|----------|-----------|
| **DeviceFingerprint** | `Sysctl.string("hw.machine")` | 易：标准 libc sysctlbyname |
| **VPhoneHardwareProvider** | `Sysctl.string("hw.machine")` | 易 |
| **SVCDirectCall** | `dlsym(RTLD_NEXT, "sysctlbyname")` 取下一跳 | 中：需 hook dlsym 或 RTLD_NEXT 链 |
| **DualPathValidator** | 同时调 Sysctl 与 SVCDirectCall，比较结果 | 需两路一致，否则判 tampered |
| **LayeredConsistencyProvider** | 直接 `sysctlbyname("hw.machine", ...)` | 易 |
| **SysctlDetector** | 原始 `sysctl(&mib, 4, ...)` | 易：与 sysctlbyname 不同，需分别 hook |

**结论：**
- **无真正的 SVC 直调**：全部通过 libc sysctl/sysctlbyname，未直接发 SVC 指令。
- **RTLD_NEXT 绕过**：SVCDirectCall 用 RTLD_NEXT 取“未 hook”的 sysctlbyname；若 Frida 在 RTLD_NEXT 链上，仍可能被调用。可通过 hook `dlsym` 对 `sysctlbyname` 返回真实 libc 实现来绕过 DualPathValidator。
- **DualPathValidator**：同时调标准路径与 RTLD_NEXT 路径，不一致即 tampered。需两路返回相同值，即 hook 要同时覆盖 sysctlbyname 的 PLT 与 RTLD_NEXT 解析结果（或 hook 在更底层，使两路都经过同一实现）。

---

## 六、综合绕过优先级建议

1. **高优先级（易实现、影响大）**
   - Hook `sysctlbyname` / `sysctl`：统一返回真实机型、无越狱进程列表、无 P_TRACED。
   - Hook `FileManager.fileExists`、`lstat`、`access`：对越狱路径一致返回 false。
   - Hook `getenv` 并清空 environ 中的 DYLD_*。
   - Hook `UIApplication.canOpenURL`：对 cydia:// 等返回 false。
   - Hook `_dyld_get_image_name`：隐藏 frida/gadget 等路径。

2. **中优先级（需多路径一致）**
   - 保证 FileManager 与 lstat/access 一致，避免 fileExistsMismatch。
   - 保证 getenv 与 environ 一致。
   - 保证 sysctl、IOKit、uname 的 hw.machine/model 一致。
   - 满足 DualPathValidator：标准 sysctl 与 RTLD_NEXT sysctl 返回相同值。

3. **低优先级（实现复杂或需内核）**
   - Prologue/IndirectSymbolPointer 检测：需 inline hook 或 SVC 直调，或避免对敏感符号做 fishhook。
   - 行为信号：需注入逼真的 touch/motion 序列，并保持 touch-motion 时间相关性。
   - MountPoint：需 hook getmntinfo 或内核 VFS。
   - Battery：需 hook UIDevice/IOKit 并构造合理电压序列。

4. **检测与反检测对抗**
   - 检测方已有多路径、prologue、时序、行为熵等设计。
   - 绕过方需系统性覆盖所有路径，并注意跨层一致性（如 L1 正常 + L2 hook 会触发 cross_layer_inconsistency）。
   - 建议检测方：引入真实 SVC 直调、多随机化阈值、服务端行为建模，以提升绕过成本。
