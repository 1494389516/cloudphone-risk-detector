# 去特征化 Hook 工具威胁分析报告

> 参考案例：https://github.com/kkkbbb/rustFrida（Android 平台）
> 分析日期：2026-04-06
> 关联 SDK：CloudPhoneRiskKit v7.3

---

## 0. 平台说明

**rustFrida 是 Android ARM64 平台的动态插桩框架，不直接威胁 iOS 应用。**

本报告以 rustFrida 为 **参考案例**，分析其体现的"去特征化"设计思路对 iOS 安全检测的启示。
该趋势已在 iOS 生态中出现（魔改 Frida、Dopamine/Ellekit、Substrate 变种、商业逆向工具等），
rustFrida 只是将这一思路做到了最彻底的程度。

---

## 1. rustFrida 项目概述（Android）

rustFrida 是一个用 **Rust 编写的 ARM64 Android 动态插桩框架**，是传统 Frida 的替代实现。

| 能力 | 说明 | iOS 对应类比 |
|------|------|-------------|
| **Native Hook** | NORMAL / WXSHADOW / RECOMP 三种隐蔽模式 | Dobby、fishhook、Ellekit |
| **Java Hook** | JNI 层方法拦截 | ObjC method swizzling |
| **eBPF 监控** | 内核态 SO 加载监控 | iOS 无此能力（无 eBPF） |
| **QBDI 集成** | 指令级 DBI 追踪 | DynamoRIO 类似物（iOS 极少见） |
| **QuickJS 引擎** | 替代 V8 的嵌入式 JS 引擎 | 同——Frida iOS 魔改版可能采用 |
| **无依赖部署** | 单体二进制，ADB 推送 | IPA 重签注入 / DYLD_INSERT_LIBRARIES |

### 架构对比

```
原版 Frida (跨平台):
  frida-server (监听 27042) → D-Bus RPC → frida-agent → Gum Interceptor

rustFrida (Android):
  rustfrida (单体二进制) → shellcode loader → libagent.so → Rust Hook Engine

iOS 去特征化变种（已出现的趋势）:
  魔改 frida-server（改名/改端口/strip 符号）→ 去 D-Bus → 定制 agent dylib
```

### 核心"去特征化"手段

这些手段 **平台无关**，可直接移植到 iOS 场景：

| 去特征化手段 | 效果 | 已在 iOS 出现？ |
|-------------|------|:-------------:|
| 去除 D-Bus 协议栈 | 协议指纹全部失效 | 部分（魔改版用私有协议） |
| 更换监听端口 / 去除监听 | 端口扫描失效 | 是（随机端口已常见） |
| 重命名二进制和 dylib | 文件工件检测失效 | 是（改名 frida-server） |
| 替换 GLib/V8 依赖 | 线程名检测失效 | 部分（JavaScriptCore 替代） |
| Rust/C++ 编译 + strip | 内存字符串扫描大幅降低 | 是（strip -x 已成标配） |
| 代码重编译（RECOMP 思路） | Trampoline 模式匹配失效 | 暂未见成熟实现 |

---

## 2. iOS 实际威胁场景分析

以下不以 rustFrida 为目标，而是分析 **iOS 上已经存在或即将出现** 的去特征化 hook 威胁：

### 2.1 现有 SDK 检测器对去特征化工具的有效性

```
检测器                     对标准 Frida   对去特征化工具   差距
                           有效率          有效率
────────────────────────────────────────────────────────────
FridaDetector              ~95%           ~15%          严重
FridaThreadDetector        ~90%           ~20%          严重
FridaModuleDetector        ~90%           ~25%          严重
FridaSocketDetector        ~85%           ~20%          严重
GumTrampolineDetector      ~85%           ~50%          中等
MemoryIntegrityChecker     ~80%           ~45%          中等
AntiDebugWatchdog          ~70%           ~30%          中等
ObjCSwizzleDetector        ~75%           ~60%          轻微
DyldInterposeDetector      ~80%           ~50%          中等
```

**核心问题：** 以 `Frida` 命名的检测器（FridaDetector、FridaThreadDetector、FridaModuleDetector、FridaSocketDetector）的检测逻辑高度依赖 Frida 特征签名（端口 27042、D-Bus 协议、`gum-js-loop` 线程名、`frida:rpc` 内存字符串等），面对去特征化工具几乎全部失效。

### 2.2 iOS 实际已出现的去特征化手段

#### 2.2.1 魔改 Frida（改名 + 换端口 + 去符号）

**威胁来源：** 越狱社区广泛流传的 Frida 魔改版
**手段：**
- 将 `frida-server` 重命名为随机名称（如 `srv_helper`）
- 监听端口改为随机高端口或使用 USB 通道
- 对 frida-agent.dylib 执行 `strip -x` 去除符号表
- sed/patch 替换二进制中的 `frida`、`gum`、`re.frida` 字符串

**SDK 检测缺口：**
- FridaDetector 端口扫描失效（非 27042）
- FridaModuleDetector 模块名匹配失效（不含 "frida"）
- FridaThreadDetector 线程名仍可能有效（GLib 线程名难以修改）

#### 2.2.2 Dopamine / Ellekit Hook 引擎

**威胁来源：** iOS 16+ rootless 越狱工具链
**手段：**
- Ellekit 替代 Substrate/Substitute，使用自有 hook 引擎
- 不使用 Frida 的 Gum Interceptor，不产生 LDR+BR trampoline
- dylib 名称为 `libellekit.dylib`（不匹配 Frida 关键词）
- 从 `/var/jb/` 加载（rootless jailbreak 路径）

**SDK 检测缺口：**
- FridaDetector 全部失效（与 Frida 无关）
- GumTrampolineDetector 部分失效（hook 模式不同）
- DylibInjectionDetector 的 `/var/jb/` 路径检测有效

#### 2.2.3 IPA 重签注入（免越狱）

**威胁来源：** 企业签名/自签名分发的篡改 IPA
**手段：**
- 在 IPA 中添加 `LC_LOAD_DYLIB`，注入自定义 dylib
- 注入的 dylib 名称完全自定义（如 `libutils.dylib`）
- 通过 `DYLD_INSERT_LIBRARIES` 加载
- dylib 位于 App Bundle 内部（白名单路径内）

**SDK 检测缺口：**
- FridaDetector 全部失效
- ModuleDetector 关键词匹配失效（dylib 名称无特征）
- DylibInjectionDetector 的 DYLD_INSERT_LIBRARIES 检测有效
- CodeSignatureValidator 的签名校验有效

#### 2.2.4 Dobby / fishhook 轻量级 hook

**威胁来源：** 开源 hook 框架，被集成到各种逆向工具中
**手段：**
- Dobby 使用 ADRP+ADD+BR X17 跳板（与 Frida 不同的指令序列）
- fishhook 通过 dyld rebinding 修改 GOT 表
- 无任何 Frida 特征

**SDK 检测缺口：**
- GumTrampolineDetector 部分覆盖 Dobby（ADRP+ADD+BR 模式已包含）
- fishhook 的 GOT 修改不产生 trampoline，需要 GOT 完整性检查

---

## 3. 从 rustFrida 借鉴的三种隐蔽 hook 模式（跨平台通用原理）

虽然具体实现是 Android 的，但这三种模式的 **设计思路可直接应用于 iOS**：

### 3.1 NORMAL 模式 → iOS 对应：直接 mprotect + inline hook

在 iOS 上已被 Substrate、Dobby 广泛使用：
- `mprotect` / `vm_protect` 将 `__TEXT` 段改为可写
- 修改函数前几条指令为跳转
- 恢复页面为只读

**SDK 现有覆盖：** MemoryIntegrityChecker 检测 W^X 违规 → **有效**

### 3.2 WXSHADOW 模式 → iOS 对应：vm_remap 影子映射

原理可移植到 iOS：
- 使用 `mach_vm_remap()` 创建代码页的影子映射
- 通过影子映射（可写）修改代码，原始映射保持只读
- 用户态 `vm_region_64()` 查询原始映射不会发现 W^X 违规

**SDK 现有覆盖：** VMRemapDetector 检测 vm_remap 工件 → **部分有效**

### 3.3 RECOMP 模式 → iOS 对应：函数体替换

最隐蔽的方式：
- 完全重写目标函数机器码，嵌入 hook 逻辑
- 不产生标准 trampoline 跳板指令
- 重写后的代码看起来像"正常"ARM64 指令

**SDK 现有覆盖：** 无 → **需要函数完整性哈希检测**

---

## 4. 加固建议

### P0 — 已实现

#### 4.1 函数完整性哈希检测（FunctionIntegrityHashDetector）

```
当前：GumTrampolineDetector 依赖已知指令模式
加固：对关键函数前 32 字节计算 FNV-1a 哈希基线，后续对比
覆盖：任何方式修改函数前缀均可检出（含 RECOMP、Dobby、Ellekit）
```

#### 4.2 模块白名单检测（ModuleWhitelistDetector）

```
当前：DylibInjectionDetector 依赖关键词（"frida", "substrate"）
加固：枚举所有 dylib，路径不在系统白名单 → 可疑
覆盖：任意名称的注入 dylib（如 "libutils.dylib"、"libagent.dylib"）
```

#### 4.3 系统调用结果交叉验证（DirectSyscallCrossValidator）

```
当前：KernelHookSideChannel 做时序比较（概率型）
加固：libc 与直接 SVC 两条路径调用 getpid/stat/access，对比返回值
覆盖：任何工具对 libc 层的 hook 结果篡改（确定性检测，非概率型）
```

### P1 — 建议后续实现

#### 4.4 GOT/PLT 完整性检查

fishhook 通过 dyld rebinding 修改 GOT 表而不触及函数前缀，
现有检测器无法覆盖。建议：
- 在 SDK 初始化时快照关键 GOT 表项指向
- 周期性校验 GOT 表项是否仍指向合法系统库

#### 4.5 调用栈验证

hook 替换函数后，调用栈中会出现非系统库的帧：
- 对 `open`、`stat`、`dlopen` 等关键调用进行 `backtrace()` 采样
- 若栈帧经过非预期模块（不在系统白名单中）→ 可疑

#### 4.6 模块加载时序分析

正常 iOS 应用的 dylib 全部在启动阶段加载。运行时突然新增模块高度可疑：
- 监听 `_dyld_register_func_for_add_image` 回调
- 在 SDK 初始化后新加载的非系统 dylib → 报警

---

## 5. 结论

**rustFrida 本身不直接威胁 iOS 平台**，但它体现的"去特征化"设计思路已在 iOS 生态中蔓延：

| 趋势 | iOS 现状 | SDK 应对 |
|------|---------|---------|
| 重命名/strip Frida | 已广泛存在 | 签名检测失效，需行为检测 |
| 非 Frida hook 引擎（Ellekit/Dobby） | 越狱标配 | trampoline 模式匹配部分覆盖 |
| IPA 重签注入 | 免越狱攻击主流手段 | 关键词匹配失效，需白名单检测 |
| libc hook 篡改返回值 | 高级攻击中使用 | 需 SVC 交叉验证 |
| 函数体重编译 | 暂未见成熟实现 | 需函数完整性哈希 |

**核心策略转变：**

> SDK 的检测策略需要从 **"检测 Frida"** 逐步转向 **"检测 Hook 行为"**。
>
> - 签名检测（signature-based）保留用于捕获低成本攻击（标准 Frida/Substrate）
> - 行为检测（behavior-based）作为第二道防线捕获去特征化攻击
> - 两者共存，形成纵深防御
