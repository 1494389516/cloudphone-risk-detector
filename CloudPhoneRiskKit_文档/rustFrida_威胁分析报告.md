# rustFrida 威胁分析报告

> 分析目标：https://github.com/kkkbbb/rustFrida
> 分析日期：2026-04-06
> 关联 SDK：CloudPhoneRiskKit v7.3

---

## 1. rustFrida 项目概述

rustFrida 是一个用 **Rust 编写的 ARM64 Android 动态插桩框架**，是传统 Frida 的替代实现。其核心能力包括：

| 能力 | 说明 |
|------|------|
| **Native Hook** | 直接地址拦截，支持 NORMAL / WXSHADOW / RECOMP 三种隐蔽模式 |
| **Java Hook** | 通过 JNI 实现类方法拦截、构造函数拦截、重载分辨 |
| **内存操作** | 指针算术、直接内存读写、模块枚举与导出解析 |
| **eBPF 监控** | 内核态 SO 加载监控（`ldmonitor-ebpf`） |
| **QBDI 集成** | 动态二进制插桩（指令级追踪） |
| **QuickJS 引擎** | 嵌入式 JS 运行时，提供交互式 REPL |
| **无依赖部署** | 单一二进制通过 ADB 推送，shellcode loader 自主注入 |

### 关键架构差异（vs 原版 Frida）

```
原版 Frida:
  frida-server (监听 27042) → D-Bus RPC → frida-agent.so → Gum Interceptor
  
rustFrida:
  rustfrida (单体二进制) → 裸金属 shellcode loader → libagent.so → Rust Hook Engine
```

**核心差异点：**
- 无 D-Bus 协议栈（消除协议指纹）
- 无标准 Frida 监听端口（无 27042/27043）
- 无 `frida-server` / `frida-agent` / `frida-gadget` 命名
- Rust 编译产物，无 GLib/GIO 依赖（无 `gmain`/`gdbus` 线程）
- 使用 QuickJS 替代 V8（无 `v8:` 线程名前缀）
- WXSHADOW 模式使用内核影子页，避免 W^X 违规

---

## 2. 对 SDK 各检测层的威胁评估

### 2.1 FridaDetector — 威胁等级：🔴 高

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| 端口扫描 (27042/27043/23946) | ❌ **失效** | rustFrida 不使用标准 Frida 端口 |
| D-Bus 协议指纹 | ❌ **失效** | rustFrida 无 D-Bus 协议栈 |
| AUTH EXTERNAL/ANONYMOUS 探针 | ❌ **失效** | 无 SASL 认证握手 |
| 环境变量 (FRIDA/FRIDA_VERSION) | ❌ **失效** | rustFrida 不设置 Frida 环境变量 |
| 文件工件 (/usr/sbin/frida-server) | ❌ **失效** | 二进制名为 `rustfrida`，不在标准路径 |
| 内存签名扫描 ("frida:rpc", "gum-interceptor") | ⚠️ **部分有效** | Rust 二进制可能包含部分 frida-gum 字符串，但可被 strip |
| CRiskCore 运行时快照 | ⚠️ **部分有效** | 取决于 hook 行为是否触发行为标记 |

**风险总结：** 7 项检测中 5 项完全失效，SDK 的 Frida 检测主要依赖"Frida 特征签名"，而 rustFrida 刻意消除了这些签名。

### 2.2 GumTrampolineDetector — 威胁等级：🟡 中

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| LDR X16, #8; BR X16 模式 | ⚠️ **取决于 hook 模式** | NORMAL 模式可能使用类似 trampoline |
| ADRP; ADD; BR X17 模式 | ⚠️ **取决于实现** | Rust hook 引擎可能使用不同的跳转指令序列 |
| 匿名内存中的跳转目标 | ✅ **有效** | hook 代码必然驻留在匿名内存中 |
| Hook 链检测 | ✅ **有效** | 多个函数指向同一匿名区域仍可被检出 |

**风险总结：** 如果 rustFrida 使用 RECOMP 模式（代码重编译），可以避免 trampoline 模式匹配。但匿名内存检测仍然有效。

### 2.3 MemoryIntegrityChecker — 威胁等级：🟡 中

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| W^X 违规检测 | ❌ **WXSHADOW 模式下失效** | 内核影子页不会在用户态产生 W^X 违规 |
| W^X 违规检测 | ✅ **NORMAL 模式下有效** | 直接 mprotect 会被检测到 |
| 内联 hook ARM64 模式匹配 | ⚠️ **部分有效** | 取决于具体的 hook 指令序列 |
| 可疑镜像标记 ("frida", "gum") | ⚠️ **部分有效** | Rust 二进制可能包含 frida-gum 相关字符串 |

### 2.4 FridaThreadDetector — 威胁等级：🔴 高

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| 线程名检测 (gum-js-loop, gmain, gdbus) | ❌ **失效** | rustFrida 使用 QuickJS，不产生 GLib 线程 |
| v8: 线程名 | ❌ **失效** | 不使用 V8 引擎 |
| 异常端口劫持检测 | ⚠️ **可能有效** | 取决于 rustFrida 是否劫持异常端口 |
| 线程数量异常 | ⚠️ **部分有效** | Rust 线程池可能触发阈值 |

### 2.5 FridaModuleDetector — 威胁等级：🔴 高

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| 模块名标记 (frida-agent, frida-gadget, libgum) | ❌ **失效** | 注入库名为 `libagent.so`，不含 frida 关键词 |
| 段名标记 (__frida, __gum) | ❌ **失效** | Rust 编译不产生这些段名 |
| 字符串标记 ("frida:rpc") | ⚠️ **部分有效** | 可能存在残留字符串 |
| 可疑路径来源 (/tmp/) | ✅ **有效** | 通过 ADB 推送可能落在可疑路径 |
| Trampoline 标记 | ⚠️ **部分有效** | 同 GumTrampolineDetector |

### 2.6 FridaSocketDetector — 威胁等级：🔴 高

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| /tmp 目录扫描 (.frida) | ❌ **失效** | rustFrida 不创建 .frida 目录 |
| Socket FD 扫描 | ⚠️ **可能有效** | 取决于 rustFrida 是否使用 Unix Socket |
| 时序侧信道 (Stalker DBT) | ❌ **失效** | rustFrida 不使用 Frida Stalker |
| 时序侧信道 (QBDI) | ⚠️ **可能有效** | QBDI 模式可能产生类似时序异常 |

### 2.7 DebuggerDetector — 威胁等级：🟢 低

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| ptrace P_TRACED | ❌ 不直接适用 | rustFrida 是注入式，非调试器 |
| 父进程检查 | ❌ 不直接适用 | 父进程不是 lldb/gdb |
| 硬件断点 | ❌ 不直接适用 | 非调试器模式 |

**注意：** 虽然 DebuggerDetector 不针对 rustFrida，但 rustFrida 的 QBDI 模式可能触发部分检测。

### 2.8 AntiDebugWatchdog — 威胁等级：🟡 中

| 检测手段 | 能否检出 rustFrida | 原因 |
|----------|-------------------|------|
| 软件断点扫描 (BRKA) | ❌ **失效** | rustFrida 不插入断点指令 |
| 即时返回补丁检测 | ⚠️ **可能有效** | 如果 hook 替换函数逻辑 |
| 异常传递超时 | ⚠️ **可能有效** | hook 可能导致异常处理延迟 |
| SIGTRAP 探测 | ❌ **失效** | 非调试器模式 |

---

## 3. 总体威胁矩阵

```
                    检测能力评估（针对 rustFrida）
                    
检测器                     有效率    威胁等级    优先级
─────────────────────────────────────────────────────
FridaDetector              ~15%     🔴 高       P0
FridaThreadDetector        ~20%     🔴 高       P0
FridaModuleDetector        ~25%     🔴 高       P0
FridaSocketDetector        ~20%     🔴 高       P0
GumTrampolineDetector      ~50%     🟡 中       P1
MemoryIntegrityChecker     ~40%     🟡 中       P1
AntiDebugWatchdog          ~30%     🟡 中       P1
DebuggerDetector           ~10%     🟢 低       P2
ObjCSwizzleDetector        ~60%     🟢 低       —
DyldInterposeDetector      ~50%     🟢 低       —
```

**综合检出率估计：30-40%**（vs 原版 Frida 的 ~95%）

---

## 4. 核心威胁归纳

### 4.1 签名规避（Signature Evasion）

rustFrida 的最大威胁在于 **系统性地消除了所有 Frida 特征签名**：

- **协议层**：无 D-Bus → 协议指纹全部失效
- **网络层**：无标准端口 → 端口扫描全部失效
- **文件层**：无 frida-server 路径 → 文件工件检测失效
- **进程层**：无 GLib 线程 → 线程名检测失效
- **内存层**：Rust 编译 + strip → 内存字符串检测大幅降低

### 4.2 WXSHADOW 隐蔽 Hook

WXSHADOW 模式是核心威胁：
- 利用内核影子页实现 hook，用户态 `vm_region_64()` 查询无法发现 W^X 违规
- 绕过了 MemoryIntegrityChecker 的主要检测逻辑
- 需要内核层面的检测能力才能应对

### 4.3 RECOMP 代码重编译

RECOMP 模式通过重编译目标函数代码：
- 避免产生标准 trampoline 指令模式（LDR+BR、ADRP+ADD+BR）
- GumTrampolineDetector 的模式匹配可能完全失效
- 重编译后的代码看起来像"正常"代码

### 4.4 eBPF 内核级能力

`ldmonitor-ebpf` 模块提供内核态 SO 加载监控：
- 可以在内核层面监控目标应用加载了哪些动态库
- 可能用于在 SDK 加载之前抢先完成 hook
- SDK 的用户态检测对此无能为力

---

## 5. 加固建议

### P0 — 紧急（针对签名规避）

#### 5.1 引入行为检测替代签名检测

```
当前：检测 "frida" 字符串 / 27042 端口 / D-Bus 协议
建议：检测 hook 行为本身，而非 hook 工具的特征
```

具体措施：
- **函数完整性哈希**：对关键系统函数（open, dlopen, mmap 等）的前 N 字节计算哈希，周期性校验
- **返回值一致性检测**：同一系统调用通过不同路径（libc wrapper vs 直接 SVC）调用，对比返回值
- **调用栈验证**：通过 `backtrace()` 验证关键函数的调用栈是否合理（是否经过未知模块）

#### 5.2 通用注入检测（不依赖工具名称）

```
当前：检测 "frida-agent" / "libgum" 等已知模块名
建议：检测任何未知/异常的注入模块
```

具体措施：
- **模块白名单机制**：建立应用正常运行时的模块列表基线，检测任何非预期模块
- **模块签名验证**：验证所有加载模块的代码签名，拒绝未签名模块
- **模块加载时序分析**：检测在应用启动后异常时间点加载的模块

### P1 — 重要（针对隐蔽 Hook）

#### 5.3 多路径交叉验证

针对 WXSHADOW 模式：
- **直接系统调用对比**：关键操作同时通过 libc 和 SVC #0x80 直接调用，对比结果
- **内核信息交叉验证**：通过 `/proc/self/maps` 和 `vm_region_64()` 双重验证内存布局
- **代码段完整性**：将 `__TEXT` 段关键页面的哈希值内嵌到数据段，运行时周期性校验

#### 5.4 统计异常检测

针对 RECOMP 模式：
- **指令分布分析**：正常函数和重编译函数的指令分布存在统计差异
- **CFG 异常检测**：重编译代码的控制流图与原始代码存在差异
- **时序抖动检测**：hook 后的函数即使经过重编译，执行时间也会有微小但可测量的变化

### P2 — 改进（纵深防御）

#### 5.5 通用 Hook 引擎检测

不针对特定工具，而是检测 hook 引擎的通用行为：
- **匿名可执行内存**：任何非 dyld 映射的可执行匿名内存区域都高度可疑
- **跨模块跳转异常**：正常代码不会从系统库跳转到匿名内存
- **GOT/PLT 完整性**：周期性验证 GOT 表项是否指向合法模块

#### 5.6 启动时序防御

针对 eBPF 抢先 hook：
- **最早初始化**：确保 SDK 在 `+load` 或 `__attribute__((constructor))` 中尽早初始化
- **启动完整性快照**：在 SDK 初始化时立即对关键函数做完整性快照，后续校验
- **延迟检测**：部分检测延迟到运行中随机时间点执行，防止一次性绕过

---

## 6. 结论

rustFrida 代表了一类 **"去特征化"动态插桩工具** 的发展趋势。它系统性地消除了传统 Frida 的所有可检测特征（端口、协议、文件名、线程名、内存字符串），使得我们 SDK 中 **基于签名的检测方案大面积失效**。

**核心启示：**

> SDK 的检测策略需要从 **"检测 Frida"** 转向 **"检测 Hook 行为"**。
> 
> 签名检测（signature-based）只能应对已知工具，行为检测（behavior-based）才能应对未知变种。

**优先行动项：**
1. 立即增加函数完整性哈希校验（不依赖工具签名）
2. 引入模块白名单机制（检测任何异常注入）
3. 实现直接系统调用对比（绕过 libc hook）
4. 加强匿名可执行内存检测（通用 hook 引擎行为）
