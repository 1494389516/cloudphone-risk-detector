# CRiskCore ABI 兼容性契约

> 本文档定义 `CRiskCore` C 层导出符号的 ABI 稳定性保证、版本演进规则和兼容性矩阵。

## 当前版本

| 字段 | 值 |
|------|-----|
| ABI 语义版本 | **1.0.0** (`CPRISK_ABI_VERSION_MAJOR.MINOR.PATCH`) |
| Armor ABI 版本 | 2 (`CPRISK_ARMOR_ABI_VERSION`) |
| Whitebox ABI 版本 | 2 (`CPRISK_ARMOR_WHITEBOX_ABI_VERSION`) |
| Anti-Debug ABI 版本 | 1 (`CPRISK_ARMOR_ADBG_ABI_VERSION`) |
| Text-Encrypt ABI 版本 | 1 (`CPRISK_TEXT_ENCRYPT_ABI_VERSION`) |
| Metadata-Shuffle ABI 版本 | 1 (`CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_ABI_VERSION`) |

运行时查询：

```c
uint32_t v = cprisk_abi_version();
uint8_t major = (v >> 16) & 0xFF;
uint8_t minor = (v >> 8)  & 0xFF;
uint8_t patch = v & 0xFF;
```

---

## 导出 C 符号清单

### 核心生命周期

| 符号 | 稳定性 | 引入版本 | 说明 |
|------|--------|---------|------|
| `cprisk_init_protection` | **Stable** | 1.0 | 初始化 Armor 运行时（传入 32 字节 root key） |
| `cprisk_cleanup_protection` | **Stable** | 1.0 | 清理 Armor 运行时状态 |
| `cprisk_recheck_integrity` | **Stable** | 1.0 | 运行时完整性重校验 |
| `cprisk_is_integrity_poisoned` | **Stable** | 1.0 | 查询 integrity poison 标志位 |
| `cprisk_abi_version` | **Stable** | 1.0 | 运行时查询编译期 ABI 版本 |

### Anti-Debug / Anti-Dump

| 符号 | 稳定性 | 引入版本 | 说明 |
|------|--------|---------|------|
| `cprisk_deny_attach` | **Stable** | 1.0 | ptrace(PT_DENY_ATTACH) |
| `cprisk_register_exception_handler` | **Stable** | 1.0 | 注册 Mach exception handler |
| `cprisk_verify_exception_handler` | **Stable** | 1.0 | 校验 exception port 未被劫持 |
| `cprisk_start_anti_debug_watchdog` | **Stable** | 1.0 | 启动 anti-debug 看门狗线程 |
| `cprisk_stop_anti_debug_watchdog` | **Stable** | 1.0 | 停止看门狗线程 |
| `cprisk_get_anti_debug_watchdog_snapshot` | **Stable** | 1.0 | 获取看门狗运行状态快照 |
| `cprisk_start_anti_dump_probe` | **Stable** | 1.0 | 启动 anti-dump 探测 |
| `cprisk_stop_anti_dump_probe` | **Stable** | 1.0 | 停止 anti-dump 探测 |
| `cprisk_erase_macho_header` | **Stable** | 1.0 | 擦除 Mach-O header（仅 iOS 真机） |
| `cprisk_watchdog_note_main_thread_alive` | **Stable** | 1.0 | 主线程心跳通知 |
| `cprisk_get_antidebug_plan_snapshot` | **Stable** | 1.0 | Anti-debug plan 快照 |

### 运行时加固模式

| 符号 | 稳定性 | 引入版本 | 说明 |
|------|--------|---------|------|
| `cprisk_set_runtime_hardening_mode` | **Stable** | 1.0 | 设置运行时加固模式（production/relaxed/appStoreSafe） |

### Armor 密钥派生 & 签名

| 符号 | 稳定性 | 引入版本 | 说明 |
|------|--------|---------|------|
| `cprisk_sign_with_derived_key_and_request_binding_digest` | **Stable** | 1.0 | Armor 密钥派生签名（带 request binding） |
| `cprisk_verify_with_derived_key_and_request_binding_digest` | **Stable** | 1.0 | Armor 密钥派生验签（带 request binding） |
| `cprisk_read_full_anchor_hash` | **Stable** | 1.0 | 读取 4-lane anchor 聚合 hash |

### 内联函数（Header-Only）

| 函数 | 稳定性 | 说明 |
|------|--------|------|
| `cprisk_hmac_sha256` | **Stable** | Custom-pad HMAC-SHA256 |
| `cprisk_hmac_verify` | **Stable** | 常量时间 HMAC 比较 |
| `cprisk_derive_salt_xor_key` | **Stable** | 从 root key 派生 salt XOR 密钥 |
| `cprisk_decode_salt` | **Stable** | XOR 解码 salt |
| `cprisk_abi_version` | **Stable** | ABI 版本查询 |

---

## 导出数据结构

| 结构体 | 大小 (bytes) | 稳定性 | Static Assert |
|--------|-------------|--------|--------------|
| `cprisk_armor_strtab_header` | 12 | **Frozen** | ✅ |
| `cprisk_armor_strtab_index_entry` | 52 | **Frozen** | ✅ |
| `cprisk_armor_loader_header` | 12 | **Frozen** | ✅ |
| `cprisk_armor_loader_entry` | 136 (v3) | **Frozen** | ✅ |
| `cprisk_armor_antidebug_header` | 48 | **Frozen** | ✅ |
| `cprisk_armor_antidebug_entry` | 64 | **Frozen** | ✅ |
| `cprisk_armor_swift_metadata_shuffle_header` | 32 | **Frozen** | ✅ |
| `cprisk_armor_whitebox_header` | 56 (v2) | **Frozen** | ✅ |
| `cprisk_text_encrypt_header` | 16 | **Frozen** | ✅ |
| `cprisk_text_encrypt_entry` | 96 | **Frozen** | ✅ |
| `cprisk_whitebox_probe_result` | 16 | **Frozen** | ✅ |

> **Frozen** = 结构体内存布局已冻结，不会在同一 MAJOR 版本内变更；新增字段只能通过新版本结构体或尾部扩展。

---

## 稳定性保证

### Stable（稳定）

- 符号签名（参数类型、返回类型、调用约定）在同一 MAJOR 版本内不变
- 移除或修改签名必须 bump MAJOR
- Swift 侧通过 `import CRiskCore` 直接使用，无需版本门控

### Provisional（临时）

- 可能在 MINOR 版本间发生非兼容变更
- Swift 侧使用时应加 `#if` 或版本检测
- 升级到 Stable 时会在 CHANGELOG 中注明

### Deprecated（废弃）

- 至少保留一个 MINOR 周期，期间附带编译器 warning
- MAJOR 版本升级时可移除

---

## 向后/向前兼容规则

### 向后兼容（Backward Compatibility）

> 新版 SDK 加载旧版 ABI 数据

| 场景 | 保证 |
|------|------|
| PATCH 升级 (1.0.0 → 1.0.1) | ✅ 完全兼容 |
| MINOR 升级 (1.0.x → 1.1.0) | ✅ 完全兼容（新增字段有默认值） |
| MAJOR 升级 (1.x.x → 2.0.0) | ❌ 可能不兼容，需参考迁移指南 |

### 向前兼容（Forward Compatibility）

> 旧版 SDK 加载新版 ABI 数据

| 场景 | 保证 |
|------|------|
| PATCH 降级 (1.0.1 → 1.0.0) | ✅ 完全兼容 |
| MINOR 降级 (1.1.0 → 1.0.x) | ⚠️ 部分兼容（忽略未知尾部字段） |
| MAJOR 降级 (2.0.0 → 1.x.x) | ❌ 不兼容 |

### 兼容性矩阵

| SDK 版本 \ 数据 ABI | 1.0.x | 1.1.x | 2.0.x |
|---------------------|-------|-------|-------|
| SDK with ABI 1.0.x | ✅ | ⚠️ 忽略新字段 | ❌ |
| SDK with ABI 1.1.x | ✅ | ✅ | ❌ |
| SDK with ABI 2.0.x | ❌ 需迁移 | ❌ 需迁移 | ✅ |

---

## 版本 Bump 策略

### PATCH (x.y.Z)

适用：
- 修复内联函数 bug（不改变签名）
- 修复 `_Static_assert` 遗漏
- 文档修正

不允许：
- 增删结构体字段
- 修改函数签名
- 移除任何导出符号

### MINOR (x.Y.0)

适用：
- 新增结构体（新 `_Static_assert`）
- 新增导出函数
- 在现有 packed 结构体**尾部**新增可选字段（需附带 version 字段区分）
- 新增 `#define` 常量
- 标记符号为 Deprecated

不允许：
- 修改已有结构体的已有字段偏移
- 移除 Stable 符号
- 修改函数签名

### MAJOR (X.0.0)

适用：
- 移除 Deprecated 符号
- 修改已有结构体内存布局
- 修改函数签名或调用约定
- 重大架构变更

**必须**：
- 提供迁移指南
- 至少提前一个 MINOR 版本标注 Deprecated

---

## 迁移指南模板

### 从 ABI X.Y.Z 迁移到 ABI A.B.C

#### 破坏性变更

1. **`<符号名>`**: `<旧签名>` → `<新签名>`
   - 影响范围：`<Swift 层受影响的文件/模块>`
   - 迁移步骤：
     1. `<步骤 1>`
     2. `<步骤 2>`
   - 验证检查点：`<如何验证迁移正确>`

2. **`<结构体名>`**: 大小从 `N` → `M` 字节
   - 新增/移除字段：`<字段名及类型>`
   - 迁移步骤：...

#### 新增符号

| 符号 | 说明 | 使用建议 |
|------|------|---------|
| ... | ... | ... |

#### 废弃符号

| 符号 | 替代方案 | 移除计划 |
|------|---------|---------|
| ... | ... | ... |

---

## 运行时版本检测示例

```c
#include "cprisk_armor_abi.h"

void check_abi_compatibility(void) {
    uint32_t v = cprisk_abi_version();
    uint8_t major = (v >> 16) & 0xFF;
    uint8_t minor = (v >> 8)  & 0xFF;

    if (major != CPRISK_ABI_VERSION_MAJOR) {
        // ABI 不兼容，需要迁移
        abort();
    }
    if (minor < CPRISK_ABI_VERSION_MINOR) {
        // 缺少新特性，但基本功能可用
        // 可选择降级运行
    }
}
```

```swift
import CRiskCore

func ensureABICompatible() {
    let version = cprisk_abi_version()
    let major = (version >> 16) & 0xFF
    precondition(major == CPRISK_ABI_VERSION_MAJOR,
                 "CRiskCore ABI major version mismatch")
}
```

---

## 变更日志

| 日期 | ABI 版本 | 变更类型 | 说明 |
|------|---------|---------|------|
| 2026-03-27 | 1.0.0 | 初始发布 | 首次定义 ABI 语义版本契约 |
