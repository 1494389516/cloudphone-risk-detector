# SDK 5.3: Mach Exception Handler 实现说明

## 概述

在 CRiskCore 中新增 EXC_BREAKPOINT 异常端口抢占，防止 Frida/debugger 劫持异常端口。
SDK 初始化时主动注册 handler，若 Frida 后来劫持会失败或冲突；定期轮询验证 handler 是否仍为自己。

## 实现文件

- `cprisk_exception_handler.c` - 实现
- `CRiskCore.h` - 导出声明

## API

```c
void cprisk_register_exception_handler(void);  // 注册 EXC_BREAKPOINT handler
void cprisk_verify_exception_handler(void);    // 验证并必要时重新注册
```

## 调用位置

1. **cprisk_register_exception_handler()** - 在 `CPRiskKit.start()` 中，紧接 `cprisk_deny_attach()` 之后调用
2. **cprisk_verify_exception_handler()** - 在 `evaluate(config:scenario:)` 中，`registerProviders(for: config)` 之后调用（每次 evaluate 时验证）

## 技术细节

- **API**: `task_swap_exception_ports()` 原子替换，`task_get_exception_ports()` 验证
- **行为**: EXCEPTION_STATE_IDENTITY + ARM_THREAD_STATE64
- **Handler**: 后台 pthread 接收异常消息，对 EXC_BREAKPOINT 将 PC 前进 4 字节后回复，使断点继续执行
- **平台**: 仅在 arm64/aarch64 真机生效，模拟器与 x86_64 为 no-op

## 注意事项

1. **tvOS/watchOS**: `task_swap_exception_ports` 等 API 带有 `__TVOS_PROHIBITED`/`__WATCHOS_PROHIBITED`，在这些平台可能不可用
2. **消息格式**: 当前按 exc.defs 的 exception_raise_state_identity 布局解析；若内核使用 mach_exc（MACH_EXCEPTION_CODES）则需调整
3. **验证频率**: 每次 evaluate 调用时验证；若 evaluate 调用较少，可考虑在后台定时任务中增加验证
