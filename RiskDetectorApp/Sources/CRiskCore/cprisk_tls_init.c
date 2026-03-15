#include "include/CRiskCore.h"
#include <TargetConditionals.h>

/*
 * Early TLS (Thread Local Storage) Callback — TLS 回调时序加固
 *
 * 执行时机：__DATA,__thread_init 在 dyld 加载阶段执行，早于 __mod_init_func
 * （C++ constructor）和 Objective-C +load。
 *
 * 时序风险：Frida gadget 若打包进 IPA，也可使用 __DATA,__thread_init。同一
 * section 内多个回调的调用顺序由链接器决定（通常按 section 中出现顺序）。
 * 若 gadget 的 __thread_init 先于或交错于本回调执行，可能已注册异常端口或
 * 设置 Hook，导致 ptrace 被绕过或异常端口被抢占。
 *
 * 加固策略：
 * 1. ptrace 优先：使用 SVC 直调绕过 libc Hook，即使 Frida 已 Hook ptrace 也无效。
 * 2. 异常端口：本回调中注册后，由 cprisk_early_exception_port_reclaim（constructor
 *    101）在 __mod_init_func 阶段再次验证；若被 Frida 覆盖则 task_swap_exception_ports
 *    重新抢占。详见 cprisk_exception_handler.c。
 */
static void cprisk_tls_init_callback(void) {
    /* 1. ptrace 优先：SVC 直调，不经过 libc，抗 Hook */
    cprisk_deny_attach();

    /* 2. 抢占异常端口；若 Frida 后执行覆盖，constructor 阶段会重新抢占 */
    cprisk_register_exception_handler();
}

/* 
 * Register the callback pointer in the __DATA,__thread_init section.
 * The 'used' attribute ensures the compiler doesn't optimize it away.
 */
#if defined(__APPLE__)
__attribute__((used, section("__DATA,__thread_init")))
static void (*cprisk_tls_init_ptr)(void) = cprisk_tls_init_callback;
#endif
