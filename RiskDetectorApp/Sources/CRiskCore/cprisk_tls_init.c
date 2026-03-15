#include "include/CRiskCore.h"
#include <TargetConditionals.h>

/*
 * Early TLS (Thread Local Storage) Callback
 *
 * Placed in the __DATA,__thread_init section, this callback executes very early
 * during the dynamic linker (dyld) loading phase—before C++ constructors
 * (__mod_init_func) and Objective-C +load methods.
 *
 * This makes it an ideal place to invoke anti-debugging logic (like ptrace
 * PT_DENY_ATTACH or Mach exception handler registration) to preempt attackers
 * who try to set up hooks early in the application lifecycle.
 */

static void cprisk_tls_init_callback(void) {
    /* Invoke direct syscall ptrace(PT_DENY_ATTACH) */
    cprisk_deny_attach();
    
    /* Preemptively register Mach exception handler for EXC_BREAKPOINT */
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
