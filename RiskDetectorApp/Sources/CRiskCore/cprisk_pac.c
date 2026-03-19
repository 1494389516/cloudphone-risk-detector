#include "include/CRiskCore.h"

#include <stdint.h>

#if defined(__has_include)
#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#define CPRISK_HAS_PTRAUTH_HEADER 1
#else
#define CPRISK_HAS_PTRAUTH_HEADER 0
#endif
#else
#define CPRISK_HAS_PTRAUTH_HEADER 0
#endif

#if defined(__arm64e__) && CPRISK_HAS_PTRAUTH_HEADER
#define CPRISK_PAC_RUNTIME_AVAILABLE 1
#else
#define CPRISK_PAC_RUNTIME_AVAILABLE 0
#endif

static inline uintptr_t cprisk_pac_blend_discriminator(uintptr_t discriminator) {
#if CPRISK_PAC_RUNTIME_AVAILABLE
    return ptrauth_blend_discriminator((void *)&cprisk_pac_blend_discriminator, discriminator);
#else
    return discriminator;
#endif
}

void *cprisk_pac_sign_function_pointer(const void *ptr, uintptr_t discriminator) {
    if (ptr == NULL) {
        return NULL;
    }
#if CPRISK_PAC_RUNTIME_AVAILABLE
    const uintptr_t blended = cprisk_pac_blend_discriminator(discriminator);
    return (void *)ptrauth_sign_unauthenticated(
        ptr,
        ptrauth_key_function_pointer,
        blended);
#else
    (void)discriminator;
    return (void *)ptr;
#endif
}

void *cprisk_pac_auth_function_pointer(const void *ptr, uintptr_t discriminator) {
    if (ptr == NULL) {
        return NULL;
    }
#if CPRISK_PAC_RUNTIME_AVAILABLE
    const uintptr_t blended = cprisk_pac_blend_discriminator(discriminator);
    const void *authed = ptrauth_auth_function(
        ptr,
        ptrauth_key_function_pointer,
        blended);
    const void *resigned = ptrauth_sign_unauthenticated(
        authed,
        ptrauth_key_function_pointer,
        blended);
    if (resigned != ptr) {
        return NULL;
    }
    return (void *)authed;
#else
    (void)discriminator;
    return (void *)ptr;
#endif
}

int cprisk_pac_is_arm64e_supported(void) {
#if CPRISK_PAC_RUNTIME_AVAILABLE
    return 1;
#else
    return 0;
#endif
}
