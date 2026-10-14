#include "include/CRiskCore.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

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

static atomic_uint_fast32_t s_last_pac_flags = CPRISK_PAC_CFI_FLAG_NONE;

static uint64_t cprisk_pac_probe_callback_i(uint64_t seed) {
    return (seed ^ 0x9E3779B97F4A7C15ULL) + 0xA24BAED4963EE407ULL;
}

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

/* Authenticate an externally-signed pointer.
 * NOTE: on non-arm64e builds this returns the pointer unchanged — that is
 * a no-op fallback, NOT a verification. Callers that need real validation
 * must check cprisk_pac_is_arm64e_supported() / the -1 return of
 * cprisk_pac_validate_indirect_call_target() instead of trusting this. */
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

/* REAL validation of an externally-provided (already signed) indirect-call
 * target: authenticate the pointer AS GIVEN with the supplied discriminator.
 * This deliberately does NOT sign-then-authenticate: self-sign + self-auth
 * always succeeds and proves nothing about the supplied pointer (that
 * round-trip is a self-test, see cprisk_pac_self_test()).
 * Returns 0 = authenticated, 1 = authenticated but weak binding (a wrong
 * discriminator also authenticates it), -1 = failure (NULL, unavailable
 * platform, or authentication failed). An unsigned / forged pointer fails. */
int cprisk_pac_validate_indirect_call_target(const void *func_ptr, uintptr_t discriminator) {
    if (func_ptr == NULL) {
        atomic_store(&s_last_pac_flags, CPRISK_PAC_CFI_FLAG_AUTH_FAILED);
        return -1;
    }

    uint32_t flags = CPRISK_PAC_CFI_FLAG_NONE;
#if !CPRISK_PAC_RUNTIME_AVAILABLE
    /* No PAC hardware/compiler support: authentication is impossible, so
     * this is a failure, not a success. */
    flags |= CPRISK_PAC_CFI_FLAG_UNAVAILABLE | CPRISK_PAC_CFI_FLAG_AUTH_FAILED;
    atomic_store(&s_last_pac_flags, flags);
    return -1;
#else
    const void *authed = ptrauth_auth_function(
        func_ptr,
        ptrauth_key_function_pointer,
        cprisk_pac_blend_discriminator(discriminator));
    if (authed == NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_AUTH_FAILED;
        atomic_store(&s_last_pac_flags, flags);
        return -1;
    }
    /* Weak-binding probe: a wrong discriminator must NOT authenticate. */
    const void *wrong_auth = ptrauth_auth_function(
        func_ptr,
        ptrauth_key_function_pointer,
        cprisk_pac_blend_discriminator(discriminator ^ 0xBADC0FFEE0DDF00DULL));
    if (wrong_auth != NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_WEAK_BINDING;
    }
    atomic_store(&s_last_pac_flags, flags);
    return (flags & CPRISK_PAC_CFI_FLAG_WEAK_BINDING) != 0u ? 1 : 0;
#endif
}

/* SELF-TEST ONLY (not validation): signs a known-good internal pointer
 * and authenticates it back. A pass here proves the PAC mechanism works;
 * it says nothing about any externally-supplied pointer. */
int cprisk_pac_self_test(uintptr_t discriminator) {
    uint32_t flags = CPRISK_PAC_CFI_FLAG_NONE;
#if !CPRISK_PAC_RUNTIME_AVAILABLE
    flags |= CPRISK_PAC_CFI_FLAG_UNAVAILABLE;
    atomic_store(&s_last_pac_flags, flags);
    return 0;
#else
    typedef uint64_t (*cprisk_pac_probe_fn_t)(uint64_t);
    const cprisk_pac_probe_fn_t fn = cprisk_pac_probe_callback_i;
    const uint64_t sample = 0x13579BDF2468ACE0ULL;
    const uint64_t expected = cprisk_pac_probe_callback_i(sample);

    void *signed_ptr = cprisk_pac_sign_function_pointer((const void *)fn, discriminator);
    if (signed_ptr == NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_SIGN_FAILED | CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
        atomic_store(&s_last_pac_flags, flags);
        return 1;
    }

    void *authed_ptr = cprisk_pac_auth_function_pointer(signed_ptr, discriminator);
    if (authed_ptr == NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_AUTH_FAILED | CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
        atomic_store(&s_last_pac_flags, flags);
        return 1;
    }

    const cprisk_pac_probe_fn_t authed_fn = (cprisk_pac_probe_fn_t)authed_ptr;
    if (authed_fn(sample) != expected) {
        flags |= CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
    }

    void *wrong_auth = cprisk_pac_auth_function_pointer(
        signed_ptr,
        discriminator ^ 0x9E3779B97F4A7C15ULL
    );
    if (wrong_auth != NULL) {
        flags |= CPRISK_PAC_CFI_FLAG_WEAK_BINDING | CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED;
    }

    atomic_store(&s_last_pac_flags, flags);
    return (flags & CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED) == 0u ? 0 : 1;
#endif
}

int cprisk_pac_validate_core_callbacks(void) {
    struct {
        const void *pointer;
        uintptr_t discriminator;
    } callbacks[] = {
        { (const void *)&cprisk_compute_integrity_hash, 0x43505249534B4346ULL }, /* "CPRISKCF" */
        { (const void *)&cprisk_detect_hardware_breakpoints, 0x43505249534B4347ULL },
        { (const void *)&cprisk_detect_thread_exception_ports, 0x43505249534B4348ULL },
        { (const void *)&cprisk_run_all_signal_probes, 0x43505249534B4349ULL },
    };

    uint32_t aggregatedFlags = CPRISK_PAC_CFI_FLAG_NONE;
    bool validationFailed = false;

    /* NOTE: these callbacks are compiler-signed with the compiler's own
     * discriminators (unknown to us), so they cannot be validated with
     * cprisk_pac_validate_indirect_call_target() + an invented
     * discriminator. This loop is therefore an explicit SELF-TEST
     * (sign-then-auth round-trip of each pointer), not external validation. */
    for (size_t i = 0; i < (sizeof(callbacks) / sizeof(callbacks[0])); ++i) {
        void *signed_ptr = cprisk_pac_sign_function_pointer(
            callbacks[i].pointer, callbacks[i].discriminator);
        const int rc = (signed_ptr == NULL) ? -1 :
            (cprisk_pac_auth_function_pointer(signed_ptr, callbacks[i].discriminator) == NULL ? -1 : 0);
        if (rc != 0)
            aggregatedFlags |= CPRISK_PAC_CFI_FLAG_AUTH_FAILED;

        const uint32_t lastFlags = (uint32_t)atomic_load(&s_last_pac_flags);
        aggregatedFlags |= lastFlags;
        if (rc != 0) {
            validationFailed = true;
        }
    }

    if (validationFailed) {
        aggregatedFlags |= CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED;
    } else {
        aggregatedFlags &= ~CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED;
    }

    atomic_store(&s_last_pac_flags, aggregatedFlags);
    return validationFailed ? 1 : 0;
}

uint32_t cprisk_get_last_pac_cfi_flags(void) {
    return (uint32_t)atomic_load(&s_last_pac_flags);
}
