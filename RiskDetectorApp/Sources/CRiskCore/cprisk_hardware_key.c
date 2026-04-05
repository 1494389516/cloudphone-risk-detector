/*
 * cprisk_hardware_key.c — Layer-2 device-key derivation for Hybrid KDF.
 *
 * Three-layer key derivation:
 *   Layer 1: rootKey       (CLI provided)
 *   Layer 2: deviceKey    = HMAC(rootKey, deviceSalt)
 *   Layer 3: effectiveRoot = HMAC(deviceKey, sessionToken)
 *
 * This file implements Layer-2 (device binding).  Layer-3 (session binding)
 * lives in cprisk_session_token.c.
 *
 * Device salt is sourced from Keychain / IOKit when available; a static
 * fallback salt is used when platform services are unavailable.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_sha256.h"
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <TargetConditionals.h>
#include <sys/utsname.h>
#endif

#if defined(__APPLE__) && TARGET_OS_OSX && !TARGET_OS_MACCATALYST
#include <IOKit/IOKitLib.h>
#endif

/* Fallback device salt used when IOKit/Keychain are unavailable.
 * Encodes "CRISKDEV1.00" — versioned so new deployments can detect
 * and rotate to real hardware roots without a protocol break. */
static const uint8_t s_device_fallback_salt[CPRISK_ARMOR_KEY_SIZE] = {
    0x43, 0x52, 0x49, 0x53, 0x4B, 0x44, 0x45, 0x56,
    0x31, 0x2E, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* 1 when a platform-derived hardware salt was successfully produced, 0 when
 * the static fallback salt is in use. */
static _Atomic int s_device_bound_ready = 0;

/* HMAC-SHA256 wrapper that delegates to the inline definition in
 * cprisk_armor_abi.h, which is transitively included via CRiskCore.h. */
static void cprisk_hmac_sha256_i(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[CPRISK_ARMOR_HASH_SIZE]
) {
    /* cprisk_hmac_sha256 is defined as static inline in cprisk_armor_abi.h */
    cprisk_hmac_sha256(key, key_len, msg, msg_len, out);
}

#if defined(__APPLE__)
static int cprisk_fill_random_i(uint8_t *out, size_t out_len) {
    if (!out || out_len == 0)
        return -1;

    if (SecRandomCopyBytes(kSecRandomDefault, out_len, out) == errSecSuccess)
        return 0;

    if (out_len <= 256) {
        int entropy_err = 0;
        if (cprisk_getentropy_direct(out, out_len, &entropy_err) == 0)
            return 0;
    }
    return -1;
}

static CFMutableDictionaryRef cprisk_create_keychain_query_i(void) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (!query)
        return NULL;

    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR("com.cloudphonerisk.cprisk"));
    CFDictionarySetValue(query, kSecAttrAccount, CFSTR("device-salt.v1"));
    CFDictionarySetValue(query, kSecAttrLabel, CFSTR("cprisk-device-salt"));
    return query;
}

/* Returns:
 *   0: salt loaded
 *   1: key missing
 *  -1: keychain unavailable or invalid data */
static int cprisk_keychain_read_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_salt)
        return -1;

    int rc = -1;
    CFMutableDictionaryRef query = cprisk_create_keychain_query_i();
    if (!query)
        return -1;

    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (status == errSecSuccess && result && CFGetTypeID(result) == CFDataGetTypeID()) {
        CFDataRef data_ref = (CFDataRef)result;
        CFIndex data_len = CFDataGetLength(data_ref);
        if (data_len == CPRISK_ARMOR_KEY_SIZE) {
            memcpy(out_salt, CFDataGetBytePtr(data_ref), CPRISK_ARMOR_KEY_SIZE);
            rc = 0;
        }
    } else if (status == errSecItemNotFound) {
        rc = 1;
    }

    if (result)
        CFRelease(result);
    CFRelease(query);
    return rc;
}

/* Returns:
 *   0: stored
 *   1: duplicate key
 *  -1: add failure */
static int cprisk_keychain_store_salt_i(const uint8_t salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!salt)
        return -1;

    int rc = -1;
    CFMutableDictionaryRef add_query = cprisk_create_keychain_query_i();
    if (!add_query)
        return -1;

    CFDataRef salt_data = CFDataCreate(kCFAllocatorDefault, salt, CPRISK_ARMOR_KEY_SIZE);
    if (!salt_data) {
        CFRelease(add_query);
        return -1;
    }

    CFDictionarySetValue(add_query, kSecValueData, salt_data);
    OSStatus status = SecItemAdd(add_query, NULL);
    if (status == errSecSuccess) {
        rc = 0;
    } else if (status == errSecDuplicateItem) {
        rc = 1;
    }

    CFRelease(salt_data);
    CFRelease(add_query);
    return rc;
}

static int cprisk_get_or_create_keychain_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    int read_rc = cprisk_keychain_read_salt_i(out_salt);
    if (read_rc == 0)
        return 0;
    if (read_rc != 1)
        return -1;

    uint8_t generated_salt[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_fill_random_i(generated_salt, sizeof(generated_salt)) != 0) {
        cprisk_secure_zero(generated_salt, sizeof(generated_salt));
        return -1;
    }

    int store_rc = cprisk_keychain_store_salt_i(generated_salt);
    if (store_rc == 0) {
        memcpy(out_salt, generated_salt, CPRISK_ARMOR_KEY_SIZE);
        cprisk_secure_zero(generated_salt, sizeof(generated_salt));
        return 0;
    }

    cprisk_secure_zero(generated_salt, sizeof(generated_salt));
    if (store_rc == 1) {
        return cprisk_keychain_read_salt_i(out_salt) == 0 ? 0 : -1;
    }
    return -1;
}
#endif

#if defined(__APPLE__)
static void cprisk_sha256_update_tagged_bytes_i(
    cprisk_sha256_ctx *ctx,
    const uint8_t *tag,
    size_t tag_len,
    const uint8_t *bytes,
    size_t len
) {
    if (!ctx || !tag || tag_len == 0)
        return;
    cprisk_sha256_update(ctx, tag, tag_len);
    if (bytes && len > 0) {
        cprisk_sha256_update(ctx, bytes, len);
    }
}

static void cprisk_sha256_update_tagged_cstr_i(
    cprisk_sha256_ctx *ctx,
    const char *tag,
    const char *str
) {
    if (!ctx || !tag || !str || str[0] == '\0')
        return;
    const size_t tag_len = strlen(tag);
    const size_t str_len = strlen(str);
    cprisk_sha256_update_tagged_bytes_i(
        ctx,
        (const uint8_t *)tag,
        tag_len,
        (const uint8_t *)str,
        str_len
    );
}
#endif

#if defined(__APPLE__) && TARGET_OS_OSX && !TARGET_OS_MACCATALYST
static int cprisk_get_ioplatform_uuid_i(char out_uuid[128]) {
    if (!out_uuid)
        return -1;

    out_uuid[0] = '\0';

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("IOPlatformExpertDevice")
    );
    if (service == IO_OBJECT_NULL)
        return -1;

    CFTypeRef uuid_ref = IORegistryEntryCreateCFProperty(
        service,
        CFSTR("IOPlatformUUID"),
        kCFAllocatorDefault,
        0
    );
    IOObjectRelease(service);

    if (!uuid_ref || CFGetTypeID(uuid_ref) != CFStringGetTypeID()) {
        if (uuid_ref)
            CFRelease(uuid_ref);
        return -1;
    }

    Boolean copied = CFStringGetCString(
        (CFStringRef)uuid_ref,
        out_uuid,
        128,
        kCFStringEncodingUTF8
    );
    CFRelease(uuid_ref);
    return (copied && out_uuid[0] != '\0') ? 0 : -1;
}

static int cprisk_mix_device_and_keychain_salt_i(
    const char *platform_uuid,
    const uint8_t keychain_salt[CPRISK_ARMOR_KEY_SIZE],
    uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]
) {
    if (!platform_uuid || !keychain_salt || !out_salt)
        return -1;

    uint8_t uuid_digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx uuid_ctx;
    cprisk_sha256_init(&uuid_ctx);

    static const uint8_t uuid_tag[] = "cprisk.device.uuid.v1";
    cprisk_sha256_update(&uuid_ctx, uuid_tag, sizeof(uuid_tag) - 1);
    cprisk_sha256_update(&uuid_ctx,
                         (const uint8_t *)platform_uuid,
                         strlen(platform_uuid));
    cprisk_sha256_final(&uuid_ctx, uuid_digest);

    static const uint8_t mix_tag[] = "cprisk.device.mix.v1";
    uint8_t mix_input[CPRISK_ARMOR_KEY_SIZE + sizeof(mix_tag) - 1];
    memcpy(mix_input, uuid_digest, CPRISK_ARMOR_KEY_SIZE);
    memcpy(mix_input + CPRISK_ARMOR_KEY_SIZE, mix_tag, sizeof(mix_tag) - 1);

    cprisk_hmac_sha256_i(keychain_salt, CPRISK_ARMOR_KEY_SIZE,
                         mix_input, sizeof(mix_input),
                         out_salt);

    cprisk_secure_zero(uuid_digest, sizeof(uuid_digest));
    cprisk_secure_zero(mix_input, sizeof(mix_input));
    return 0;
}

/* Returns 0 only when the "real" binding path is used:
 * IOPlatformUUID (strong device signal) + keychain persisted salt. */
static int cprisk_get_macos_device_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_salt)
        return -1;

#if !defined(__APPLE__)
    (void)out_salt;
    return -1;
#else
    char platform_uuid[128];
    uint8_t keychain_salt[CPRISK_ARMOR_KEY_SIZE];

    if (cprisk_get_ioplatform_uuid_i(platform_uuid) != 0) {
        cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
        return -1;
    }

    if (cprisk_get_or_create_keychain_salt_i(keychain_salt) != 0) {
        cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
        cprisk_secure_zero(platform_uuid, sizeof(platform_uuid));
        return -1;
    }

    int rc = cprisk_mix_device_and_keychain_salt_i(platform_uuid, keychain_salt, out_salt);
    cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
    cprisk_secure_zero(platform_uuid, sizeof(platform_uuid));
    return rc;
#endif
}
#endif

#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST
static int cprisk_sysctl_string_i(const char *name, char *out, size_t out_len) {
    if (!name || !out || out_len == 0)
        return -1;

    size_t len = out_len;
    int err = 0;
    if (cprisk_sysctlbyname_direct(name, out, &len, NULL, 0, &err) != 0 || len == 0) {
        out[0] = '\0';
        return -1;
    }
    if (len >= out_len) {
        len = out_len - 1;
    }
    out[len] = '\0';
    return 0;
}

static int cprisk_collect_ios_device_fingerprint_i(
    uint8_t out_digest[CPRISK_ARMOR_HASH_SIZE]
) {
    if (!out_digest)
        return -1;

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);

    static const uint8_t root_tag[] = "cprisk.ios.device.v1";
    cprisk_sha256_update(&ctx, root_tag, sizeof(root_tag) - 1);

    struct utsname un;
    memset(&un, 0, sizeof(un));
    if (uname(&un) == 0) {
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.sysname", un.sysname);
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.release", un.release);
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.version", un.version);
        cprisk_sha256_update_tagged_cstr_i(&ctx, "uname.machine", un.machine);
    }

    char hw_machine[128];
    if (cprisk_sysctl_string_i("hw.machine", hw_machine, sizeof(hw_machine)) == 0) {
        cprisk_sha256_update_tagged_cstr_i(&ctx, "hw.machine", hw_machine);
    }

    char hw_model[128];
    if (cprisk_sysctl_string_i("hw.model", hw_model, sizeof(hw_model)) == 0) {
        cprisk_sha256_update_tagged_cstr_i(&ctx, "hw.model", hw_model);
    }

    uint64_t memsize = 0;
    size_t memsize_len = sizeof(memsize);
    int mem_err = 0;
    if (cprisk_sysctlbyname_direct("hw.memsize", &memsize, &memsize_len, NULL, 0, &mem_err) == 0 &&
        memsize_len == sizeof(memsize)) {
        cprisk_sha256_update_tagged_bytes_i(
            &ctx,
            (const uint8_t *)"hw.memsize",
            sizeof("hw.memsize") - 1,
            (const uint8_t *)&memsize,
            sizeof(memsize)
        );
    }

    char bundle_id[256];
    bundle_id[0] = '\0';
    CFBundleRef bundle = CFBundleGetMainBundle();
    if (bundle) {
        CFStringRef ident = CFBundleGetIdentifier(bundle);
        if (ident && CFStringGetCString(ident, bundle_id, sizeof(bundle_id), kCFStringEncodingUTF8)) {
            cprisk_sha256_update_tagged_cstr_i(&ctx, "bundle.id", bundle_id);
        }
    }

    cprisk_sha256_final(&ctx, out_digest);
    cprisk_secure_zero(&ctx, sizeof(ctx));
    cprisk_secure_zero(hw_machine, sizeof(hw_machine));
    cprisk_secure_zero(hw_model, sizeof(hw_model));
    cprisk_secure_zero(bundle_id, sizeof(bundle_id));
    return 0;
}

static int cprisk_get_ios_device_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_salt)
        return -1;

    uint8_t device_digest[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_collect_ios_device_fingerprint_i(device_digest) != 0) {
        return -1;
    }

    uint8_t keychain_salt[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_get_or_create_keychain_salt_i(keychain_salt) != 0) {
        cprisk_secure_zero(device_digest, sizeof(device_digest));
        return -1;
    }

    static const uint8_t mix_tag[] = "cprisk.device.ios.mix.v1";
    uint8_t mix_input[CPRISK_ARMOR_HASH_SIZE + sizeof(mix_tag) - 1];
    memcpy(mix_input, device_digest, CPRISK_ARMOR_HASH_SIZE);
    memcpy(mix_input + CPRISK_ARMOR_HASH_SIZE, mix_tag, sizeof(mix_tag) - 1);

    cprisk_hmac_sha256_i(keychain_salt, CPRISK_ARMOR_KEY_SIZE,
                         mix_input, sizeof(mix_input),
                         out_salt);

    cprisk_secure_zero(device_digest, sizeof(device_digest));
    cprisk_secure_zero(keychain_salt, sizeof(keychain_salt));
    cprisk_secure_zero(mix_input, sizeof(mix_input));
    return 0;
}
#endif

/* Platform-specific device-salt retrieval.
 * Returns 0 on success, -1 on failure.
 * On failure the caller falls back to s_device_fallback_salt. */
static int cprisk_get_device_salt_i(uint8_t out_salt[CPRISK_ARMOR_KEY_SIZE]) {
#if defined(__APPLE__) && TARGET_OS_OSX && !TARGET_OS_MACCATALYST
    return cprisk_get_macos_device_salt_i(out_salt);
#elif defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_MACCATALYST
    return cprisk_get_ios_device_salt_i(out_salt);
#else
    (void)out_salt;
    return -1;
#endif
}

int cprisk_derive_device_key(
    const uint8_t *root_key,
    uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]
) {
    if (!root_key || !out_device_key)
        return -1;

    uint8_t device_salt[CPRISK_ARMOR_KEY_SIZE];

    /* Attempt to retrieve real hardware salt; fall back to static salt. */
    if (cprisk_get_device_salt_i(device_salt) != 0) {
        memcpy(device_salt, s_device_fallback_salt, CPRISK_ARMOR_KEY_SIZE);
        atomic_store(&s_device_bound_ready, 0);
    } else {
        atomic_store(&s_device_bound_ready, 1);
    }

    /* deviceKey = HMAC(rootKey, deviceSalt) */
    cprisk_hmac_sha256_i(root_key, CPRISK_ARMOR_KEY_SIZE,
                         device_salt, CPRISK_ARMOR_KEY_SIZE,
                         out_device_key);

    /* Clear intermediate material from stack. */
    cprisk_secure_zero(device_salt, sizeof(device_salt));

    return 0;
}

int cprisk_is_device_bound(void) {
    return atomic_load(&s_device_bound_ready) ? 1 : 0;
}
