/*
 * TLS SPKI SHA-256 pinning helpers (Apple Security.framework).
 * Builds SubjectPublicKeyInfo DER from SecKey external representation to match
 * standard tooling (openssl x509 -pubkey | openssl pkey -pubout -outform der | sha256).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "include/cprisk_sha256.h"

#define CPRISK_PIN_SHA256_DIGEST_LENGTH 32u

/* ASN.1 SPKI headers (same constants as former Swift implementation). */
static const uint8_t k_rsa2048_spki_hdr[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
};
static const uint8_t k_rsa4096_spki_hdr[] = {
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00
};
static const uint8_t k_ec_p256_spki_hdr[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00
};
static const uint8_t k_ec_p384_spki_hdr[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
};

enum {
    CPRISK_PIN_SCOPE_ANY = 0u,
    CPRISK_PIN_SCOPE_LEAF = 1u,
    CPRISK_PIN_SCOPE_INTERMEDIATE = 2u,
};

static int cprisk_spki_der_from_pubkey_bytes_i(
    SecKeyRef key,
    const uint8_t *pub_bytes,
    size_t pub_len,
    uint8_t *out_spki,
    size_t out_cap,
    size_t *out_spki_len
) {
    const uint8_t *hdr = NULL;
    size_t hdr_len = 0u;

    CFDictionaryRef attrs = SecKeyCopyAttributes(key);
    if (attrs != NULL) {
        CFTypeRef type = CFDictionaryGetValue(attrs, kSecAttrKeyType);
        if (type != NULL && CFEqual(type, kSecAttrKeyTypeRSA)) {
            if (pub_len == 270u) {
                hdr = k_rsa2048_spki_hdr;
                hdr_len = sizeof(k_rsa2048_spki_hdr);
            } else if (pub_len == 526u) {
                hdr = k_rsa4096_spki_hdr;
                hdr_len = sizeof(k_rsa4096_spki_hdr);
            }
        } else if (type != NULL && CFEqual(type, kSecAttrKeyTypeECSECPrimeRandom)) {
            if (pub_len == 65u) {
                hdr = k_ec_p256_spki_hdr;
                hdr_len = sizeof(k_ec_p256_spki_hdr);
            } else if (pub_len == 97u) {
                hdr = k_ec_p384_spki_hdr;
                hdr_len = sizeof(k_ec_p384_spki_hdr);
            }
        }
        CFRelease(attrs);
    }

    if (hdr == NULL || hdr_len == 0u) {
        /* Length-only fallback when attributes are unavailable. */
        if (pub_len == 270u) {
            hdr = k_rsa2048_spki_hdr;
            hdr_len = sizeof(k_rsa2048_spki_hdr);
        } else if (pub_len == 526u) {
            hdr = k_rsa4096_spki_hdr;
            hdr_len = sizeof(k_rsa4096_spki_hdr);
        } else if (pub_len == 65u) {
            hdr = k_ec_p256_spki_hdr;
            hdr_len = sizeof(k_ec_p256_spki_hdr);
        } else if (pub_len == 97u) {
            hdr = k_ec_p384_spki_hdr;
            hdr_len = sizeof(k_ec_p384_spki_hdr);
        } else {
            return -1;
        }
    }

    if (hdr_len + pub_len > out_cap) {
        return -1;
    }
    memcpy(out_spki, hdr, hdr_len);
    memcpy(out_spki + hdr_len, pub_bytes, pub_len);
    *out_spki_len = hdr_len + pub_len;
    return 0;
}

int cprisk_spki_sha256_from_sec_certificate(void *sec_certificate_ref, uint8_t out_digest[32]) {
    if (sec_certificate_ref == NULL || out_digest == NULL) {
        return -1;
    }
    SecCertificateRef cert = (SecCertificateRef)sec_certificate_ref;
    SecKeyRef key = SecCertificateCopyKey(cert);
    if (key == NULL) {
        return -2;
    }

    CFErrorRef cf_err = NULL;
    CFDataRef key_data = SecKeyCopyExternalRepresentation(key, &cf_err);
    if (key_data == NULL) {
        if (cf_err != NULL) {
            CFRelease(cf_err);
        }
        CFRelease(key);
        return -3;
    }

    const uint8_t *pub_bytes = CFDataGetBytePtr(key_data);
    size_t pub_len = (size_t)CFDataGetLength(key_data);

    uint8_t spki_buf[640];
    size_t spki_len = 0u;
    int brc = cprisk_spki_der_from_pubkey_bytes_i(key, pub_bytes, pub_len, spki_buf, sizeof(spki_buf), &spki_len);
    CFRelease(key_data);
    CFRelease(key);

    if (brc != 0 || spki_len == 0u) {
        return -4;
    }

    cprisk_sha256(spki_buf, spki_len, out_digest);
    return 0;
}

int cprisk_pinset_match_layered_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count,
    const uint8_t *scopes,
    uint32_t chain_index
) {
    if (candidate_digest == NULL || candidate_len != CPRISK_PIN_SHA256_DIGEST_LENGTH) {
        return -1;
    }
    if (pin_count == 0u) {
        return 0;
    }
    if (packed_pins == NULL || scopes == NULL) {
        return -1;
    }

    uint8_t any_match = 0u;
    size_t pin_index = 0u;
    for (pin_index = 0u; pin_index < pin_count; ++pin_index) {
        const uint8_t *slot = packed_pins + (pin_index * CPRISK_PIN_SHA256_DIGEST_LENGTH);
        uint8_t diff = 0u;
        size_t byte_index = 0u;
        for (byte_index = 0u; byte_index < CPRISK_PIN_SHA256_DIGEST_LENGTH; ++byte_index) {
            diff |= (uint8_t)(candidate_digest[byte_index] ^ slot[byte_index]);
        }
        const uint8_t digest_ok = (uint8_t)(diff == 0u);
        const uint8_t scope = scopes[pin_index];
        uint8_t pos_ok = 0u;
        if (scope == CPRISK_PIN_SCOPE_ANY) {
            pos_ok = 1u;
        } else if (scope == CPRISK_PIN_SCOPE_LEAF) {
            pos_ok = (uint8_t)(chain_index == 0u);
        } else if (scope == CPRISK_PIN_SCOPE_INTERMEDIATE) {
            pos_ok = (uint8_t)(chain_index >= 1u);
        } else {
            pos_ok = 0u;
        }
        any_match |= (uint8_t)(digest_ok & pos_ok);
    }
    return any_match != 0u ? 1 : 0;
}

#else /* !__APPLE__ */

int cprisk_spki_sha256_from_sec_certificate(void *sec_certificate_ref, uint8_t out_digest[32]) {
    (void)sec_certificate_ref;
    (void)out_digest;
    return -4;
}

int cprisk_pinset_match_layered_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count,
    const uint8_t *scopes,
    uint32_t chain_index
) {
    (void)candidate_digest;
    (void)candidate_len;
    (void)packed_pins;
    (void)pin_count;
    (void)scopes;
    (void)chain_index;
    return -1;
}

#endif /* __APPLE__ */
