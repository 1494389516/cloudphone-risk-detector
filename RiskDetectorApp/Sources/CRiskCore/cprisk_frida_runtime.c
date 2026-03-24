/*
 * cprisk_frida_runtime.c — Multi-channel Frida / Gum runtime hints (iOS arm64).
 *
 * Sensitive needles are not stored as contiguous ASCII literals; short tokens are
 * reconstructed with SHA256(label) XOR masks (v1). Plaintext exists only briefly
 * on the stack and is cleared after each scan.
 */

#include "include/CRiskCore.h"

#ifndef CPRISK_FRIDA_RUNTIME_SNAPSHOT_DECLARED
enum {
    CPRISK_FRIDA_RT_IMAGE = 1u << 0,
    CPRISK_FRIDA_RT_DLSYM = 1u << 1,
    CPRISK_FRIDA_RT_PROC = 1u << 2,
};
typedef struct cprisk_frida_runtime_snapshot {
    uint32_t supported;
    uint32_t flags;
    uint32_t image_hit_count;
    uint32_t dlsym_hit_count;
    uint32_t proc_hit_count;
} cprisk_frida_runtime_snapshot_t;
#endif

#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <stdint.h>
#include <strings.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#endif

int cprisk_obf_decode_sha256_label(
    const char *label,
    size_t label_len,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
) {
    if (!label || label_len == 0 || !enc || enc_len == 0 || !out || out_sz <= enc_len) {
        return -1;
    }
    uint8_t mask[32];
    cprisk_sha256((const uint8_t *)label, label_len, mask);
    for (size_t i = 0; i < enc_len; i++) {
        out[i] = (char)(enc[i] ^ mask[i % 32u]);
    }
    out[enc_len] = '\0';
    return 0;
}

int cprisk_obf_decode_sha256_tag(
    uint32_t domain,
    uint32_t key_id,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
) {
    if (!enc || enc_len == 0 || !out || out_sz <= enc_len) {
        return -1;
    }
    uint8_t tag[8];
    tag[0] = (uint8_t)(domain & 0xffu);
    tag[1] = (uint8_t)((domain >> 8) & 0xffu);
    tag[2] = (uint8_t)((domain >> 16) & 0xffu);
    tag[3] = (uint8_t)((domain >> 24) & 0xffu);
    tag[4] = (uint8_t)(key_id & 0xffu);
    tag[5] = (uint8_t)((key_id >> 8) & 0xffu);
    tag[6] = (uint8_t)((key_id >> 16) & 0xffu);
    tag[7] = (uint8_t)((key_id >> 24) & 0xffu);
    uint8_t mask[32];
    cprisk_sha256(tag, sizeof(tag), mask);
    for (size_t i = 0; i < enc_len; i++) {
        out[i] = (char)(enc[i] ^ mask[i % 32u]);
    }
    out[enc_len] = '\0';
    return 0;
}

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)

static int cprisk_frida_path_needle_hit_i(
    const char *path,
    uint32_t domain,
    uint32_t key_id,
    const uint8_t *enc,
    size_t enc_len
) {
    char buf[96];
    if (enc_len + 1u > sizeof(buf)) {
        return 0;
    }
    if (cprisk_obf_decode_sha256_tag(domain, key_id, enc, enc_len, buf, sizeof(buf)) != 0) {
        return 0;
    }
    const int hit = (strstr(path, buf) != NULL) ? 1 : 0;
    cprisk_secure_zero(buf, sizeof(buf));
    return hit;
}

static int cprisk_token_in_path(const char *path) {
    if (!path || path[0] == '\0') {
        return 0;
    }
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_FRIDA_RT;
    static const uint8_t e_frida[] = {0xad, 0x0c, 0x6f, 0xa8, 0x2c};
    static const uint8_t e_frida_cap[] = {0x04, 0x5e, 0x3c, 0x4f, 0xf8};
    static const uint8_t e_gum_js[] = {0xfa, 0x53, 0x66, 0x5a, 0x2e, 0x64};
    static const uint8_t e_agent[] = {
        0x85, 0x46, 0xc9, 0x61, 0xb0, 0x93, 0xa2, 0xf6, 0xf8, 0x85, 0x08};
    static const uint8_t e_gadget[] = {
        0x2d, 0xf1, 0x1f, 0x72, 0x48, 0x9a, 0xfb, 0x9f, 0xb5, 0x16, 0x4a, 0xcc};
    static const uint8_t e_libgum[] = {0xce, 0x86, 0xa1, 0x7c, 0xd3, 0xac};
    static const uint8_t e_server[] = {
        0xe7, 0x62, 0x5c, 0x95, 0x5e, 0x0f, 0x7f, 0x20, 0x52, 0xef, 0xf3, 0xce};
    static const uint8_t e_gumjs_compact[] = {0x8e, 0xca, 0xa1, 0xd3, 0x71};

    if (cprisk_frida_path_needle_hit_i(path, D, 1u, e_frida, sizeof(e_frida)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 2u, e_frida_cap, sizeof(e_frida_cap)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 3u, e_gum_js, sizeof(e_gum_js)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 4u, e_agent, sizeof(e_agent)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 5u, e_gadget, sizeof(e_gadget)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 6u, e_libgum, sizeof(e_libgum)))
        return 1;
    if (cprisk_frida_path_needle_hit_i(path, D, 7u, e_server, sizeof(e_server)))
        return 1;

    char gumjs_buf[16];
    if (cprisk_obf_decode_sha256_tag(D, 8u, e_gumjs_compact, sizeof(e_gumjs_compact), gumjs_buf, sizeof(gumjs_buf)) ==
        0) {
        const int gj = (strcasestr(path, gumjs_buf) != NULL) ? 1 : 0;
        cprisk_secure_zero(gumjs_buf, sizeof(gumjs_buf));
        if (gj)
            return 1;
    }
    return 0;
}

static void cprisk_frida_scan_dyld_images(uint32_t *flags_out, uint32_t *image_hits_out) {
    uint32_t hits = 0;
    const uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) {
            continue;
        }
        if (cprisk_token_in_path(name)) {
            hits++;
        }
    }
    if (hits > 0 && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_IMAGE;
    }
    if (image_hits_out) {
        *image_hits_out = hits;
    }
}

static void cprisk_frida_scan_dlsym(uint32_t *flags_out, uint32_t *dlsym_hits_out) {
    static const uint8_t e_gum_init[] = {0x76, 0x13, 0xf9, 0x65, 0x84, 0x20, 0xb7, 0x32};
    static const uint8_t e_gum_deinit[] = {0x34, 0xd0, 0x1a, 0x54, 0xeb, 0x42, 0xaa, 0xb6, 0xc5, 0xaa};
    static const uint8_t e_gum_embed[] = {
        0xea, 0x26, 0x7b, 0xb3, 0xf1, 0xbc, 0x28, 0xb3, 0x94, 0xc3, 0xc8, 0xa5, 0x26, 0x60, 0x9f, 0x8a};
    static const uint8_t e_agent_main[] = {
        0x7b, 0xdf, 0x48, 0x0b, 0x44, 0x1c, 0x74, 0x68, 0x97, 0x12, 0xaf, 0x94, 0x83, 0x21, 0xfd, 0x09};
    static const uint8_t e_gum_backend[] = {
        0x8e, 0xa1, 0x00, 0xf2, 0x08, 0xe7, 0xab, 0xf4, 0xdd, 0x8f, 0x2d, 0x59, 0xbc, 0x05, 0x72, 0x42,
        0x04, 0x4b, 0x65, 0x8f, 0x31, 0x2b, 0x26, 0xd2, 0x99};

    static const struct {
        uint32_t key_id;
        const uint8_t *enc;
        size_t enc_len;
    } rows[] = {
        {16u, e_gum_init, sizeof(e_gum_init)},
        {17u, e_gum_deinit, sizeof(e_gum_deinit)},
        {18u, e_gum_embed, sizeof(e_gum_embed)},
        {19u, e_agent_main, sizeof(e_agent_main)},
        {20u, e_gum_backend, sizeof(e_gum_backend)},
    };

    uint32_t hits = 0;
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_FRIDA_RT;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char sym[40];
        if (rows[i].enc_len + 1u > sizeof(sym)) {
            continue;
        }
        if (cprisk_obf_decode_sha256_tag(
                D,
                rows[i].key_id,
                rows[i].enc,
                rows[i].enc_len,
                sym,
                sizeof(sym)) != 0) {
            continue;
        }
        void *p = dlsym(RTLD_DEFAULT, sym);
        cprisk_secure_zero(sym, sizeof(sym));
        if (p != NULL) {
            hits++;
        }
    }
    if (hits > 0 && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_DLSYM;
    }
    if (dlsym_hits_out) {
        *dlsym_hits_out = hits;
    }
}

static int cprisk_comm_looks_like_frida(const char *comm) {
    if (!comm || comm[0] == '\0') {
        return 0;
    }
    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_FRIDA_RT;
    static const uint8_t e_frida[] = {0xad, 0x0c, 0x6f, 0xa8, 0x2c};
    static const uint8_t e_gum_js[] = {0xfa, 0x53, 0x66, 0x5a, 0x2e, 0x64};

    char fr[16];
    char gj[16];
    if (cprisk_obf_decode_sha256_tag(D, 1u, e_frida, sizeof(e_frida), fr, sizeof(fr)) != 0) {
        return 0;
    }
    if (cprisk_obf_decode_sha256_tag(D, 3u, e_gum_js, sizeof(e_gum_js), gj, sizeof(gj)) != 0) {
        cprisk_secure_zero(fr, sizeof(fr));
        return 0;
    }

    int hit = 0;
    if (strncasecmp(comm, fr, strlen(fr)) == 0) {
        hit = 1;
    } else if (strcasestr(comm, fr) != NULL) {
        hit = 1;
    } else if (strcasestr(comm, gj) != NULL) {
        hit = 1;
    }
    cprisk_secure_zero(fr, sizeof(fr));
    cprisk_secure_zero(gj, sizeof(gj));
    return hit;
}

static void cprisk_frida_scan_proc_table(uint32_t *flags_out, uint32_t *proc_hits_out) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t buf_size = 0;
    int err = 0;
    if (cprisk_sysctl_direct(mib, 4, NULL, &buf_size, NULL, 0, &err) != 0) {
        return;
    }
    if (buf_size < sizeof(struct kinfo_proc) || buf_size > 32u * 1024u * 1024u) {
        return;
    }
    uint8_t *buf = (uint8_t *)malloc(buf_size);
    if (!buf) {
        return;
    }
    size_t len = buf_size;
    if (cprisk_sysctl_direct(mib, 4, buf, &len, NULL, 0, &err) != 0) {
        free(buf);
        return;
    }
    size_t count = len / sizeof(struct kinfo_proc);
    struct kinfo_proc *kp = (struct kinfo_proc *)buf;
    uint32_t hits = 0;
    for (size_t i = 0; i < count; i++) {
        if (cprisk_comm_looks_like_frida(kp[i].kp_proc.p_comm)) {
            hits++;
        }
    }
    free(buf);
    if (hits > 0 && flags_out) {
        *flags_out |= CPRISK_FRIDA_RT_PROC;
    }
    if (proc_hits_out) {
        *proc_hits_out = hits;
    }
}

#endif /* Apple device */

int cprisk_frida_runtime_snapshot(cprisk_frida_runtime_snapshot_t *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    out->supported = 1u;
    uint32_t flags = 0u;
    cprisk_frida_scan_dyld_images(&flags, &out->image_hit_count);
    cprisk_frida_scan_dlsym(&flags, &out->dlsym_hit_count);
    cprisk_frida_scan_proc_table(&flags, &out->proc_hit_count);
    out->flags = flags;
#else
    out->supported = 0u;
#endif
    return 0;
}
