/*
 * cprisk_frida_runtime.c — Multi-channel Frida / Gum runtime hints (iOS arm64).
 *
 * Channels (orthogonal, low FP alone; fused scoring is applied in Swift):
 *  - Loaded image path scan (_dyld_get_image_name)
 *  - dlsym(RTLD_DEFAULT) for Gum/Frida exports when injected
 *  - Process table scan for frida-* comm names (best-effort; may be empty in sandbox)
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

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#endif

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)

static int cprisk_token_in_path(const char *path) {
    if (!path || path[0] == '\0') {
        return 0;
    }
    static const char *const needles[] = {
        "frida",
        "Frida",
        "gum-js",
        "frida-agent",
        "frida-gadget",
        "libgum",
        "frida-server",
    };
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
        if (strstr(path, needles[i]) != NULL) {
            return 1;
        }
    }
    if (strcasestr(path, "gumjs") != NULL) {
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
    static const char *const syms[] = {
        "gum_init",
        "gum_deinit",
        "gum_embed_script",
        "frida_agent_main",
        "gum_script_backend_obtain",
    };
    uint32_t hits = 0;
    for (size_t i = 0; i < sizeof(syms) / sizeof(syms[0]); i++) {
        void *p = dlsym(RTLD_DEFAULT, syms[i]);
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
    if (strncasecmp(comm, "frida", 5) == 0) {
        return 1;
    }
    if (strcasestr(comm, "frida") != NULL) {
        return 1;
    }
    if (strcasestr(comm, "gum-js") != NULL) {
        return 1;
    }
    return 0;
}

static void cprisk_frida_scan_proc_table(uint32_t *flags_out, uint32_t *proc_hits_out) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
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
