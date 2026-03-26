/*
 * CRiskCore — __TEXT.__text page encryption consumer (cprisk-armor pass 12).
 * Fail-closed: invalid metadata disables the feature without crashing loops.
 * HMAC / content-hash failure: integrity poison + trap-filled page (brk) to
 * avoid infinite EXC_BAD_ACCESS retries on the same faulting PC.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_armor_abi.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int cprisk_armor_xor_region(uint8_t *target, size_t sz, uint32_t key_id,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *key);
extern void cprisk_armor_derive_chained_key(const uint8_t *parent_key,
                                            uint32_t section_index,
                                            const uint8_t *nonce,
                                            size_t nonce_len,
                                            uint8_t depth,
                                            uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);
/* Uses loader hidden mprotect: POSIX syscall + Mach vm_region/vm_protect cross-check (cprisk_data_loader.c). */
extern int cprisk_armor_vm_protect(void *addr, size_t len, int prot);

/* Domain 4 = ArmorABI.WhiteBox.Domain.loaderKey — non-hybrid PRF (domains 1–5 bypass
 * effectiveRoot binding). Must match TextSegmentEncryptor mask + XOR mix. */
#define CPRISK_TEXT_WB_MASK_DOMAIN 4u

static void cprisk_text_mask_prf_input_i(uint32_t section_index,
                                         const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
                                         uint8_t out32[32]) {
    static const uint8_t k_label[] = "CPRISK_WB_TEXT_MASK_v1";
    uint8_t msg[sizeof(k_label) - 1u + 4u + CPRISK_ARMOR_NONCE_SIZE];
    memcpy(msg, k_label, sizeof(k_label) - 1u);
    msg[sizeof(k_label) - 1u + 0] = (uint8_t)(section_index);
    msg[sizeof(k_label) - 1u + 1] = (uint8_t)(section_index >> 8);
    msg[sizeof(k_label) - 1u + 2] = (uint8_t)(section_index >> 16);
    msg[sizeof(k_label) - 1u + 3] = (uint8_t)(section_index >> 24);
    memcpy(msg + sizeof(k_label) - 1u + 4u, nonce, CPRISK_ARMOR_NONCE_SIZE);
    cprisk_sha256(msg, sizeof(msg), out32);
    cprisk_secure_zero(msg, sizeof(msg));
}

/* section_key = chained_key XOR WB_PRF(domain4, SHA256(label||section_index||nonce)).
 * Hooks on cprisk_armor_derive_chained_key alone no longer yield the XOR keystream key. */
static int cprisk_text_derive_section_key_i(const uint8_t parent_key[CPRISK_ARMOR_KEY_SIZE],
                                          uint32_t section_index,
                                          const uint8_t *nonce,
                                          size_t nonce_len,
                                          uint8_t depth,
                                          uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    uint8_t chain[CPRISK_ARMOR_KEY_SIZE];
    uint8_t wb_in[32];
    uint8_t wb_out[32];

    cprisk_armor_derive_chained_key(parent_key, section_index, nonce, nonce_len, depth,
                                    chain);
    cprisk_text_mask_prf_input_i(section_index, nonce, wb_in);
    if (cprisk_whitebox_evaluate_domain(CPRISK_TEXT_WB_MASK_DOMAIN, wb_in, wb_out) != 0) {
        cprisk_secure_zero(chain, sizeof(chain));
        cprisk_secure_zero(wb_in, sizeof(wb_in));
        cprisk_secure_zero(wb_out, sizeof(wb_out));
        return -1;
    }
    for (size_t i = 0; i < CPRISK_ARMOR_KEY_SIZE; i++)
        out_key[i] = (uint8_t)(chain[i] ^ wb_out[i]);
    cprisk_secure_zero(chain, sizeof(chain));
    cprisk_secure_zero(wb_in, sizeof(wb_in));
    cprisk_secure_zero(wb_out, sizeof(wb_out));
    return 0;
}

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

#define CPRISK_TEXT_PAGE_SIZE 4096u
/* Idle re-encrypt eligibility: min time a page may stay decrypted before XOR+PROT_NONE.
 * Hot __TEXT can remain fault-free for long stretches; pair with watchdog idle cadence
 * (primary + secondary) so plaintext is not gated only on ~1 Hz ticks. */
/* Tighter idle re-encrypt: reduce plaintext dwell between JIT decrypt and service_idle sweep. */
#define CPRISK_TEXT_RECRYPT_NS 32000000ull
#define CPRISK_TEXT_SECTION_INDEX_BASE 100000u

static pthread_mutex_t s_text_mutex = PTHREAD_MUTEX_INITIALIZER;
static mach_timebase_info_data_t s_timebase;
static pthread_once_t s_tb_once = PTHREAD_ONCE_INIT;

static uint8_t s_parent_key[CPRISK_ARMOR_KEY_SIZE];
static int s_parent_ready;

static struct cprisk_text_encrypt_entry *s_entries = NULL;
static uint32_t s_entry_count;
static uint8_t *s_poison = NULL;
static uint8_t *s_decrypted = NULL;
static uint64_t *s_decrypt_ticks = NULL;

static int s_text_honeypot_armed;
static void *s_text_honeypot_page;

static void cprisk_text_timebase_once(void) {
    (void)mach_timebase_info(&s_timebase);
}

static uint64_t cprisk_text_ticks_to_ns(uint64_t delta_ticks) {
    (void)pthread_once(&s_tb_once, cprisk_text_timebase_once);
    if (s_timebase.denom == 0)
        return 0;
    uint64_t numer = (uint64_t)s_timebase.numer;
    uint64_t denom = (uint64_t)s_timebase.denom;
    return delta_ticks / denom * numer + (delta_ticks % denom) * numer / denom;
}

static const struct mach_header_64 *cprisk_text_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_text_own_hdr);
}

static int cprisk_text_page_span(uint8_t *target, size_t sz, void **page_out, size_t *len_out) {
    if (!target || sz == 0 || !page_out || !len_out)
        return -1;
    if ((uintptr_t)target > UINTPTR_MAX - sz)
        return -1;
    if ((uintptr_t)target + sz > UINTPTR_MAX - 0xFFF)
        return -1;
    uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
    uintptr_t end = ((uintptr_t)target + sz + 0xFFF) & ~(uintptr_t)0xFFF;
    *page_out = (void *)page;
    *len_out = (size_t)(end - page);
    return 0;
}

static int cprisk_text_validate_bounds(
    const struct mach_header_64 *hdr,
    const struct cprisk_text_encrypt_entry *ent
) {
    if (!hdr || !ent)
        return -1;
    /* Build-time Pass 12 may emit a tail descriptor shorter than 4 KiB when
     * __TEXT.__text is not page-aligned on disk. Runtime only requires the
     * entry to start on a page boundary and stay fully inside __TEXT.__text. */
    if (ent->size == 0)
        return -1;
    if (ent->vm_addr % CPRISK_TEXT_PAGE_SIZE != 0)
        return -1;

    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize == 0 || cursor + lc->cmdsize > end)
            break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strncmp(seg->segname, "__TEXT", 16) != 0) {
                cursor += lc->cmdsize;
                continue;
            }
            const struct section_64 *sections =
                (const struct section_64 *)(cursor + sizeof(*seg));
            for (uint32_t s = 0; s < seg->nsects; s++) {
                const struct section_64 *sec = &sections[s];
                if (strncmp(sec->sectname, "__text", 16) != 0)
                    continue;
                if ((seg->initprot & VM_PROT_EXECUTE) == 0)
                    return -1;
                uint64_t lo = sec->addr;
                uint64_t hi = sec->addr + sec->size;
                uint64_t e0 = ent->vm_addr;
                uint64_t e1 = ent->vm_addr + ent->size;
                if (e0 >= lo && e1 <= hi && e1 >= e0)
                    return 0;
                return -1;
            }
        }
        cursor += lc->cmdsize;
    }
    return -1;
}

static int cprisk_text_parse_descriptor(
    const uint8_t *sec,
    unsigned long sec_sz,
    uint32_t *count_out
) {
    if (!sec || !count_out || sec_sz < sizeof(struct cprisk_text_encrypt_header))
        return -1;
    const struct cprisk_text_encrypt_header *h = (const struct cprisk_text_encrypt_header *)sec;
    if (h->magic != CPRISK_TEXT_ENCRYPT_MAGIC || h->version != CPRISK_TEXT_ENCRYPT_ABI_VERSION)
        return -1;
    if (h->count > CPRISK_MAX_ENTRY_COUNT)
        return -1;
    size_t need = sizeof(struct cprisk_text_encrypt_header) +
                  (size_t)h->count * sizeof(struct cprisk_text_encrypt_entry);
    if (need > (size_t)sec_sz)
        return -1;
    *count_out = h->count;
    return 0;
}

static int cprisk_text_plain_hash_ok(
    const uint8_t *ptr,
    size_t sz,
    const uint8_t *expect_content_hash
) {
    uint8_t plain_hash[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(ptr, sz, plain_hash);
    int bad = memcmp(plain_hash, expect_content_hash, CPRISK_ARMOR_HASH_SIZE) != 0;
    cprisk_secure_zero(plain_hash, sizeof(plain_hash));
    return bad ? -1 : 0;
}

static void cprisk_text_honeypot_disarm(void) {
    if (!s_text_honeypot_armed || !s_text_honeypot_page)
        return;
    cprisk_unregister_text_honeypot_page();
    (void)cprisk_armor_vm_protect(s_text_honeypot_page, CPRISK_TEXT_PAGE_SIZE, PROT_READ | PROT_EXEC);
    s_text_honeypot_armed = 0;
    s_text_honeypot_page = NULL;
}

/*
 * Replace the build-time zero pad with high-entropy bytes before PROT_NONE so
 * static "all-zero honeypot page" signatures and fixed vm_protect + size
 * heuristics are less reliable for Frida bypass scripts.
 */
static void cprisk_text_honeypot_fill_entropy_i(void *page) {
    uint8_t *p = (uint8_t *)page;
    uint8_t buf[128];
    int err = 0;
    size_t off = 0;
    uint64_t mix = (uint64_t)(uintptr_t)page ^ (uint64_t)mach_absolute_time();
    while (off < CPRISK_TEXT_PAGE_SIZE) {
        size_t n = CPRISK_TEXT_PAGE_SIZE - off;
        if (n > sizeof(buf)) {
            n = sizeof(buf);
        }
        if (cprisk_getentropy_direct(buf, n, &err) != 0) {
            for (size_t i = 0; i < n; i++) {
                mix = mix * 6364136223846793005ULL + 1ULL;
                buf[i] = (uint8_t)(mix >> 56);
            }
        }
        memcpy(p + off, buf, n);
        cprisk_secure_zero(buf, sizeof(buf));
        off += n;
    }
}

static void cprisk_text_honeypot_arm(const struct mach_header_64 *hdr) {
    cprisk_text_honeypot_disarm();
    if (!hdr)
        return;
    unsigned long psz = 0;
    const uint8_t *p = cprisk_find_section(hdr, "__TEXT", "__cprisk_pad", &psz);
    if (!p || psz < CPRISK_TEXT_PAGE_SIZE)
        return;
    if (((uintptr_t)p % CPRISK_TEXT_PAGE_SIZE) != 0)
        return;
    void *page = (void *)(uintptr_t)p;
    if (cprisk_armor_vm_protect(page, CPRISK_TEXT_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0)
        return;
    cprisk_text_honeypot_fill_entropy_i(page);
    if (cprisk_armor_vm_protect(page, CPRISK_TEXT_PAGE_SIZE, PROT_NONE) != 0) {
        (void)cprisk_armor_vm_protect(page, CPRISK_TEXT_PAGE_SIZE, PROT_READ | PROT_EXEC);
        return;
    }
    if (cprisk_register_text_honeypot_page(page, CPRISK_TEXT_PAGE_SIZE) != 0) {
        (void)cprisk_armor_vm_protect(page, CPRISK_TEXT_PAGE_SIZE, PROT_READ | PROT_EXEC);
        return;
    }
    s_text_honeypot_armed = 1;
    s_text_honeypot_page = page;
}

static void cprisk_text_fill_poison_brk(uint8_t *ptr, size_t sz) {
    uint32_t brk0 = 0xD4200000u;
    size_t i = 0;
    for (; i + 4 <= sz; i += 4) {
        memcpy(ptr + i, &brk0, sizeof(brk0));
    }
    for (; i < sz; i++)
        ptr[i] = 0;
}

static void cprisk_text_poison_entry(
    uint8_t *ptr,
    size_t sz,
    void *page,
    size_t span
) {
    if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) != 0) {
        cprisk_integrity_poison_text_encrypt_lane();
        return;
    }
    cprisk_text_fill_poison_brk(ptr, sz);
    if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC) != 0)
        cprisk_integrity_poison_text_encrypt_lane();
}

static void cprisk_text_maybe_reencrypt_idle(uint64_t now_ticks) {
    if (!s_entries || !s_decrypted || !s_decrypt_ticks || !s_poison)
        return;
    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr)
        return;
    intptr_t slide = cprisk_compute_slide(hdr);

    for (uint32_t i = 0; i < s_entry_count; i++) {
        if (!s_decrypted[i] || s_poison[i])
            continue;
        uint64_t dt = now_ticks - s_decrypt_ticks[i];
        if (cprisk_text_ticks_to_ns(dt) < CPRISK_TEXT_RECRYPT_NS)
            continue;

        const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
        uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
        void *page = NULL;
        size_t span = 0;
        if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;

        unsigned long text_sz = 0;
        const uint8_t *text_base = cprisk_find_section(hdr, "__TEXT", "__text", &text_sz);
        if (!text_base || text_sz < ent->size)
            continue;
        uintptr_t text_lo = (uintptr_t)text_base;
        if ((uintptr_t)ptr < text_lo)
            continue;
        uint32_t page_idx = (uint32_t)(((uintptr_t)ptr - text_lo) / CPRISK_TEXT_PAGE_SIZE);
        uint32_t section_index = CPRISK_TEXT_SECTION_INDEX_BASE + page_idx;

        uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
        if (cprisk_text_derive_section_key_i(
                s_parent_key,
                section_index,
                ent->nonce,
                CPRISK_ARMOR_NONCE_SIZE,
                1,
                section_key) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }

        if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        if (cprisk_text_plain_hash_ok(ptr, (size_t)ent->size, ent->content_hash) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        (void)cprisk_armor_xor_region(
            ptr,
            (size_t)ent->size,
            ent->key_id,
            ent->nonce,
            CPRISK_ARMOR_NONCE_SIZE,
            section_key);
        cprisk_secure_zero(section_key, sizeof(section_key));
        if (cprisk_armor_vm_protect(page, span, PROT_NONE) != 0)
            cprisk_integrity_poison_text_encrypt_lane();
        s_decrypted[i] = 0;
    }
}

static void cprisk_text_encrypt_release_locked(void) {
    cprisk_text_honeypot_disarm();

    if (!s_parent_ready)
        return;

    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    intptr_t slide = hdr ? cprisk_compute_slide(hdr) : 0;

    if (hdr && s_entries && s_entry_count > 0 && s_decrypted && s_poison) {
        for (uint32_t i = 0; i < s_entry_count; i++) {
            if (s_poison[i])
                continue;
            if (!s_decrypted[i])
                continue;
            const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
            uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
            void *page = NULL;
            size_t span = 0;
            if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) != 0)
                continue;

            unsigned long text_sz = 0;
            const uint8_t *text_base = cprisk_find_section(hdr, "__TEXT", "__text", &text_sz);
            uint32_t page_idx = 0;
            if (text_base && (uintptr_t)ptr >= (uintptr_t)text_base)
                page_idx = (uint32_t)(((uintptr_t)ptr - (uintptr_t)text_base) / CPRISK_TEXT_PAGE_SIZE);
            uint32_t section_index = CPRISK_TEXT_SECTION_INDEX_BASE + page_idx;

            uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
            if (cprisk_text_derive_section_key_i(
                    s_parent_key,
                    section_index,
                    ent->nonce,
                    CPRISK_ARMOR_NONCE_SIZE,
                    1,
                    section_key) != 0) {
                cprisk_integrity_poison_text_encrypt_lane();
                continue;
            }

            if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) == 0) {
                if (cprisk_text_plain_hash_ok(ptr, (size_t)ent->size, ent->content_hash) != 0) {
                    cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
                    s_poison[i] = 1;
                    cprisk_integrity_poison_text_encrypt_lane();
                } else {
                    (void)cprisk_armor_xor_region(
                        ptr,
                        (size_t)ent->size,
                        ent->key_id,
                        ent->nonce,
                        CPRISK_ARMOR_NONCE_SIZE,
                        section_key);
                    (void)cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC);
                }
            } else {
                (void)cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC);
            }
            cprisk_secure_zero(section_key, sizeof(section_key));
        }
    }

    free(s_entries);
    free(s_poison);
    free(s_decrypted);
    free(s_decrypt_ticks);
    s_entries = NULL;
    s_poison = NULL;
    s_decrypted = NULL;
    s_decrypt_ticks = NULL;
    s_entry_count = 0;
    cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
    s_parent_ready = 0;
}

void cprisk_text_encrypt_install(const uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE]) {
    pthread_mutex_lock(&s_text_mutex);
    cprisk_text_encrypt_release_locked();

    if (!loader_key) {
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    memcpy(s_parent_key, loader_key, CPRISK_ARMOR_KEY_SIZE);
    s_parent_ready = 1;

    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr) {
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_TEXT_ENCRYPT,
        &sec_sz);
    uint32_t count = 0;
    if (!sec || cprisk_text_parse_descriptor(sec, sec_sz, &count) != 0) {
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    if (count == 0) {
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    const struct cprisk_text_encrypt_entry *src =
        (const struct cprisk_text_encrypt_entry *)(sec + sizeof(struct cprisk_text_encrypt_header));

    s_entries = (struct cprisk_text_encrypt_entry *)calloc((size_t)count, sizeof(struct cprisk_text_encrypt_entry));
    s_poison = (uint8_t *)calloc((size_t)count, 1);
    s_decrypted = (uint8_t *)calloc((size_t)count, 1);
    s_decrypt_ticks = (uint64_t *)calloc((size_t)count, sizeof(uint64_t));
    if (!s_entries || !s_poison || !s_decrypted || !s_decrypt_ticks) {
        free(s_entries);
        free(s_poison);
        free(s_decrypted);
        free(s_decrypt_ticks);
        s_entries = NULL;
        s_poison = NULL;
        s_decrypted = NULL;
        s_decrypt_ticks = NULL;
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
        pthread_mutex_unlock(&s_text_mutex);
        return;
    }

    intptr_t slide = cprisk_compute_slide(hdr);
    uint32_t installed = 0;

    for (uint32_t i = 0; i < count; i++) {
        struct cprisk_text_encrypt_entry ent = src[i];
        if (cprisk_text_validate_bounds(hdr, &ent) != 0)
            continue;

        uint8_t *ptr = (uint8_t *)((uintptr_t)ent.vm_addr + (uintptr_t)slide);
        void *page = NULL;
        size_t span = 0;
        if (cprisk_text_page_span(ptr, (size_t)ent.size, &page, &span) != 0)
            continue;

        if (cprisk_armor_vm_protect(page, span, PROT_NONE) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            continue;
        }
        memcpy(&s_entries[installed], &ent, sizeof(ent));
        installed++;
    }

    s_entry_count = installed;
    if (installed == 0) {
        free(s_entries);
        free(s_poison);
        free(s_decrypted);
        free(s_decrypt_ticks);
        s_entries = NULL;
        s_poison = NULL;
        s_decrypted = NULL;
        s_decrypt_ticks = NULL;
        cprisk_secure_zero(s_parent_key, sizeof(s_parent_key));
        s_parent_ready = 0;
    } else {
        cprisk_text_honeypot_arm(hdr);
    }

    pthread_mutex_unlock(&s_text_mutex);
}

void cprisk_text_encrypt_service_idle(void) {
    pthread_mutex_lock(&s_text_mutex);
    cprisk_text_maybe_reencrypt_idle(mach_absolute_time());
    pthread_mutex_unlock(&s_text_mutex);
}

void cprisk_text_encrypt_uninstall(void) {
    pthread_mutex_lock(&s_text_mutex);
    cprisk_text_encrypt_release_locked();
    pthread_mutex_unlock(&s_text_mutex);
}

int cprisk_text_jit_decrypt(void *fault_addr) {
    if (!fault_addr || !s_parent_ready || !s_entries || s_entry_count == 0)
        return 0;

    pthread_mutex_lock(&s_text_mutex);
    uint64_t now = mach_absolute_time();
    cprisk_text_maybe_reencrypt_idle(now);

    const struct mach_header_64 *hdr = cprisk_text_own_hdr();
    if (!hdr) {
        pthread_mutex_unlock(&s_text_mutex);
        return 0;
    }
    intptr_t slide = cprisk_compute_slide(hdr);

    for (uint32_t i = 0; i < s_entry_count; i++) {
        const struct cprisk_text_encrypt_entry *ent = &s_entries[i];
        uint8_t *ptr = (uint8_t *)((uintptr_t)ent->vm_addr + (uintptr_t)slide);
        void *page = NULL;
        size_t span = 0;
        if (cprisk_text_page_span(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;

        if ((uintptr_t)fault_addr < (uintptr_t)page ||
            (uintptr_t)fault_addr >= (uintptr_t)page + span)
            continue;

        if (s_poison[i]) {
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }

        if (s_decrypted[i]) {
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }

        if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_WRITE) != 0) {
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }

        unsigned long text_sz = 0;
        const uint8_t *text_base = cprisk_find_section(hdr, "__TEXT", "__text", &text_sz);
        uint32_t page_idx = 0;
        if (text_base && (uintptr_t)ptr >= (uintptr_t)text_base)
            page_idx = (uint32_t)(((uintptr_t)ptr - (uintptr_t)text_base) / CPRISK_TEXT_PAGE_SIZE);
        uint32_t section_index = CPRISK_TEXT_SECTION_INDEX_BASE + page_idx;

        uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
        if (cprisk_text_derive_section_key_i(
                s_parent_key,
                section_index,
                ent->nonce,
                CPRISK_ARMOR_NONCE_SIZE,
                1,
                section_key) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            (void)cprisk_armor_vm_protect(page, span, PROT_NONE);
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }

        if (ent->size > SIZE_MAX - CPRISK_ARMOR_NONCE_SIZE) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }
        size_t hmac_msg_len = CPRISK_ARMOR_NONCE_SIZE + (size_t)ent->size;
        uint8_t *hmac_msg = (uint8_t *)malloc(hmac_msg_len);
        if (!hmac_msg) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            (void)cprisk_armor_vm_protect(page, span, PROT_NONE);
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }
        memcpy(hmac_msg, ent->nonce, CPRISK_ARMOR_NONCE_SIZE);
        memcpy(hmac_msg + CPRISK_ARMOR_NONCE_SIZE, ptr, (size_t)ent->size);
        uint8_t computed_hmac[CPRISK_ARMOR_HASH_SIZE];
        cprisk_hmac_sha256(section_key, CPRISK_ARMOR_KEY_SIZE, hmac_msg, hmac_msg_len, computed_hmac);
        cprisk_secure_zero(hmac_msg, hmac_msg_len);
        free(hmac_msg);

        if (cprisk_hmac_verify(ent->hmac_tag, computed_hmac, CPRISK_ARMOR_HASH_SIZE) != 0) {
            cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
            cprisk_secure_zero(section_key, sizeof(section_key));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }
        cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));

        if (cprisk_armor_xor_region(
                ptr,
                (size_t)ent->size,
                ent->key_id,
                ent->nonce,
                CPRISK_ARMOR_NONCE_SIZE,
                section_key) != 0) {
            cprisk_secure_zero(section_key, sizeof(section_key));
            (void)cprisk_armor_vm_protect(page, span, PROT_NONE);
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }
        cprisk_secure_zero(section_key, sizeof(section_key));

        uint8_t plain_hash[CPRISK_SHA256_DIGEST_LENGTH];
        cprisk_sha256(ptr, (size_t)ent->size, plain_hash);
        if (memcmp(plain_hash, ent->content_hash, CPRISK_ARMOR_HASH_SIZE) != 0) {
            cprisk_secure_zero(plain_hash, sizeof(plain_hash));
            cprisk_text_poison_entry(ptr, (size_t)ent->size, page, span);
            s_poison[i] = 1;
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 1;
        }
        cprisk_secure_zero(plain_hash, sizeof(plain_hash));

        if (cprisk_armor_vm_protect(page, span, PROT_READ | PROT_EXEC) != 0) {
            cprisk_integrity_poison_text_encrypt_lane();
            pthread_mutex_unlock(&s_text_mutex);
            return 0;
        }

        s_decrypted[i] = 1;
        s_decrypt_ticks[i] = now;
        pthread_mutex_unlock(&s_text_mutex);
        return 1;
    }

    pthread_mutex_unlock(&s_text_mutex);
    return 0;
}

int cprisk_text_on_demand_decrypt(void *fault_addr) {
    return cprisk_text_jit_decrypt(fault_addr);
}

#else /* Simulator / non-arm64 Apple targets */

void cprisk_text_encrypt_install(const uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE]) {
    (void)loader_key;
}

void cprisk_text_encrypt_uninstall(void) {}

void cprisk_text_encrypt_service_idle(void) {}

int cprisk_text_jit_decrypt(void *fault_addr) {
    (void)fault_addr;
    return 0;
}

int cprisk_text_on_demand_decrypt(void *fault_addr) {
    return cprisk_text_jit_decrypt(fault_addr);
}

#endif
