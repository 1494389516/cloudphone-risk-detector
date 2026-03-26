/*
 * CRiskCore - Multi-path integrity verification for cprisk-armor ABI v2.
 * Three independent paths compute the __TEXT.__text hash; path C reconstructs
 * the digest from the four split anchor sections. The HMAC anchor tag is
 * verified against the reconstructed hash using the root key.
 * The combined result feeds key derivation, so tampering silently corrupts
 * the derived key.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_instruction_cache.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── internal ──────────────────────────────────────────────────────── */

/* Single-thread assumption: cprisk_init_protection / cprisk_prepare_deception_material_i
 * are called from Swift start() before any concurrent evaluate(). s_runtime_material_ready,
 * s_deception_material_ready are not atomic; use _Atomic or pthread_once if multi-threaded. */
static uint8_t s_runtime_material[CPRISK_ARMOR_HASH_SIZE];
static int s_runtime_material_ready;

/* Hybrid KDF state: three-layer key derivation.
 *   Layer 1: rootKey       (CLI provided)
 *   Layer 2: deviceKey    = HMAC(rootKey, deviceSalt)
 *   Layer 3: effectiveRoot = HMAC(deviceKey, sessionToken)
 *
 * effectiveRoot is stored in s_effective_root and used in place of
 * root_key for all subsequent derivations (white-box domain evaluation,
 * loader key, runtime material).  This binds the entire key chain to
 * both the physical device and the current session. */
static uint8_t s_device_key[CPRISK_ARMOR_KEY_SIZE];
static int s_device_key_ready;
static uint8_t s_effective_root[CPRISK_ARMOR_KEY_SIZE];
static int s_effective_root_ready;

/* Non-static so cprisk_anti_dump_probe.c can set it when dump/injection is detected. */
volatile int s_integrity_deception_active;
static uint8_t s_deception_material[CPRISK_ARMOR_HASH_SIZE];
static int s_deception_material_ready;

static uint8_t s_saved_integrity_hash[CPRISK_ARMOR_HASH_SIZE];
static int s_integrity_hash_saved;
static int s_integrity_poisoned;

/* Distinct semantic bookkeeping per poison entry point (anti batch-NOP / single-hook). */
static volatile uint32_t s_poison_lane_seq[CPRISK_POISON_LANE_COUNT];
static volatile uint32_t s_poison_semantic_breadcrumb;
static uint32_t s_poison_semantic_rolling[2];
/* Poison-wave / ordering state: downstream material mix depends on more than s_integrity_poisoned alone. */
static volatile uint32_t s_poison_epoch;
static volatile uint64_t s_poison_cause_mix;

/* Staged / deferred poison: weak-signal lanes accumulate opaque hits before full commit.
 * Thresholds are compile-time tunable; partial hits mix into cause/rolling state without
 * incrementing per-lane seq (avoids a linear “distance-to-poison” oracle). */
#ifndef CPRISK_POISON_STAGED_WATCHDOG_THRESHOLD
#define CPRISK_POISON_STAGED_WATCHDOG_THRESHOLD 3u
#endif
#ifndef CPRISK_POISON_STAGED_ANTI_DUMP_THRESHOLD
#define CPRISK_POISON_STAGED_ANTI_DUMP_THRESHOLD 2u
#endif

static atomic_uint_fast32_t s_staged_watchdog_hits;
static atomic_uint_fast32_t s_staged_anti_dump_hits;
static atomic_uint_fast64_t s_staged_opacity_tick;

#if defined(CPRISK_MTE_COMPILE_SUPPORT)
static cprisk_mte_canary_state_t s_runtime_material_canary;
static cprisk_mte_canary_state_t s_saved_integrity_canary;
#endif

static uint64_t s_init_elapsed_ns;

/* SDK-configurable anti-debug tier (production vs dev/QA relaxed). */
static int s_runtime_hardening_mode = CPRISK_RUNTIME_HARDENING_PRODUCTION;
static uint64_t s_init_timing_threshold_override_ns;

#define CPRISK_INIT_TIMING_BASE_NS 5000000000ULL
#define CPRISK_INIT_TIMING_RELAXED_EXTRA_NS 10000000000ULL

static const struct mach_header_64 *cprisk_own_hdr_i(void);
static uint64_t cprisk_monotonic_ns(void);

/* Forward declarations for Hybrid KDF (implemented in separate modules). */
int cprisk_derive_device_key(
    const uint8_t *root_key,
    uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]
);
int cprisk_get_session_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

static void cprisk_prepare_deception_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash
);

extern void cprisk_watchdog_note_guard_page_fault(void);

/* Minimal bytecode bootstrap (loader key): single HALT = identity; extend with new opcodes if needed. */
enum {
    CPRISK_MV_OP_HALT = 0,
    CPRISK_MV_OP_XOR_IMM = 1,
};

static void cprisk_mini_vm_exec_buf(uint8_t buf[32], const uint8_t *code, size_t len) {
    size_t pc = 0;
    while (pc < len) {
        uint8_t op = code[pc++];
        if (op == CPRISK_MV_OP_HALT)
            return;
        if (op == CPRISK_MV_OP_XOR_IMM && pc < len) {
            uint8_t imm = code[pc++];
            for (size_t i = 0; i < 32; i++)
                buf[i] = (uint8_t)(buf[i] ^ imm);
        } else {
            return;
        }
    }
}

/* Deterministic non-identity bootstrap: XOR_IMM then HALT (was pure HALT). */
static void cprisk_mini_vm_bootstrap_material32(uint8_t buf[32]) {
    const uint8_t prog[] = { CPRISK_MV_OP_XOR_IMM, 0xA5u, CPRISK_MV_OP_HALT };
    cprisk_mini_vm_exec_buf(buf, prog, sizeof(prog));
}

static void cprisk_loader_key_mini_vm_bootstrap(uint8_t key[32]) {
    cprisk_mini_vm_bootstrap_material32(key);
}

#if (defined(DEBUG) && DEBUG) || defined(CPRISK_ALLOW_MINI_VM_BOOTSTRAP_ENV_BYPASS)
static int cprisk_mini_vm_bootstrap_disabled(void) {
    static int s_cached = -1;
    if (s_cached >= 0)
        return s_cached;
    const char *e = getenv("CPRISK_DISABLE_MINI_VM_BOOTSTRAP");
    s_cached = (e && (e[0] == '1' || e[0] == 'y' || e[0] == 'Y')) ? 1 : 0;
    return s_cached;
}
#else
static int cprisk_mini_vm_bootstrap_disabled(void) {
    /* Release: ignore env; optional unit-test override via compile flag above. */
    return 0;
}
#endif

#ifndef CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER
#define CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER 0
#endif

enum {
    CPRISK_ADBG_PARSE_OK_I = 0u,
    CPRISK_ADBG_PARSE_TRUNCATED_I = 1u,
    CPRISK_ADBG_PARSE_MAGIC_I = 2u,
    CPRISK_ADBG_PARSE_VERSION_I = 3u,
    CPRISK_ADBG_PARSE_LAYOUT_I = 4u,
    CPRISK_ADBG_PARSE_BOUNDS_I = 5u,
    CPRISK_ADBG_PARSE_TOO_MANY_ENTRIES_I = 6u
};

enum {
    CPRISK_ADBG_TRIGGER_INIT_I = 1u << 0,
    CPRISK_ADBG_TRIGGER_INIT_FAILURE_I = 1u << 1,
    CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I = 1u << 2
};

typedef struct cprisk_adbg_runtime_plan_i {
    uint32_t loaded;
    uint32_t section_present;
    uint32_t section_valid;
    uint32_t parse_error;
    uint32_t entry_count;
    uint32_t policy_union_bits;
    uint64_t seed;
    uint64_t text_base_address;
    uint32_t probe_immediate;
} cprisk_adbg_runtime_plan_t;

typedef struct cprisk_adbg_runtime_entry_i {
    uint64_t identifier_hash;
    uint64_t patch_site_vm_offset;
    uint32_t patch_site_file_offset;
    uint32_t policy_bits;
    uint32_t entry_flags;
    uint32_t scatter_slot;
} cprisk_adbg_runtime_entry_t;

static cprisk_adbg_runtime_plan_t s_adbg_plan_i;
static cprisk_antidebug_plan_snapshot_t s_adbg_snapshot_i;
static cprisk_adbg_runtime_entry_t s_adbg_entries_i[CPRISK_MAX_ENTRY_COUNT];
static uint32_t s_adbg_entry_count_i = 0u;
static uintptr_t s_adbg_inline_patch_sites_i[CPRISK_MAX_ENTRY_COUNT];
static uint32_t s_adbg_inline_patch_count_i = 0u;
static atomic_uint_fast32_t s_adbg_inline_patch_armed_i = 0u;
static atomic_uint_fast32_t s_adbg_inline_patch_tamper_i = 0u;
static uint8_t *s_test_adbg_plan_i = NULL;
static size_t s_test_adbg_plan_len_i = 0u;

static uint32_t cprisk_popcount32_i(uint32_t value) {
    uint32_t count = 0u;
    while (value != 0u) {
        count += value & 1u;
        value >>= 1u;
    }
    return count;
}

static int cprisk_mul_size_checked_i(size_t lhs, size_t rhs, size_t *out) {
    if (out == NULL)
        return -1;
    if (lhs != 0u && rhs > SIZE_MAX / lhs)
        return -1;
    *out = lhs * rhs;
    return 0;
}

static void cprisk_antidebug_reset_plan_state_i(void) {
    memset(&s_adbg_plan_i, 0, sizeof(s_adbg_plan_i));
    memset(&s_adbg_snapshot_i, 0, sizeof(s_adbg_snapshot_i));
    memset(s_adbg_entries_i, 0, sizeof(s_adbg_entries_i));
    memset(s_adbg_inline_patch_sites_i, 0, sizeof(s_adbg_inline_patch_sites_i));
    s_adbg_entry_count_i = 0u;
    s_adbg_inline_patch_count_i = 0u;
    atomic_store(&s_adbg_inline_patch_armed_i, 0u);
    atomic_store(&s_adbg_inline_patch_tamper_i, 0u);
}

static int cprisk_antidebug_section_bytes_i(const uint8_t **out_bytes, size_t *out_len) {
    if (!out_bytes || !out_len)
        return -1;

    *out_bytes = NULL;
    *out_len = 0u;

    if (s_test_adbg_plan_i != NULL && s_test_adbg_plan_len_i > 0u) {
        *out_bytes = s_test_adbg_plan_i;
        *out_len = s_test_adbg_plan_len_i;
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sec_size = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_ANTI_DEBUG_PLAN,
        &sec_size);
    if (!sec || sec_size == 0u)
        return 0;

    *out_bytes = sec;
    *out_len = (size_t)sec_size;
    return 0;
}

static void cprisk_antidebug_load_plan_i(void) {
    if (s_adbg_plan_i.loaded != 0u)
        return;

    s_adbg_plan_i.loaded = 1u;

    const uint8_t *bytes = NULL;
    size_t bytes_len = 0u;
    if (cprisk_antidebug_section_bytes_i(&bytes, &bytes_len) != 0 || bytes == NULL || bytes_len == 0u) {
        return;
    }

    s_adbg_plan_i.section_present = 1u;
    s_adbg_snapshot_i.section_present = 1u;

    if (bytes_len < sizeof(struct cprisk_armor_antidebug_header)) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_TRUNCATED_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_TRUNCATED_I;
        return;
    }

    struct cprisk_armor_antidebug_header header;
    memcpy(&header, bytes, sizeof(header));

    if (header.magic != CPRISK_ARMOR_ADBG_MAGIC) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_MAGIC_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_MAGIC_I;
        return;
    }
    if (header.version < CPRISK_ARMOR_ADBG_ABI_VERSION) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_VERSION_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_VERSION_I;
        return;
    }
    if (header.header_size < sizeof(struct cprisk_armor_antidebug_header) ||
        header.entry_size < sizeof(struct cprisk_armor_antidebug_entry)) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_LAYOUT_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_LAYOUT_I;
        return;
    }
    if (header.entry_count > CPRISK_MAX_ENTRY_COUNT) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_TOO_MANY_ENTRIES_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_TOO_MANY_ENTRIES_I;
        return;
    }

    size_t entries_bytes = 0u;
    if (cprisk_mul_size_checked_i((size_t)header.entry_count, (size_t)header.entry_size, &entries_bytes) != 0) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        return;
    }
    if ((size_t)header.header_size > bytes_len || entries_bytes > bytes_len - (size_t)header.header_size) {
        s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_BOUNDS_I;
        return;
    }

    const uint8_t *entry_cursor = bytes + (size_t)header.header_size;
    uint32_t policy_union = 0u;
    uint32_t parsed_entries = 0u;
    for (uint32_t i = 0u; i < header.entry_count; i++) {
        struct cprisk_armor_antidebug_entry entry;
        memcpy(&entry, entry_cursor, sizeof(entry));
        policy_union |= entry.policy_bits;
        if (parsed_entries < CPRISK_MAX_ENTRY_COUNT) {
            s_adbg_entries_i[parsed_entries].identifier_hash = entry.identifier_hash;
            s_adbg_entries_i[parsed_entries].patch_site_vm_offset = entry.patch_site_vm_offset;
            s_adbg_entries_i[parsed_entries].patch_site_file_offset = entry.patch_site_file_offset;
            s_adbg_entries_i[parsed_entries].policy_bits = entry.policy_bits;
            s_adbg_entries_i[parsed_entries].entry_flags = entry.entry_flags;
            s_adbg_entries_i[parsed_entries].scatter_slot = entry.scatter_slot;
            parsed_entries += 1u;
        }
        entry_cursor += (size_t)header.entry_size;
    }
    s_adbg_entry_count_i = parsed_entries;

    s_adbg_plan_i.section_valid = 1u;
    s_adbg_plan_i.parse_error = CPRISK_ADBG_PARSE_OK_I;
    s_adbg_plan_i.entry_count = header.entry_count;
    s_adbg_plan_i.policy_union_bits = policy_union;
    s_adbg_plan_i.seed = header.seed;
    s_adbg_plan_i.text_base_address = header.text_base_address;
    s_adbg_plan_i.probe_immediate = header.probe_immediate;

    s_adbg_snapshot_i.section_valid = 1u;
    s_adbg_snapshot_i.parse_error = CPRISK_ADBG_PARSE_OK_I;
    s_adbg_snapshot_i.entry_count = header.entry_count;
    s_adbg_snapshot_i.policy_union_bits = policy_union;
}

#define CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR \
    (0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_RUNTIME_GATE << 5u))

static int cprisk_antidebug_addr_in_text_i(
    uintptr_t addr,
    const uint8_t *text_base,
    size_t text_size
) {
    if (text_base == NULL || text_size < sizeof(uint32_t)) {
        return 0;
    }
    const uintptr_t start = (uintptr_t)text_base;
    const uintptr_t end = start + text_size;
    if (end < start) {
        return 0;
    }
    return (addr >= start && (addr + sizeof(uint32_t)) <= end) ? 1 : 0;
}

static int cprisk_antidebug_patch_site_i(uintptr_t patch_addr, int *out_tamper) {
    if (out_tamper != NULL) {
        *out_tamper = 0;
    }
    if ((patch_addr & 0x3u) != 0u) {
        return -1;
    }

    uint32_t original_instr = 0u;
    memcpy(&original_instr, (const void *)patch_addr, sizeof(original_instr));
    if (original_instr == CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR) {
        return 0;
    }
    if ((original_instr & 0xFFE00000u) == 0xD4200000u) {
        if (out_tamper != NULL) {
            *out_tamper = 1;
        }
        return -1;
    }

    const uintptr_t page_addr = patch_addr & ~(uintptr_t)0xFFFu;
    int restore_prot = PROT_READ | PROT_EXEC;
    vm_address_t region_addr = (vm_address_t)patch_addr;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    if (vm_region_64(mach_task_self(),
                     &region_addr,
                     &region_size,
                     VM_REGION_BASIC_INFO_64,
                     (vm_region_info_t)&info,
                     &info_count,
                     &object_name) == KERN_SUCCESS) {
        if (object_name != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object_name);
        int queried = (int)info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
        if (queried != 0) {
            restore_prot = queried;
        }
    }

    if (cprisk_mprotect_direct((void *)page_addr, 0x1000u, PROT_READ | PROT_WRITE, NULL) != 0) {
        return -1;
    }

    const uint32_t patched_instr = CPRISK_ADBG_RUNTIME_GATE_BRK_INSTR;
    memcpy((void *)patch_addr, &patched_instr, sizeof(patched_instr));
    cprisk_flush_instruction_cache((void *)patch_addr, sizeof(patched_instr));

    if (cprisk_mprotect_direct((void *)page_addr, 0x1000u, restore_prot, NULL) != 0) {
        if (cprisk_mprotect_direct((void *)page_addr, 0x1000u, PROT_READ | PROT_EXEC, NULL) != 0) {
            return -1;
        }
    }
    return 0;
}

static int cprisk_antidebug_apply_inline_patch_gate_i(void) {
    cprisk_antidebug_load_plan_i();
    if (s_adbg_plan_i.section_valid == 0u) {
        return 0;
    }
    if (atomic_load(&s_adbg_inline_patch_armed_i) != 0u) {
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    unsigned long text_size_ul = 0u;
    const uint8_t *text_base =
        hdr != NULL ? cprisk_find_section(hdr, "__TEXT", "__text", &text_size_ul) : NULL;
    const size_t text_size = (size_t)text_size_ul;
    if (text_base == NULL || text_size < sizeof(uint32_t)) {
        s_adbg_snapshot_i.inline_patch_failure_count += 1u;
        atomic_store(&s_adbg_inline_patch_tamper_i, 1u);
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
        cprisk_integrity_poison_antidebug_lane();
        return -1;
    }

    const intptr_t slide = cprisk_compute_slide(hdr);
    const uintptr_t runtime_text_base =
        (uintptr_t)((intptr_t)s_adbg_plan_i.text_base_address + slide);
    uint32_t patched_count = 0u;
    uint32_t failure_count = 0u;
    int tamper_detected = 0;

    for (uint32_t i = 0u; i < s_adbg_entry_count_i; i++) {
        const cprisk_adbg_runtime_entry_t *entry = &s_adbg_entries_i[i];
        const int allow_inline =
            (entry->entry_flags & CPRISK_ARMOR_ADBG_ENTRY_FLAG_INLINE_PATCH_RESERVED) != 0u;
        const int allow_gate =
            (entry->entry_flags & CPRISK_ARMOR_ADBG_ENTRY_FLAG_RUNTIME_GATE_RESERVED) != 0u ||
            (entry->policy_bits & CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE) != 0u;
        if (!allow_inline || !allow_gate) {
            continue;
        }
        if (entry->patch_site_vm_offset > (uint64_t)(UINTPTR_MAX - runtime_text_base)) {
            failure_count += 1u;
            tamper_detected = 1;
            continue;
        }

        const uintptr_t patch_addr = runtime_text_base + (uintptr_t)entry->patch_site_vm_offset;
        if (!cprisk_antidebug_addr_in_text_i(patch_addr, text_base, text_size)) {
            failure_count += 1u;
            tamper_detected = 1;
            continue;
        }

        int tamper_here = 0;
        if (cprisk_antidebug_patch_site_i(patch_addr, &tamper_here) != 0) {
            failure_count += 1u;
            tamper_detected |= tamper_here;
            continue;
        }

        int duplicate = 0;
        for (uint32_t j = 0u; j < patched_count; j++) {
            if (s_adbg_inline_patch_sites_i[j] == patch_addr) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate && patched_count < CPRISK_MAX_ENTRY_COUNT) {
            s_adbg_inline_patch_sites_i[patched_count] = patch_addr;
            patched_count += 1u;
        }
    }

    s_adbg_inline_patch_count_i = patched_count;
    s_adbg_snapshot_i.inline_patch_count = patched_count;
    s_adbg_snapshot_i.inline_patch_failure_count += failure_count;
    s_adbg_snapshot_i.inline_patch_armed = patched_count > 0u ? 1u : 0u;
    if (tamper_detected) {
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
    }
    atomic_store(&s_adbg_inline_patch_armed_i, patched_count > 0u ? 1u : 0u);
    atomic_store(&s_adbg_inline_patch_tamper_i, tamper_detected ? 1u : 0u);

    if (failure_count != 0u) {
        cprisk_integrity_poison_antidebug_lane();
        return -1;
    }
    return patched_count > 0u ? 1 : 0;
}

static int cprisk_antidebug_is_runtime_gate_site_i(uintptr_t brk_pc) {
    if (brk_pc == 0u || s_adbg_inline_patch_count_i == 0u) {
        return 0;
    }
    for (uint32_t i = 0u; i < s_adbg_inline_patch_count_i; i++) {
        if (s_adbg_inline_patch_sites_i[i] == brk_pc) {
            return 1;
        }
    }
    return 0;
}

int cprisk_exception_handler_handle_runtime_gate_brk(uint16_t brk_imm, uintptr_t brk_pc) {
    if (brk_imm != (uint16_t)CPRISK_BRK_IMM_RUNTIME_GATE) {
        return 0;
    }

    const int armed = atomic_load(&s_adbg_inline_patch_armed_i) != 0u;
    int tamper = atomic_load(&s_adbg_inline_patch_tamper_i) != 0u;
    if (!armed || !cprisk_antidebug_is_runtime_gate_site_i(brk_pc)) {
        tamper = 1;
    }

    if (tamper || cprisk_is_being_traced_redundant() != 0 || cprisk_trace_crosscheck_inconsistent() != 0) {
        atomic_store(&s_adbg_inline_patch_tamper_i, 1u);
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
        s_adbg_snapshot_i.trap_event_count += 1u;
        cprisk_integrity_poison_antidebug_lane();
        return -1;
    }

    /* Clean path: consume runtime-gate BRK and continue execution. */
    return 1;
}

static uint32_t cprisk_antidebug_select_policy_bits_i(
    uint32_t probe_bits,
    int high_risk,
    uint32_t *out_selected_entries,
    uint64_t *out_identifier_mix
) {
    if (out_selected_entries)
        *out_selected_entries = 0u;
    if (out_identifier_mix)
        *out_identifier_mix = 0u;

    if (s_adbg_entry_count_i == 0u) {
        return s_adbg_plan_i.policy_union_bits;
    }

    const uint64_t selector_seed =
        s_adbg_plan_i.seed ^
        ((uint64_t)probe_bits << 11u) ^
        ((uint64_t)s_adbg_plan_i.probe_immediate << 3u) ^
        0x9E3779B97F4A7C15ULL;

    uint32_t selected_bits = 0u;
    uint32_t selected_count = 0u;
    uint64_t selected_mix = 0u;

    for (uint32_t i = 0u; i < s_adbg_entry_count_i; i++) {
        const cprisk_adbg_runtime_entry_t *entry = &s_adbg_entries_i[i];
        if (entry->policy_bits == 0u) {
            continue;
        }

        const uint64_t gate =
            entry->identifier_hash ^
            selector_seed ^
            ((uint64_t)entry->scatter_slot << 32u) ^
            ((uint64_t)entry->entry_flags << 9u);
        const int always_gate =
            (entry->policy_bits & CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE) != 0u;
        const int selected = always_gate != 0
            ? 1
            : (high_risk
                ? ((gate & 0x3u) != 0u)
                : ((gate & 0x7u) == 0u));
        if (!selected) {
            continue;
        }

        selected_bits |= entry->policy_bits;
        selected_count += 1u;
        selected_mix ^= entry->identifier_hash ^ gate;
    }

    if (selected_bits == 0u) {
        selected_bits = s_adbg_plan_i.policy_union_bits;
    }

    if (out_selected_entries)
        *out_selected_entries = selected_count;
    if (out_identifier_mix)
        *out_identifier_mix = selected_mix;
    return selected_bits;
}

static uint64_t cprisk_antidebug_delay_response_i(uint64_t seed, uint32_t probe_immediate, int high_risk) {
    uint64_t mix = seed ^ ((uint64_t)probe_immediate << 17u) ^ 0x9E3779B97F4A7C15ULL;
    uint64_t delay_ns = 500000ull + (mix % 1500000ull); /* 0.5ms .. 2.0ms */
    if (high_risk)
        delay_ns += 20000000ull + ((mix >> 11u) % 30000000ull); /* +20ms .. +50ms */

    struct timespec req;
    req.tv_sec = (time_t)(delay_ns / 1000000000ull);
    req.tv_nsec = (long)(delay_ns % 1000000000ull);
    (void)nanosleep(&req, NULL);
    return delay_ns;
}

static int cprisk_parse_apple_hw_major_generation_i(const char *machine, int *out_major) {
    if (!machine || !out_major)
        return -1;
    *out_major = -1;
    const char *p = NULL;
    if (strncmp(machine, "iPhone", 6) == 0)
        p = machine + 6;
    else if (strncmp(machine, "iPad", 4) == 0)
        p = machine + 4;
    else if (strncmp(machine, "iPod", 4) == 0)
        p = machine + 4;
    else if (strncmp(machine, "Mac", 3) == 0)
        p = machine + 3;
    else if (strncmp(machine, "Watch", 5) == 0)
        p = machine + 5;
    else if (strncmp(machine, "Appletv", 7) == 0)
        p = machine + 7;
    else
        return -1;
    if (*p < '0' || *p > '9')
        return -1;
    int v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        if (v > 9999)
            return -1;
        p++;
    }
    *out_major = v;
    return 0;
}

static uint64_t cprisk_generation_slack_ns_i(int major_gen) {
    if (major_gen < 0)
        return 8000000000ULL;
    if (major_gen >= 16)
        return 0;
    if (major_gen >= 14)
        return 2000000000ULL;
    if (major_gen >= 12)
        return 5000000000ULL;
    return 10000000000ULL;
}

static uint64_t cprisk_compute_init_timing_threshold_ns_for_machine_i(
    const char *machine,
    cprisk_runtime_hardening_mode_t mode
) {
    int m = -1;
    if (machine && machine[0] != '\0')
        (void)cprisk_parse_apple_hw_major_generation_i(machine, &m);
    uint64_t t = CPRISK_INIT_TIMING_BASE_NS + cprisk_generation_slack_ns_i(m);
    if (mode == CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA ||
        mode == CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE)
        t += CPRISK_INIT_TIMING_RELAXED_EXTRA_NS;
    return t;
}

static int cprisk_runtime_relaxed_dev_qa_i(void) {
    return s_runtime_hardening_mode == CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA ||
        s_runtime_hardening_mode == CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE;
}

static void cprisk_antidebug_apply_policies_i(uint32_t trigger_flags, int init_rc_hint, int integrity_rc_hint) {
    cprisk_antidebug_load_plan_i();
    if (s_adbg_plan_i.section_valid == 0u || s_adbg_plan_i.policy_union_bits == 0u)
        return;
    if ((trigger_flags & CPRISK_ADBG_TRIGGER_INIT_I) != 0u) {
        (void)cprisk_antidebug_apply_inline_patch_gate_i();
    }

    const uint32_t strong_probe_mask =
        CPRISK_PROBE_SIGNAL_TRAP |
        CPRISK_PROBE_THREAD_EXCEPTION_PORT |
        CPRISK_PROBE_HARDWARE_BP |
        CPRISK_PROBE_SOFTWARE_BP |
        CPRISK_PROBE_INSTANT_RETURN_PATCH |
        CPRISK_PROBE_CSOPS |
        CPRISK_PROBE_DBI_MARKER |
        CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT |
        CPRISK_PROBE_SUSPICIOUS_THREAD |
        CPRISK_PROBE_TRACE_CROSSCHECK;
    const uint32_t weak_probe_mask =
        CPRISK_PROBE_SINGLE_STEP |
        CPRISK_PROBE_TIMING_ANOMALY |
        CPRISK_PROBE_TTY |
        CPRISK_PROBE_DEVELOPER_DISK;

    const int traced = cprisk_is_being_traced_redundant();
    uint32_t probe_bits = cprisk_run_all_signal_probes();
    if (cprisk_trace_crosscheck_inconsistent() != 0) {
        probe_bits |= CPRISK_PROBE_TRACE_CROSSCHECK;
    }
    const uint32_t strong_hits = cprisk_popcount32_i(probe_bits & strong_probe_mask);
    uint32_t weak_scoring_mask = weak_probe_mask;
    if (cprisk_runtime_relaxed_dev_qa_i()) {
        weak_scoring_mask &= (uint32_t)~(CPRISK_PROBE_TTY |
                                         CPRISK_PROBE_DEVELOPER_DISK |
                                         CPRISK_PROBE_TIMING_ANOMALY);
    }
    const uint32_t weak_hits = cprisk_popcount32_i(probe_bits & weak_scoring_mask);
    const int debug_strength = (traced ? 3 : 0) + (int)(strong_hits * 2u + weak_hits);
    const int debugger_likely = traced != 0 || debug_strength >= 3;
    const int debugger_confirmed = traced != 0 || debug_strength >= 5 || strong_hits >= 2u;
    const int integrity_tampered =
        (trigger_flags & CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I) != 0u ||
        integrity_rc_hint > 0;
    const int init_failed = init_rc_hint != 0;
    const int high_risk = debugger_likely || integrity_tampered || init_failed;
    uint32_t selected_entries = 0u;
    uint64_t selected_identifier_mix = 0u;
    const uint32_t policy_bits = cprisk_antidebug_select_policy_bits_i(
        probe_bits,
        high_risk,
        &selected_entries,
        &selected_identifier_mix
    );
    uint32_t applied = 0u;

    s_adbg_snapshot_i.consume_count += 1u;
    s_adbg_snapshot_i.last_probe_bits = probe_bits;
    s_adbg_snapshot_i.last_gate_closed = 0u;
    s_adbg_snapshot_i.last_soft_fail_mode = 0u;
    s_adbg_snapshot_i.last_delay_ns = 0u;
    s_adbg_snapshot_i.inline_patch_armed =
        atomic_load(&s_adbg_inline_patch_armed_i) != 0u ? 1u : 0u;
    if (atomic_load(&s_adbg_inline_patch_tamper_i) != 0u) {
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
    }
    (void)selected_entries;
    (void)selected_identifier_mix;

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE) != 0u) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE;
        cprisk_deny_attach();
        if (debugger_likely) {
            s_adbg_snapshot_i.last_gate_closed = 1u;
            cprisk_prepare_deception_material_i(NULL, NULL, NULL);
            s_integrity_deception_active = 1;
        }
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE) != 0u) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE;
        s_adbg_snapshot_i.last_delay_ns = cprisk_antidebug_delay_response_i(
            s_adbg_plan_i.seed, s_adbg_plan_i.probe_immediate, high_risk);
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY) != 0u && high_risk) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY;
        s_adbg_snapshot_i.escalation_count += 1u;
        cprisk_integrity_poison_antidebug_lane();
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER) != 0u &&
        (integrity_tampered || init_failed || (trigger_flags & CPRISK_ADBG_TRIGGER_INIT_FAILURE_I) != 0u)) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER;
        s_adbg_snapshot_i.trap_event_count += 1u;
        if (cprisk_probe_exception_delivery_timeout() != 0 || debugger_likely) {
            cprisk_integrity_poison_antidebug_lane();
        }
    }

    if ((policy_bits & CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER) != 0u && debugger_confirmed) {
        applied |= CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER;
        s_adbg_snapshot_i.last_soft_fail_mode = 1u;
        cprisk_integrity_poison_antidebug_lane();
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
#if CPRISK_ANTI_DEBUG_HARD_CRASH_ON_DEBUGGER
        if (debug_strength >= 7) {
            __builtin_trap();
        }
#endif
    }

    s_adbg_snapshot_i.last_applied_policy_bits = applied;
}

int cprisk_get_antidebug_plan_snapshot(cprisk_antidebug_plan_snapshot_t *out_snapshot) {
    if (!out_snapshot)
        return -1;
    s_adbg_snapshot_i.inline_patch_armed =
        atomic_load(&s_adbg_inline_patch_armed_i) != 0u ? 1u : 0u;
    if (atomic_load(&s_adbg_inline_patch_tamper_i) != 0u) {
        s_adbg_snapshot_i.last_inline_patch_tamper = 1u;
    }
    *out_snapshot = s_adbg_snapshot_i;
    return 0;
}

int cprisk_test_set_antidebug_plan(const uint8_t *plan, size_t plan_len) {
    if (!plan || plan_len == 0u)
        return -1;

    uint8_t *copy = (uint8_t *)malloc(plan_len);
    if (!copy)
        return -1;
    memcpy(copy, plan, plan_len);

    if (s_test_adbg_plan_i != NULL) {
        cprisk_secure_zero(s_test_adbg_plan_i, s_test_adbg_plan_len_i);
        free(s_test_adbg_plan_i);
    }
    s_test_adbg_plan_i = copy;
    s_test_adbg_plan_len_i = plan_len;
    cprisk_antidebug_reset_plan_state_i();
    return 0;
}

void cprisk_test_clear_antidebug_plan(void) {
    if (s_test_adbg_plan_i != NULL) {
        cprisk_secure_zero(s_test_adbg_plan_i, s_test_adbg_plan_len_i);
        free(s_test_adbg_plan_i);
    }
    s_test_adbg_plan_i = NULL;
    s_test_adbg_plan_len_i = 0u;
    cprisk_antidebug_reset_plan_state_i();
}

static const struct mach_header_64 *cprisk_own_hdr_i(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr_i);
}

static void cprisk_fill_root_material_i(const uint8_t *root_key,
                                        size_t root_key_len,
                                        uint8_t out[CPRISK_ARMOR_KEY_SIZE]) {
    memset(out, 0, CPRISK_ARMOR_KEY_SIZE);
    if (!root_key || root_key_len == 0)
        return;

    size_t copy_len = root_key_len;
    if (copy_len > CPRISK_ARMOR_KEY_SIZE)
        copy_len = CPRISK_ARMOR_KEY_SIZE;
    memcpy(out, root_key, copy_len);
}

static void cprisk_u64_to_le_i(uint64_t value, uint8_t out[8]) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
    out[4] = (uint8_t)(value >> 32);
    out[5] = (uint8_t)(value >> 40);
    out[6] = (uint8_t)(value >> 48);
    out[7] = (uint8_t)(value >> 56);
}

static uint64_t cprisk_u64_from_le_i(const uint8_t in[8]) {
    return ((uint64_t)in[0]) |
           ((uint64_t)in[1] << 8) |
           ((uint64_t)in[2] << 16) |
           ((uint64_t)in[3] << 24) |
           ((uint64_t)in[4] << 32) |
           ((uint64_t)in[5] << 40) |
           ((uint64_t)in[6] << 48) |
           ((uint64_t)in[7] << 56);
}

static uint64_t cprisk_rotl64_i(uint64_t value, unsigned int shift) {
    shift &= 63U;
    if (shift == 0U)
        return value;
    return (value << shift) | (value >> (64U - shift));
}

static uintptr_t cprisk_pac_discriminator_i(const uint8_t *seed, size_t seed_len) {
    uint64_t acc = 0x43505249534B5041ULL; /* "CPRISKPA" */
    if (seed && seed_len > 0) {
        const size_t take = seed_len > 16 ? 16 : seed_len;
        for (size_t i = 0; i < take; i++) {
            acc ^= ((uint64_t)seed[i]) << ((i & 7u) * 8u);
            acc = cprisk_rotl64_i(acc, 9u) ^ 0x9E3779B97F4A7C15ULL;
        }
    }
    return (uintptr_t)acc;
}

static int cprisk_validate_pac_cfi_i(const uint8_t *seed, size_t seed_len) {
    const uintptr_t discriminator = cprisk_pac_discriminator_i(seed, seed_len);
    if (cprisk_pac_self_test(discriminator) != 0)
        return -1;
    if (cprisk_pac_validate_core_callbacks() != 0)
        return -1;
    return 0;
}

enum {
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG_I = 1u,
    CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY_I = 2u,
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED_I = 3u,
    CPRISK_WHITEBOX_DOMAIN_LOADER_KEY_I = 4u,
    CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL_I = 5u
};

int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

static int cprisk_derive_pass1_string_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label[] = "cprisk.pass1.key.v1";
    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_final(&ctx, digest);

    memcpy(out_key, digest, CPRISK_ARMOR_KEY_SIZE);
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

static uint64_t cprisk_anchor_bound_accumulator_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label[] = "cprisk.pass1.acc.v2";
    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_final(&ctx, digest);

    uint64_t acc = cprisk_u64_from_le_i(digest);
    cprisk_secure_zero(digest, sizeof(digest));
    return cprisk_rotl64_i(acc, 7U);
}

static void cprisk_mix_stable_deception_context_i(cprisk_sha256_ctx *ctx) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    uint8_t hdr_le[8];
    uint8_t self_le[8];
    uint8_t pid_le[8];
    uint8_t elapsed_le[8];

    cprisk_u64_to_le_i((uint64_t)(uintptr_t)hdr, hdr_le);
    cprisk_u64_to_le_i((uint64_t)(uintptr_t)cprisk_get_runtime_material, self_le);
    cprisk_u64_to_le_i((uint64_t)cprisk_getpid_direct(), pid_le);
    cprisk_u64_to_le_i(s_init_elapsed_ns, elapsed_le);

    cprisk_sha256_update(ctx, hdr_le, sizeof(hdr_le));
    cprisk_sha256_update(ctx, self_le, sizeof(self_le));
    cprisk_sha256_update(ctx, pid_le, sizeof(pid_le));
    cprisk_sha256_update(ctx, elapsed_le, sizeof(elapsed_le));

    cprisk_secure_zero(hdr_le, sizeof(hdr_le));
    cprisk_secure_zero(self_le, sizeof(self_le));
    cprisk_secure_zero(pid_le, sizeof(pid_le));
    cprisk_secure_zero(elapsed_le, sizeof(elapsed_le));
}

static void cprisk_derive_decoy_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label[] = "cprisk.runtime.decoy.v1";
    static const uint8_t missing_root[] = "missing-root";
    static const uint8_t missing_anchor[] = "missing-anchor";
    static const uint8_t missing_integrity_enc[] = {
        0x37, 0x33, 0x29, 0x29, 0x33, 0x34, 0x3D, 0x77, 0x33,
        0x34, 0x2E, 0x3F, 0x3D, 0x28, 0x33, 0x2E, 0x23
    };
    uint8_t missing_integrity_dec[sizeof(missing_integrity_enc)];
    for (size_t i = 0; i < sizeof(missing_integrity_enc); i++) {
        missing_integrity_dec[i] = (uint8_t)(missing_integrity_enc[i] ^ 0x5A);
    }

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);

    if (root_material)
        cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_root, sizeof(missing_root) - 1U);

    if (full_anchor_hash)
        cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_anchor, sizeof(missing_anchor) - 1U);

    if (integrity_hash)
        cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_integrity_dec, sizeof(missing_integrity_dec));

    cprisk_mix_stable_deception_context_i(&ctx);
    cprisk_sha256_final(&ctx, out_hash);
    cprisk_secure_zero(missing_integrity_dec, sizeof(missing_integrity_dec));
}

static void cprisk_prepare_deception_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash
) {
    if (s_deception_material_ready)
        return;
    cprisk_derive_decoy_material_i(
        root_material, full_anchor_hash, integrity_hash, s_deception_material);
    s_deception_material_ready = 1;
}

static int cprisk_should_activate_deception_i(void) {
    if (cprisk_is_being_traced_redundant())
        return 1;
    if (cprisk_is_mprotect_tampered())
        return 1;
    if (cprisk_check_init_timing())
        return 1;
    return 0;
}

static void cprisk_integrity_poison_semantic_reset_i(void) {
    memset((void *)&s_poison_lane_seq[0], 0, sizeof(s_poison_lane_seq));
    s_poison_semantic_breadcrumb = 0u;
    s_poison_semantic_rolling[0] = 0u;
    s_poison_semantic_rolling[1] = 0u;
    s_poison_epoch = 0u;
    s_poison_cause_mix = 0u;
}

static void cprisk_integrity_poison_lane_sidefx_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT)
        lane = CPRISK_POISON_LANE_FORCE;
    s_poison_lane_seq[lane] += 1u;
    const uint32_t seq = s_poison_lane_seq[lane];
    s_poison_epoch += 1u;
    s_poison_cause_mix = s_poison_cause_mix * 0x9E3779B97F4A7C15ULL;
    s_poison_cause_mix ^= ((uint64_t)(lane + 1u) << 48) ^ (uint64_t)seq ^ ((uint64_t)seq << 32);
    const uint32_t lane_mix = lane * 0x85EBCA6Bu;
    s_poison_semantic_rolling[0] ^= 0x9E3779B9u ^ lane_mix ^ seq;
    s_poison_semantic_rolling[1] ^=
        (uint32_t)(lane + 1u) * 0xC2B2AE3Du ^ (seq << (lane & 7u));

    /* Lane-specific non-linear fold: not a second copy of the same transform (symbol rename only). */
    if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_A) {
        s_poison_semantic_breadcrumb ^= (0xA5C3E971u ^ (seq * 0x9E3779B9u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 11) | (s_poison_semantic_breadcrumb >> 21);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_B) {
        s_poison_semantic_breadcrumb ^= (0x4B7D8E0Fu ^ (seq * 0x85EBCA6Bu));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 13) | (s_poison_semantic_breadcrumb << 19);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_RECHECK) {
        s_poison_semantic_breadcrumb ^= (0xC0DEF00Du ^ (seq * 0xDEADBEEFu));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 7) | (s_poison_semantic_breadcrumb >> 25);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WATCHDOG) {
        s_poison_semantic_breadcrumb ^= (0xBADC0DE3u ^ (seq * 0x1234567u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 17) | (s_poison_semantic_breadcrumb >> 15);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CODE_SIGNING) {
        s_poison_semantic_breadcrumb ^= (0x51E9C0DEu ^ (seq * 0xABCDEF01u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 9) | (s_poison_semantic_breadcrumb << 23);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_SVC_IFACE) {
        s_poison_semantic_breadcrumb ^= (0xFACADE5Au ^ (seq * 0x55AA1100u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 5) | (s_poison_semantic_breadcrumb >> 27);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTIDEBUG) {
        s_poison_semantic_breadcrumb ^= (0xADB6D00Du ^ (seq * 0x10203041u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 3) | (s_poison_semantic_breadcrumb >> 29);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EXCEPTION) {
        s_poison_semantic_breadcrumb ^= (0xE11CE771u ^ (seq * 0x31415927u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 7) | (s_poison_semantic_breadcrumb << 25);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTI_DUMP) {
        s_poison_semantic_breadcrumb ^= (0xA17DD00Fu ^ (seq * 0x27182818u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 13) | (s_poison_semantic_breadcrumb >> 19);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_DATA_LOADER) {
        s_poison_semantic_breadcrumb ^= (0xDA7A10ADu ^ (seq * 0x01000193u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 11) | (s_poison_semantic_breadcrumb << 21);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_TEXT_ENCRYPT) {
        s_poison_semantic_breadcrumb ^= (0x7E87C0DEu ^ (seq * 0x5BD1E995u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 9) | (s_poison_semantic_breadcrumb >> 23);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WHITEBOX) {
        s_poison_semantic_breadcrumb ^= (0xB01DFACEu ^ (seq * 0x045D9F3Bu));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb >> 5) | (s_poison_semantic_breadcrumb << 27);
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CFF) {
        s_poison_semantic_breadcrumb ^= (0xCFF0A11Eu ^ (seq * 0x7F4A7C15u));
        s_poison_semantic_breadcrumb =
            (s_poison_semantic_breadcrumb << 15) | (s_poison_semantic_breadcrumb >> 17);
    }
    /* Low bits record which lanes fired (Swift/tests); applied after folds so they stay observable. */
    if (lane < 32u)
        s_poison_semantic_breadcrumb |= (1u << lane);
}

static void cprisk_integrity_poison_lane_tweak_deception_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT || !s_deception_material_ready)
        return;
    const uint32_t salt0 = s_poison_semantic_rolling[0] ^ (lane * 0x243F6A88u);
    const uint32_t salt1 = s_poison_semantic_rolling[1] ^ (s_poison_lane_seq[lane] * 7u);
    uint8_t *const m = s_deception_material;

    if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_A) {
        /* Front window: independent from evt_b's tail window. */
        for (size_t i = 0; i < 12u && i < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            m[i] ^= (uint8_t)((salt0 >> ((i % 4u) * 8u)) & 0xFFu) ^ (uint8_t)(0xA5u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EVT_B) {
        for (size_t i = 0; i < 12u && (size_t)CPRISK_ARMOR_HASH_SIZE > 12u; i++) {
            const size_t j = (size_t)CPRISK_ARMOR_HASH_SIZE - 12u + i;
            m[j] ^= (uint8_t)((salt1 >> ((i % 4u) * 8u)) & 0xFFu) ^ (uint8_t)(0x5Au + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_RECHECK) {
        /* Middle stripe: overlaps neither evt_a front nor evt_b tail windows. */
        for (size_t i = 0; i < 12u && i + 8u <= (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 8u + i;
            m[j] ^= (uint8_t)((salt0 ^ salt1) >> ((i % 4u) * 8u)) ^ (uint8_t)(0x3Cu + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WATCHDOG) {
        for (size_t i = 0; i < 8u && i + 4u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 4u + i;
            m[j] ^= (uint8_t)(salt0 >> ((i % 4u) * 8u)) ^ (uint8_t)(0x71u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CODE_SIGNING) {
        for (size_t i = 0; i < 6u && i + 20u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 20u + i;
            m[j] ^= (uint8_t)(salt1 >> ((i % 4u) * 8u)) ^ (uint8_t)(0xC0u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_SVC_IFACE) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[2] ^= salt0 ^ 0xC001D00Du;
        dm[3] ^= salt1 ^ 0xD00DF00Du;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTIDEBUG) {
        for (size_t i = 0; i < 6u && i + 2u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 2u + i;
            m[j] ^= (uint8_t)(salt0 >> ((i % 4u) * 8u)) ^ (uint8_t)(0x44u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_EXCEPTION) {
        for (size_t i = 0; i < 6u && i + 14u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 14u + i;
            m[j] ^= (uint8_t)(salt1 >> ((i % 4u) * 8u)) ^ (uint8_t)(0x81u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_ANTI_DUMP) {
        for (size_t i = 0; i < 6u && i + 24u < (size_t)CPRISK_ARMOR_HASH_SIZE; i++) {
            const size_t j = 24u + i;
            m[j] ^= (uint8_t)((salt0 ^ salt1) >> ((i % 4u) * 8u)) ^ (uint8_t)(0x29u + (uint8_t)i);
        }
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_DATA_LOADER) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[4] ^= salt0 ^ 0xDADA11AAu;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_TEXT_ENCRYPT) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[5] ^= salt1 ^ 0x7E70C0DEu;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_WHITEBOX) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[6] ^= (salt0 ^ salt1) ^ 0xB01DB0B0u;
    } else if (lane == (uint32_t)CPRISK_POISON_LANE_CFF) {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[7] ^= salt0 ^ 0xCF0CF0CFu;
    } else {
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[0] ^= salt0;
        dm[1] ^= salt1;
    }
}

static void cprisk_integrity_poison_lane_full_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT)
        lane = CPRISK_POISON_LANE_FORCE;
    s_integrity_poisoned = 1;
    cprisk_integrity_poison_lane_sidefx_i(lane);
    /* Anti-dump full commit always arms deception material (legacy probe parity); other lanes
     * only when traced / mprotect-tamper / init-timing heuristics fire. */
    if (cprisk_should_activate_deception_i() ||
        lane == (uint32_t)CPRISK_POISON_LANE_ANTI_DUMP) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        cprisk_integrity_poison_lane_tweak_deception_i(lane);
    }
}

static void cprisk_integrity_poison_staged_note_i(uint32_t lane) {
    if (lane >= (uint32_t)CPRISK_POISON_LANE_COUNT)
        lane = CPRISK_POISON_LANE_FORCE;
    const uint64_t t = atomic_fetch_add(&s_staged_opacity_tick, 1) + 1ull;
    uint64_t z = t * 0x9E3779B97F4A7C15ULL;
    z ^= (uint64_t)(lane + 1u) << 48;
    z ^= z >> 33;
    z *= 0xff51afd7ed558ccdULL;
    z ^= z >> 33;
    z *= 0xc4ceb9fe1a85ec53ULL;
    z ^= z >> 33;
    z ^= (uint64_t)lane * 0xD6E8FEB86655FD96ULL;
    s_poison_cause_mix ^= z;
    s_poison_semantic_rolling[0] ^= (uint32_t)(z >> 32);
    s_poison_semantic_rolling[1] ^= (uint32_t)z;
    /*
     * Signature-noise: fold staged tick into deception material so staged-only responses are not
     * bitwise stable across ticks (complements lane_tweak_deception_i when full commit is deferred).
     */
    if (s_deception_material_ready) {
        const uint32_t tv = (uint32_t)(t & 0xFFFFFFFFu);
        uint32_t *dm = (uint32_t *)s_deception_material;
        dm[0] ^= tv ^ (uint32_t)(z >> 32);
        dm[1] ^= (uint32_t)z ^ ((uint32_t)lane * 0x13579BDFu);
        if ((size_t)CPRISK_ARMOR_HASH_SIZE >= 16u) {
            uint8_t *const m = s_deception_material;
            m[12] ^= (uint8_t)(tv & 0xFFu);
            m[13] ^= (uint8_t)((tv >> 8) & 0xFFu);
            m[14] ^= (uint8_t)((uint32_t)lane ^ (uint32_t)(t >> 40));
            m[15] ^= (uint8_t)((z >> 56) & 0xFFu);
        }
    }
}

static void cprisk_integrity_poison_watchdog_lane_staged_i(void) {
    const uint32_t n = atomic_fetch_add(&s_staged_watchdog_hits, 1) + 1u;
    if (n >= CPRISK_POISON_STAGED_WATCHDOG_THRESHOLD) {
        atomic_store(&s_staged_watchdog_hits, 0u);
        cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_WATCHDOG);
    } else {
        cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_WATCHDOG);
    }
}

static void cprisk_integrity_poison_anti_dump_lane_staged_i(void) {
    const uint32_t n = atomic_fetch_add(&s_staged_anti_dump_hits, 1) + 1u;
    if (n >= CPRISK_POISON_STAGED_ANTI_DUMP_THRESHOLD) {
        atomic_store(&s_staged_anti_dump_hits, 0u);
        cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_ANTI_DUMP);
    } else {
        cprisk_integrity_poison_staged_note_i(CPRISK_POISON_LANE_ANTI_DUMP);
    }
}

static void cprisk_derive_loader_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'a'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, '3'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'e'^CPRISK_SALT_XOR_KEY_DEFAULT, 'y'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    uint8_t acc_le[8];
    cprisk_u64_to_le_i(string_acc, acc_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, acc_le, sizeof(acc_le));
    cprisk_sha256_final(&ctx, out_key);

    cprisk_secure_zero(label, sizeof(label));
    cprisk_secure_zero(acc_le, sizeof(acc_le));
}

static void cprisk_derive_runtime_material_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint64_t data_acc,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'r'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'u'^CPRISK_SALT_XOR_KEY_DEFAULT, 'n'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'm'^CPRISK_SALT_XOR_KEY_DEFAULT, 'e'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'a'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'e'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    uint8_t str_le[8];
    uint8_t data_le[8];
    cprisk_u64_to_le_i(string_acc, str_le);
    cprisk_u64_to_le_i(data_acc, data_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, str_le, sizeof(str_le));
    cprisk_sha256_update(&ctx, data_le, sizeof(data_le));
    cprisk_sha256_final(&ctx, out_hash);

    cprisk_secure_zero(label, sizeof(label));
    cprisk_secure_zero(str_le, sizeof(str_le));
    cprisk_secure_zero(data_le, sizeof(data_le));
}

static void cprisk_sha256_concat2_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_final(&ctx, out_hash);
}

static void cprisk_sha256_concat3_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    const uint8_t *c,
    size_t c_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_update(&ctx, c, c_len);
    cprisk_sha256_final(&ctx, out_hash);
}

static void cprisk_sha256_concat4_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    const uint8_t *c,
    size_t c_len,
    const uint8_t *d,
    size_t d_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_update(&ctx, c, c_len);
    cprisk_sha256_update(&ctx, d, d_len);
    cprisk_sha256_final(&ctx, out_hash);
}

static int cprisk_verify_anchor_whitebox_i(
    const uint8_t full_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz != CPRISK_ARMOR_HASH_SIZE)
        return -1;

    uint8_t computed_tag[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG_I,
            full_hash,
            computed_tag) != 0) {
        return -1;
    }

    const int rc = cprisk_hmac_verify(sec, computed_tag, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_tag, sizeof(computed_tag));
    return rc;
}

static int cprisk_init_protection_legacy_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint64_t string_acc = 0;
    int rc = -1;
    memset(loader_key, 0, sizeof(loader_key));

    if (cprisk_verify_anchor_hmac(root_material, full_anchor_hash) != 0) {
        rc = -4;
        goto cleanup;
    }

    string_acc = cprisk_anchor_bound_accumulator_i(
        root_material, full_anchor_hash, integrity);

    {
        uint8_t pass1_string_key[CPRISK_ARMOR_KEY_SIZE];
        cprisk_derive_pass1_string_key_i(root_material, pass1_string_key);
        if (cprisk_init_string_decryptor(pass1_string_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
            cprisk_secure_zero(pass1_string_key, sizeof(pass1_string_key));
            rc = -5;
            goto cleanup;
        }
        cprisk_secure_zero(pass1_string_key, sizeof(pass1_string_key));
    }

    cprisk_prepare_deception_material_i(
        root_material, full_anchor_hash, integrity);

    cprisk_derive_loader_key_i(
        root_material,
        full_anchor_hash,
        integrity,
        string_acc,
        loader_key);

    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_loader_key_mini_vm_bootstrap(loader_key);

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    if (cprisk_load_protected_data() < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_derive_runtime_material_i(
        root_material,
        full_anchor_hash,
        integrity,
        string_acc,
        cprisk_get_data_integrity_accumulator(),
        s_runtime_material);
    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_mini_vm_bootstrap_material32(s_runtime_material);
    s_runtime_material_ready = 1;
    rc = 0;

cleanup:
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    return rc;
}

static int cprisk_init_protection_whitebox_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t pass1_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t acc_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t acc_seed[CPRISK_ARMOR_HASH_SIZE];
    uint8_t loader_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t runtime_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t anchor_acc_le[8];
    uint8_t string_acc_le[8];
    uint8_t data_acc_le[8];
    uint64_t anchor_accumulator = 0;
    int rc = -1;

    memset(pass1_key, 0, sizeof(pass1_key));
    memset(acc_digest, 0, sizeof(acc_digest));
    memset(acc_seed, 0, sizeof(acc_seed));
    memset(loader_digest, 0, sizeof(loader_digest));
    memset(loader_key, 0, sizeof(loader_key));
    memset(runtime_digest, 0, sizeof(runtime_digest));
    memset(anchor_acc_le, 0, sizeof(anchor_acc_le));
    memset(string_acc_le, 0, sizeof(string_acc_le));
    memset(data_acc_le, 0, sizeof(data_acc_le));

    if (cprisk_verify_anchor_whitebox_i(full_anchor_hash) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -4;
        goto cleanup;
    }

    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY_I,
            NULL,
            pass1_key) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -5;
        goto cleanup;
    }
    if (cprisk_init_string_decryptor(pass1_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -5;
        goto cleanup;
    }

    cprisk_prepare_deception_material_i(
        root_material, full_anchor_hash, integrity);

    cprisk_sha256_concat2_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            acc_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED_I,
            acc_digest,
            acc_seed) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -6;
        goto cleanup;
    }
    anchor_accumulator = cprisk_rotl64_i(cprisk_u64_from_le_i(acc_seed), 7U);
    cprisk_u64_to_le_i(anchor_accumulator, anchor_acc_le);

    cprisk_sha256_concat3_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            anchor_acc_le,
                            sizeof(anchor_acc_le),
                            loader_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_LOADER_KEY_I,
            loader_digest,
            loader_key) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        rc = -6;
        goto cleanup;
    }

    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_loader_key_mini_vm_bootstrap(loader_key);

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    if (cprisk_load_protected_data() < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_u64_to_le_i(cprisk_get_string_integrity_accumulator(), string_acc_le);
    cprisk_u64_to_le_i(cprisk_get_data_integrity_accumulator(), data_acc_le);
    cprisk_sha256_concat4_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            string_acc_le,
                            sizeof(string_acc_le),
                            data_acc_le,
                            sizeof(data_acc_le),
                            runtime_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL_I,
            runtime_digest,
            s_runtime_material) != 0) {
        cprisk_integrity_poison_whitebox_lane();
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    if (!cprisk_mini_vm_bootstrap_disabled())
        cprisk_mini_vm_bootstrap_material32(s_runtime_material);
    s_runtime_material_ready = 1;
    rc = 0;

cleanup:
    cprisk_secure_zero(pass1_key, sizeof(pass1_key));
    cprisk_secure_zero(acc_digest, sizeof(acc_digest));
    cprisk_secure_zero(acc_seed, sizeof(acc_seed));
    cprisk_secure_zero(loader_digest, sizeof(loader_digest));
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    cprisk_secure_zero(runtime_digest, sizeof(runtime_digest));
    cprisk_secure_zero(anchor_acc_le, sizeof(anchor_acc_le));
    cprisk_secure_zero(string_acc_le, sizeof(string_acc_le));
    cprisk_secure_zero(data_acc_le, sizeof(data_acc_le));
    return rc;
}

/* ── Path A: Mach VM read ──────────────────────────────────────────── */

/* vm_size_t is 32-bit on Darwin; avoid truncation when sz > UINT32_MAX */
#define CPRISK_VM_READ_CHUNK_MAX ((size_t)0xFFFFFFFFUL)

static int path_a(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    uint8_t *buf = NULL;
    buf = (uint8_t *)malloc(sz);
    if (!buf)
        return -1;

    size_t total_read = 0;
    size_t offset = 0;
    while (offset < sz) {
        size_t to_read = sz - offset;
        if (to_read > CPRISK_VM_READ_CHUNK_MAX)
            to_read = CPRISK_VM_READ_CHUNK_MAX;

        vm_size_t vmsz = (vm_size_t)to_read;
        vm_size_t out_sz = vmsz;
        kern_return_t kr = vm_read_overwrite(
            mach_task_self(),
            (vm_address_t)(text + offset),
            vmsz,
            (vm_address_t)(buf + offset),
            &out_sz);
        if (kr != KERN_SUCCESS) {
            cprisk_secure_zero(buf, total_read);
            free(buf);
            return -1;
        }
        total_read += (size_t)out_sz;
        offset += (size_t)out_sz;
        if (out_sz < vmsz)
            break;
    }

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = total_read;
    const uint8_t *p = buf;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    cprisk_secure_zero(buf, total_read);
    free(buf);
    return 0;
}

/* ── Path B: direct pointer read ───────────────────────────────────── */

static int path_b(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = sz;
    const uint8_t *p = text;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    return 0;
}

/* ── Path C: reassemble from split anchor sections ─────────────────── */

static int path_c(const struct mach_header_64 *hdr, uint8_t *out) {
    static const char *names[CPRISK_ARMOR_ANCHOR_LANE_COUNT] = {
        CPRISK_ARMOR_SECTION_ANCHOR_A,
        CPRISK_ARMOR_SECTION_ANCHOR_B,
        CPRISK_ARMOR_SECTION_ANCHOR_C,
        CPRISK_ARMOR_SECTION_ANCHOR_D
    };
    for (uint32_t i = 0; i < CPRISK_ARMOR_ANCHOR_LANE_COUNT; i++) {
        unsigned long sz = 0;
        const uint8_t *p = cprisk_find_section(
            hdr, CPRISK_ARMOR_SEGMENT_DATA, names[i], &sz);
        if (!p || sz < CPRISK_ARMOR_ANCHOR_LANE_SIZE)
            return -1;
        memcpy(out + i * CPRISK_ARMOR_ANCHOR_LANE_SIZE,
               p,
               CPRISK_ARMOR_ANCHOR_LANE_SIZE);
    }
    return 0;
}

static uint64_t cprisk_abs_u64_i(uint64_t lhs, uint64_t rhs) {
    return lhs >= rhs ? (lhs - rhs) : (rhs - lhs);
}

static void cprisk_integrity_timing_canary_i(
    int path_a_rc,
    int path_b_rc,
    uint64_t path_a_ns,
    uint64_t path_b_ns
) {
    if (path_a_rc != 0 || path_b_rc != 0 || path_a_ns == 0u || path_b_ns == 0u) {
        return;
    }

    const uint64_t slower = path_a_ns > path_b_ns ? path_a_ns : path_b_ns;
    const uint64_t faster = path_a_ns > path_b_ns ? path_b_ns : path_a_ns;
    if (faster < 5000u) {
        return;
    }

    const double ratio = (double)slower / (double)faster;
    const uint64_t delta_ns = cprisk_abs_u64_i(path_a_ns, path_b_ns);
    if (ratio >= 48.0 && delta_ns >= 15000000ull) {
        cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_RECHECK);
    }
}

/* ── public API ────────────────────────────────────────────────────── */

int cprisk_compute_integrity_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    uint8_t ha[CPRISK_SHA256_DIGEST_LENGTH];
    uint8_t hb[CPRISK_SHA256_DIGEST_LENGTH];
    uint8_t hc[CPRISK_SHA256_DIGEST_LENGTH];

    const uint64_t path_a_start_ns = cprisk_monotonic_ns();
    int ra = path_a(hdr, ha);
    const uint64_t path_a_end_ns = cprisk_monotonic_ns();

    const uint64_t path_b_start_ns = cprisk_monotonic_ns();
    int rb = path_b(hdr, hb);
    const uint64_t path_b_end_ns = cprisk_monotonic_ns();

    int rc = path_c(hdr, hc);
    uint64_t path_a_ns = 0u;
    uint64_t path_b_ns = 0u;
    if (path_a_end_ns >= path_a_start_ns) {
        path_a_ns = path_a_end_ns - path_a_start_ns;
    }
    if (path_b_end_ns >= path_b_start_ns) {
        path_b_ns = path_b_end_ns - path_b_start_ns;
    }
    cprisk_integrity_timing_canary_i(ra, rb, path_a_ns, path_b_ns);

    uint8_t cat[CPRISK_SHA256_DIGEST_LENGTH * 3];
    if (ra == 0)
        memcpy(cat, ha, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    if (rb == 0)
        memcpy(cat + CPRISK_SHA256_DIGEST_LENGTH, hb, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat + CPRISK_SHA256_DIGEST_LENGTH, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    if (rc == 0)
        memcpy(cat + 2 * CPRISK_SHA256_DIGEST_LENGTH, hc, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat + 2 * CPRISK_SHA256_DIGEST_LENGTH, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    cprisk_sha256(cat, sizeof(cat), out_hash);

    cprisk_secure_zero(ha, sizeof(ha));
    cprisk_secure_zero(hb, sizeof(hb));
    cprisk_secure_zero(hc, sizeof(hc));
    cprisk_secure_zero(cat, sizeof(cat));

    return 0;
}

int cprisk_read_full_anchor_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    /* ABI v2: reconstruct fullHash from split anchor lanes */
    return path_c(hdr, out_hash);
}

int cprisk_verify_anchor_hmac(const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
                              const uint8_t full_hash[CPRISK_ARMOR_HASH_SIZE]) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz < CPRISK_ARMOR_HMAC_FULL_HASH_SECTION_SIZE)
        return -1;

    uint8_t computed_hmac[CPRISK_ARMOR_HASH_SIZE];
    cprisk_hmac_sha256(root_material, CPRISK_ARMOR_KEY_SIZE,
                       full_hash, CPRISK_ARMOR_HASH_SIZE,
                       computed_hmac);

    int result = cprisk_hmac_verify(sec, computed_hmac, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
    return result;
}

static uint64_t cprisk_monotonic_ns(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0)
        mach_timebase_info(&tb);
    if (tb.denom == 0)
        return 0;
    uint64_t abs_time = mach_absolute_time();
    /* Avoid overflow: split multiply to prevent abs_time * numer from wrapping. */
    return abs_time / tb.denom * tb.numer + (abs_time % tb.denom) * tb.numer / tb.denom;
}

int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len) {
    uint64_t t_start = cprisk_monotonic_ns();

    uint8_t root_material[CPRISK_ARMOR_KEY_SIZE];
    uint8_t integrity[CPRISK_ARMOR_HASH_SIZE];
    uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE];
    int rc = -1;

    s_integrity_poisoned = 0;
    cprisk_integrity_poison_semantic_reset_i();
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_anti_dump_hits, 0u);
    atomic_store(&s_staged_opacity_tick, 0ull);
    s_integrity_hash_saved = 0;
    s_integrity_deception_active = 0;
    s_runtime_material_ready = 0;
    s_deception_material_ready = 0;
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    cprisk_secure_zero(s_deception_material, sizeof(s_deception_material));
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    cprisk_mte_canary_remove(&s_runtime_material_canary);
    cprisk_mte_canary_remove(&s_saved_integrity_canary);
#endif
    cprisk_antidebug_reset_plan_state_i();

    cprisk_fill_root_material_i(root_key, root_key_len, root_material);

    /* Reject NULL or all-zero root keys */
    {
        int all_zero = 1;
        for (int zi = 0; zi < CPRISK_ARMOR_KEY_SIZE; zi++) {
            if (root_material[zi] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            rc = -1;
            goto cleanup;
        }
    }

    if (cprisk_compute_integrity_hash(integrity) != 0) {
        rc = -2;
        goto cleanup;
    }

    if (cprisk_validate_pac_cfi_i(root_material, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Reuse adaptive baseline from signal-probe single-step detector. */
    if (cprisk_detect_single_stepping()) {
        s_integrity_deception_active = 1;
    }
#endif

    cprisk_antidebug_apply_policies_i(CPRISK_ADBG_TRIGGER_INIT_I, 0, 0);

    memcpy(s_saved_integrity_hash, integrity, CPRISK_ARMOR_HASH_SIZE);
    s_integrity_hash_saved = 1;

    if (cprisk_read_full_anchor_hash(full_anchor_hash) != 0) {
        rc = -3;
        goto cleanup;
    }

    if (cprisk_whitebox_available() != 0) {
        rc = cprisk_init_protection_whitebox_i(
            root_material,
            full_anchor_hash,
            integrity);
    } else {
        rc = cprisk_init_protection_legacy_i(
            root_material,
            full_anchor_hash,
            integrity);
    }

    /* Initialize three-layer Hybrid KDF (device + session binding).
     * This populates s_effective_root which white-box domains 6-9 consume.
     * Called regardless of the whitebox/legacy init result so that the
     * new domains are available as soon as a valid root_key is provided. */
    (void)cprisk_init_hybrid_kdf(root_key);

    if (rc == 0) {
        /* Keep anti-dump probe lifecycle tied to protection lifecycle,
         * while remaining idempotent when watchdog already started it. */
        (void)cprisk_start_anti_dump_probe(5);
        cprisk_apply_deferred_early_injection_policy();
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
        if (cprisk_mte_available() != 0) {
            if (cprisk_mte_self_test() != 0) {
                cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
                s_runtime_material_ready = 0;
                cprisk_unload_protected_data();
                cprisk_cleanup_string_decryptor();
                cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_RECHECK);
                rc = -8;
            } else if (cprisk_mte_canary_install(
                           &s_runtime_material_canary,
                           s_runtime_material,
                           sizeof(s_runtime_material)) != 0 ||
                       cprisk_mte_canary_install(
                           &s_saved_integrity_canary,
                           s_saved_integrity_hash,
                           sizeof(s_saved_integrity_hash)) != 0) {
                cprisk_mte_canary_remove(&s_runtime_material_canary);
                cprisk_mte_canary_remove(&s_saved_integrity_canary);
                cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
                s_runtime_material_ready = 0;
                cprisk_unload_protected_data();
                cprisk_cleanup_string_decryptor();
                cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_RECHECK);
                rc = -8;
            }
        }
#endif
    }

cleanup:
    if (rc != 0) {
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INIT_FAILURE_I,
            rc,
            rc == -2 ? 1 : 0);
    }
    if (rc != 0) {
        cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
        s_runtime_material_ready = 0;
    }

    cprisk_secure_zero(root_material, sizeof(root_material));
    cprisk_secure_zero(integrity, sizeof(integrity));
    cprisk_secure_zero(full_anchor_hash, sizeof(full_anchor_hash));

    s_init_elapsed_ns = cprisk_monotonic_ns() - t_start;
    return rc;
}

void cprisk_cleanup_protection(void) {
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    cprisk_mte_canary_remove(&s_runtime_material_canary);
    cprisk_mte_canary_remove(&s_saved_integrity_canary);
#endif
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    s_runtime_material_ready = 0;
    cprisk_secure_zero(s_deception_material, sizeof(s_deception_material));
    s_deception_material_ready = 0;
    s_integrity_hash_saved = 0;
    s_integrity_poisoned = 0;
    cprisk_integrity_poison_semantic_reset_i();
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_anti_dump_hits, 0u);
    atomic_store(&s_staged_opacity_tick, 0ull);
    s_integrity_deception_active = 0;
    s_init_elapsed_ns = 0;
    /* Wipe Hybrid KDF state. */
    cprisk_secure_zero(s_device_key, sizeof(s_device_key));
    cprisk_secure_zero(s_effective_root, sizeof(s_effective_root));
    s_device_key_ready = 0;
    s_effective_root_ready = 0;
    cprisk_clear_session_token();
    cprisk_antidebug_reset_plan_state_i();
    cprisk_stop_anti_dump_probe();
    cprisk_cleanup_string_decryptor();
    cprisk_unload_protected_data();
    s_runtime_hardening_mode = CPRISK_RUNTIME_HARDENING_PRODUCTION;
    s_init_timing_threshold_override_ns = 0;
}

static void cprisk_poison_runtime_material_output_mix_i(uint8_t buf[32]) {
    uint64_t h = 0xD6E8FEB86655FD96ULL ^ (uint64_t)s_poison_semantic_breadcrumb;
    h ^= (uint64_t)s_poison_semantic_rolling[0] << 32;
    h ^= (uint64_t)s_poison_semantic_rolling[1];
    h ^= (uint64_t)s_poison_epoch * 0x9E3779B97F4A7C15ULL;
    h ^= s_poison_cause_mix;
    for (size_t i = 0; i < 32u; i++) {
        h ^= (uint64_t)buf[i] ^ ((uint64_t)i * 0x100000001B3ULL);
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53ULL;
        h ^= h >> 33;
        buf[i] ^= (uint8_t)(h & 0xFFu);
        h >>= 8;
        if (h == 0)
            h = 0x9E3779B97F4A7C15ULL ^ (uint64_t)(i + 1u);
    }
}

int cprisk_get_runtime_material(uint8_t out_material[32]) {
    if (!out_material)
        return -1;

    if (s_integrity_poisoned || s_integrity_deception_active || !s_runtime_material_ready) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        memcpy(out_material, s_deception_material, CPRISK_ARMOR_HASH_SIZE);
        cprisk_poison_runtime_material_output_mix_i(out_material);
        return 0;
    }

    memcpy(out_material, s_runtime_material, CPRISK_ARMOR_HASH_SIZE);
    return 0;
}

int cprisk_runtime_material_ready(void) {
    return s_runtime_material_ready ? 1 : 0;
}

enum {
    CPRISK_POISON_RECHECK_SUB_PAC = 0xA01u,
    CPRISK_POISON_RECHECK_SUB_MTE = 0xA02u,
    CPRISK_POISON_RECHECK_SUB_COMPUTE = 0xA03u,
    CPRISK_POISON_RECHECK_SUB_DIFF = 0xA04u,
};

static void cprisk_integrity_poison_from_recheck_i(uint32_t subreason) {
    s_integrity_poisoned = 1;
    s_poison_cause_mix ^= (uint64_t)subreason << 40;
    cprisk_integrity_poison_lane_sidefx_i(CPRISK_POISON_LANE_RECHECK);
    if (cprisk_should_activate_deception_i()) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        cprisk_integrity_poison_lane_tweak_deception_i(CPRISK_POISON_LANE_RECHECK);
    }
}

int cprisk_recheck_integrity(void) {
    if (!s_integrity_hash_saved)
        return -1;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Under debugger: report "all clear" but silently activate deception */
    if (cprisk_is_being_traced_redundant()) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 0;
    }
#endif

    if (cprisk_validate_pac_cfi_i(s_saved_integrity_hash, CPRISK_ARMOR_HASH_SIZE) != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_PAC);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 1;
    }

#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    if (cprisk_mte_canary_verify(&s_runtime_material_canary) != 0 ||
        cprisk_mte_canary_verify(&s_saved_integrity_canary) != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_MTE);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 1;
    }
#endif

    uint8_t current[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_compute_integrity_hash(current) != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_COMPUTE);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            -2);
        cprisk_secure_zero(current, sizeof(current));
        return -2;
    }

    uint8_t diff = 0;
    for (int i = 0; i < CPRISK_ARMOR_HASH_SIZE; i++)
        diff |= current[i] ^ s_saved_integrity_hash[i];

    cprisk_secure_zero(current, sizeof(current));

    if (diff != 0) {
        cprisk_integrity_poison_from_recheck_i(CPRISK_POISON_RECHECK_SUB_DIFF);
        cprisk_antidebug_apply_policies_i(
            CPRISK_ADBG_TRIGGER_INTEGRITY_TAMPER_I,
            0,
            1);
        return 1;
    }
    return 0;
}

int cprisk_is_integrity_poisoned(void) {
    if (s_integrity_deception_active)
        return 0;
    return s_integrity_poisoned;
}

uint32_t cprisk_get_integrity_poison_semantic_breadcrumb(void) {
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_semantic_breadcrumb;
}

uint32_t cprisk_get_integrity_poison_lane_event_count(unsigned lane) {
    if (lane >= (unsigned)CPRISK_POISON_LANE_COUNT)
        return 0u;
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_lane_seq[lane];
}

uint32_t cprisk_get_integrity_poison_epoch(void) {
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_epoch;
}

uint64_t cprisk_get_integrity_poison_cause_mix(void) {
    if (s_integrity_deception_active)
        return 0u;
    return s_poison_cause_mix;
}

void cprisk_integrity_poison_evt_a(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_A);
}

void cprisk_integrity_poison_evt_b(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_B);
}

void cprisk_integrity_poison_watchdog_lane(void) {
    cprisk_integrity_poison_watchdog_lane_staged_i();
}

void cprisk_integrity_poison_watchdog_lane_now(void) {
    atomic_store(&s_staged_watchdog_hits, 0u);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_WATCHDOG);
}

void cprisk_integrity_poison_high_signal_mixed(uint32_t path_tag) {
    if (s_integrity_deception_active)
        return;
    /* Rotate full-lane commits so high-confidence responses are not dominated by a single lane id. */
    const uint32_t pick =
        (path_tag ^ (uint32_t)s_poison_epoch ^ (uint32_t)(s_poison_cause_mix >> 33)) % 5u;
    switch (pick) {
    case 0:
        cprisk_integrity_poison_watchdog_lane_now();
        break;
    case 1:
        cprisk_integrity_poison_antidebug_lane();
        break;
    case 2:
        cprisk_integrity_poison_exception_lane();
        break;
    case 3:
        cprisk_integrity_poison_svc_iface_lane();
        break;
    default:
        cprisk_integrity_poison_data_loader_lane();
        break;
    }
}

void cprisk_apply_deferred_early_injection_policy(void) {
    if (cprisk_get_early_injection_env_mask() == 0u) {
        return;
    }
    if (cprisk_get_runtime_hardening_mode() != CPRISK_RUNTIME_HARDENING_PRODUCTION) {
        return;
    }
    cprisk_integrity_poison_high_signal_mixed(0xE11A0001u);
    cprisk_integrity_poison_watchdog_lane();
}

void cprisk_integrity_poison_code_signing_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_CODE_SIGNING);
}

void cprisk_integrity_poison_svc_iface_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_SVC_IFACE);
}

void cprisk_integrity_poison_antidebug_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_ANTIDEBUG);
}

void cprisk_integrity_poison_exception_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EXCEPTION);
}

void cprisk_integrity_poison_anti_dump_lane(void) {
    cprisk_integrity_poison_anti_dump_lane_staged_i();
}

void cprisk_integrity_poison_anti_dump_lane_now(void) {
    atomic_store(&s_staged_anti_dump_hits, 0u);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_ANTI_DUMP);
}

void cprisk_integrity_poison_data_loader_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_DATA_LOADER);
}

void cprisk_integrity_poison_text_encrypt_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_TEXT_ENCRYPT);
}

void cprisk_integrity_poison_whitebox_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_WHITEBOX);
}

void cprisk_integrity_poison_cff_lane(void) {
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_CFF);
}

void cprisk_force_integrity_poison(void) {
    /* Aggregate: three independent lane commits so semantics are not a single store / single side-effect batch. */
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_A);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_EVT_B);
    cprisk_integrity_poison_lane_full_i(CPRISK_POISON_LANE_FORCE);
}

void cprisk_guard_page_fault_notify(void) {
    s_integrity_poisoned = 1;
    cprisk_integrity_poison_lane_sidefx_i(CPRISK_POISON_LANE_GUARD);
    s_integrity_deception_active = 1;
    cprisk_prepare_deception_material_i(NULL, NULL, NULL);
    cprisk_integrity_poison_lane_tweak_deception_i(CPRISK_POISON_LANE_GUARD);
    cprisk_watchdog_note_guard_page_fault();
}

uint64_t cprisk_get_init_elapsed_ns(void) {
    return s_init_elapsed_ns;
}

void cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t mode) {
    if (mode != CPRISK_RUNTIME_HARDENING_PRODUCTION && mode != CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA &&
        mode != CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE)
        mode = CPRISK_RUNTIME_HARDENING_PRODUCTION;
    s_runtime_hardening_mode = mode;
}

cprisk_runtime_hardening_mode_t cprisk_get_runtime_hardening_mode(void) {
    return (cprisk_runtime_hardening_mode_t)s_runtime_hardening_mode;
}

uint64_t cprisk_get_init_timing_threshold_ns(void) {
    if (s_init_timing_threshold_override_ns != 0)
        return s_init_timing_threshold_override_ns;
    char machine[256];
    size_t len = sizeof(machine);
    int err = 0;
    if (cprisk_sysctlbyname_direct("hw.machine", machine, &len, NULL, 0, &err) != 0 || len == 0) {
        return cprisk_compute_init_timing_threshold_ns_for_machine_i(
            NULL,
            cprisk_get_runtime_hardening_mode());
    }
    if (len >= sizeof(machine))
        len = sizeof(machine) - 1;
    machine[len] = '\0';
    return cprisk_compute_init_timing_threshold_ns_for_machine_i(
        machine,
        cprisk_get_runtime_hardening_mode());
}

void cprisk_test_set_init_timing_threshold_ns_override(uint64_t threshold_ns) {
    s_init_timing_threshold_override_ns = threshold_ns;
}

/* Last signing-path mix tier + fingerprint (server-visible via GrpcReportPayload output_path_integrity). */
static uint32_t s_signing_mix_last_fp;

void cprisk_test_reset_staged_poison_for_tests(void) {
    atomic_store(&s_staged_watchdog_hits, 0u);
    atomic_store(&s_staged_anti_dump_hits, 0u);
    atomic_store(&s_staged_opacity_tick, 0ull);
    s_integrity_poisoned = 0;
    s_integrity_deception_active = 0;
    s_signing_mix_last_fp = 0u;
    cprisk_integrity_poison_semantic_reset_i();
}

/* Passive/cached environment binding for signing/whitebox hot paths: no cprisk_run_all_signal_probes(). */
enum {
    CPRISK_PASSIVE_BINDING_TRACE = 1u << 0,
    CPRISK_PASSIVE_BINDING_DBI = 1u << 1,
    CPRISK_PASSIVE_BINDING_TIMING = 1u << 2,
    CPRISK_PASSIVE_BINDING_LIBC_FALLBACK = 1u << 3,
    CPRISK_PASSIVE_BINDING_TTY = 1u << 4,
    CPRISK_PASSIVE_BINDING_DEVELOPER_DISK = 1u << 5,
};

uint32_t cprisk_collect_passive_signal_binding_bits(void) {
    uint32_t bits = 0u;
    if (cprisk_trace_crosscheck_inconsistent() != 0 || cprisk_is_being_traced_sysctl_only() != 0)
        bits |= CPRISK_PASSIVE_BINDING_TRACE;
    if (cprisk_get_last_dbi_marker_flags() != 0u)
        bits |= CPRISK_PASSIVE_BINDING_DBI;
    if (cprisk_get_last_timing_anomaly_flags() != 0u || cprisk_check_init_timing() != 0)
        bits |= CPRISK_PASSIVE_BINDING_TIMING;
    if (cprisk_get_libc_fallback_used_mask() != 0u)
        bits |= CPRISK_PASSIVE_BINDING_LIBC_FALLBACK;
    if (cprisk_detect_tty_debug() != 0)
        bits |= CPRISK_PASSIVE_BINDING_TTY;
    if (cprisk_detect_developer_disk() != 0)
        bits |= CPRISK_PASSIVE_BINDING_DEVELOPER_DISK;
    return bits;
}

static void cprisk_signing_mix_set_fp_i(uint32_t tier_tag28, uint64_t seed) {
    uint32_t h = (uint32_t)(seed ^ (seed >> 32));
    h ^= tier_tag28 * 0x13579BDFu;
    s_signing_mix_last_fp = (tier_tag28 << 28) | (h & 0x0FFFFFFFu);
}

void cprisk_signing_runtime_material_intermediate_mix(uint8_t buf[32]) {
    if (!buf)
        return;
    if (!s_runtime_material_ready)
        return;
    if (s_integrity_poisoned || s_integrity_deception_active)
        return;

    const uint32_t wd = atomic_load(&s_staged_watchdog_hits);
    const uint32_t ad = atomic_load(&s_staged_anti_dump_hits);
    const uint32_t staged_sum = wd + ad;

    int strong_staged = 0;
    int medium_staged = 0;
    uint64_t seed = 0;

    if (wd > 0u || ad > 0u) {
        seed = atomic_load(&s_staged_opacity_tick) ^ s_poison_cause_mix;
        if (staged_sum == 1u) {
            medium_staged = 1;
        } else {
            strong_staged = 1;
        }
    }

    int weak_only = 0;
    int degraded_tier = 0;
    if (!strong_staged && !medium_staged) {
        const uint32_t passive_bits = cprisk_collect_passive_signal_binding_bits();
        const uint32_t weak_mask =
            CPRISK_PASSIVE_BINDING_TIMING |
            CPRISK_PASSIVE_BINDING_LIBC_FALLBACK |
            CPRISK_PASSIVE_BINDING_TTY |
            CPRISK_PASSIVE_BINDING_DEVELOPER_DISK;
        const uint32_t strongish =
            CPRISK_PASSIVE_BINDING_TRACE |
            CPRISK_PASSIVE_BINDING_DBI;
        if ((passive_bits & weak_mask) != 0u && (passive_bits & strongish) == 0u &&
            cprisk_is_being_traced_redundant() == 0) {
            weak_only = 1;
            seed = (uint64_t)passive_bits * 0xD6E8FEB86655FD96ULL ^ 0x9E3779B97F4A7C15ULL;
        } else if (!weak_only) {
            const int has_tr = (passive_bits & CPRISK_PASSIVE_BINDING_TRACE) != 0u;
            const int has_dbi = (passive_bits & CPRISK_PASSIVE_BINDING_DBI) != 0u;
            if (has_tr || has_dbi) {
                seed = (uint64_t)passive_bits * 0xD6E8FEB86655FD96ULL ^
                       (uint64_t)s_poison_cause_mix ^ atomic_load(&s_staged_opacity_tick);
                if (has_tr && has_dbi) {
                    degraded_tier = 6;
                } else if (has_tr) {
                    degraded_tier = 4;
                } else {
                    degraded_tier = 5;
                }
            }
        }
    }

    /* Ambient / hook-surface tier: wb_pressure has trace/VM/mprotect/timing/libc bits (2–7)
     * but staged + passive paths above did not already classify — e.g. Mach↔POSIX mprotect
     * mismatch without TTY/timing weak bucket. Perturbs signing material only (not raw runtime bytes). */
    int ambient = 0;
    if (!strong_staged && !medium_staged && !weak_only && degraded_tier == 0) {
        const uint32_t wp = cprisk_integrity_wb_prf_pressure_mask();
        if ((wp & 0xFCu) != 0u) {
            ambient = 1;
            seed = (uint64_t)wp * 0xD6E8FEB86655FD96ULL;
            seed ^= (uint64_t)cprisk_get_vm_mprotect_crosscheck_mismatch_count() << 32;
            seed ^= (uint64_t)cprisk_get_vm_mprotect_mach_trap_mismatch_count();
            seed ^= atomic_load(&s_staged_opacity_tick);
            seed ^= s_poison_cause_mix;
        }
    }

    if (!strong_staged && !medium_staged && !weak_only && degraded_tier == 0 && !ambient)
        return;

    uint8_t seed_le[8];
    cprisk_u64_to_le_i(seed, seed_le);
    cprisk_sha256_ctx ctx;

    if (strong_staged) {
        static const uint8_t k_lab[] = "cprisk.sign.intermediate.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab, sizeof(k_lab) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 32u; i++) {
            buf[i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(3u, seed);
    } else if (medium_staged) {
        static const uint8_t k_lab_m[] = "cprisk.sign.intermediate.medium.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_m, sizeof(k_lab_m) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 16u; i++) {
            buf[8u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(2u, seed);
    } else if (weak_only) {
        static const uint8_t k_lab_p[] = "cprisk.sign.intermediate.partial.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_p, sizeof(k_lab_p) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 8u; i++) {
            buf[24u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(1u, seed);
    } else if (degraded_tier == 6) {
        static const uint8_t k_lab_td[] = "cprisk.sign.intermediate.degraded.trace_dbi.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_td, sizeof(k_lab_td) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 32u; i++) {
            buf[i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(6u, seed);
    } else if (degraded_tier == 4) {
        static const uint8_t k_lab_tr[] = "cprisk.sign.intermediate.degraded.trace.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_tr, sizeof(k_lab_tr) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 16u; i++) {
            buf[8u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(4u, seed);
    } else if (degraded_tier == 5) {
        static const uint8_t k_lab_db[] = "cprisk.sign.intermediate.degraded.dbi.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_db, sizeof(k_lab_db) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 16u; i++) {
            buf[8u + i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(5u, seed);
    } else if (ambient) {
        static const uint8_t k_lab_am[] = "cprisk.sign.intermediate.ambient.v1";
        cprisk_sha256_init(&ctx);
        cprisk_sha256_update(&ctx, k_lab_am, sizeof(k_lab_am) - 1u);
        cprisk_sha256_update(&ctx, seed_le, sizeof(seed_le));
        cprisk_sha256_update(&ctx, buf, 32);
        uint8_t mask[32];
        cprisk_sha256_final(&ctx, mask);
        for (size_t i = 0; i < 8u; i++) {
            buf[i] ^= mask[i];
        }
        cprisk_secure_zero(mask, sizeof(mask));
        cprisk_signing_mix_set_fp_i(7u, seed);
    }
    cprisk_secure_zero(seed_le, sizeof(seed_le));
}

uint32_t cprisk_get_signing_mix_fingerprint(void) {
    return s_signing_mix_last_fp;
}

uint32_t cprisk_integrity_wb_prf_pressure_mask(void) {
    uint32_t m = 0u;
    if (atomic_load(&s_staged_watchdog_hits) > 0u)
        m |= 1u;
    if (atomic_load(&s_staged_anti_dump_hits) > 0u)
        m |= 2u;
    const uint32_t pb = cprisk_collect_passive_signal_binding_bits();
    if ((pb & (CPRISK_PASSIVE_BINDING_TRACE | CPRISK_PASSIVE_BINDING_DBI)) != 0u)
        m |= 4u;
    if (cprisk_get_vm_mprotect_crosscheck_mismatch_count() > 0u)
        m |= 8u;
    if (cprisk_get_vm_mprotect_mach_trap_mismatch_count() > 0u)
        m |= 16u;
    if (cprisk_is_mprotect_tampered() != 0)
        m |= 32u;
    if ((pb & CPRISK_PASSIVE_BINDING_TIMING) != 0u)
        m |= 64u;
    if ((pb & (CPRISK_PASSIVE_BINDING_TTY | CPRISK_PASSIVE_BINDING_DEVELOPER_DISK |
               CPRISK_PASSIVE_BINDING_LIBC_FALLBACK)) != 0u)
        m |= 128u;
    return m;
}

uint64_t cprisk_test_init_timing_threshold_ns_for_machine(
    const char *machine,
    cprisk_runtime_hardening_mode_t mode
) {
    return cprisk_compute_init_timing_threshold_ns_for_machine_i(machine, mode);
}

int cprisk_check_init_timing(void) {
    const uint64_t thr = cprisk_get_init_timing_threshold_ns();
    return s_init_elapsed_ns > thr ? 1 : 0;
}

void cprisk_test_secure_zero(void *buf, size_t len) {
    cprisk_secure_zero(buf, len);
}

/* ── Hybrid Key Derivation (Three-Layer KDF) ───────────────────────── */

int cprisk_init_hybrid_kdf(const uint8_t *root_key) {
    if (!root_key)
        return -1;

    /* Reset hybrid KDF state. */
    cprisk_secure_zero(s_device_key, sizeof(s_device_key));
    cprisk_secure_zero(s_effective_root, sizeof(s_effective_root));
    s_device_key_ready = 0;
    s_effective_root_ready = 0;

    /* Layer 2: Derive device key.
     * deviceKey = HMAC(rootKey, deviceSalt)
     * deviceSalt is sourced from IOKit/Keychain when available,
     * or the static fallback salt. */
    if (cprisk_derive_device_key(root_key, s_device_key) == 0) {
        s_device_key_ready = 1;
    }

    /* Layer 3: Try to retrieve session key.
     * If no session token is active, we fall through to the
     * device-key-only path. */
    uint8_t session_key[CPRISK_ARMOR_KEY_SIZE];
    cprisk_secure_zero(session_key, sizeof(session_key));
    int has_session = (cprisk_get_session_key(session_key) == 0);

    /* Compute effective root: the key used for white-box domains 6-9
     * and any subsequent device/session-bound derivations. */
    if (has_session && s_device_key_ready) {
        /* effectiveRoot = HMAC(deviceKey, sessionKey)
         * This binds the key to both the device AND the session. */
        cprisk_hmac_sha256(s_device_key, CPRISK_ARMOR_KEY_SIZE,
                           session_key, CPRISK_ARMOR_KEY_SIZE,
                           s_effective_root);
        s_effective_root_ready = 1;
    } else if (s_device_key_ready) {
        /* Fallback when no session token: effectiveRoot = deviceKey.
         * Key is still bound to the physical device. */
        memcpy(s_effective_root, s_device_key, CPRISK_ARMOR_KEY_SIZE);
        s_effective_root_ready = 1;
    } else {
        /* Final fallback: effectiveRoot = rootKey.
         * This preserves backward compatibility when device/session
         * binding is not available. */
        memcpy(s_effective_root, root_key, CPRISK_ARMOR_KEY_SIZE);
        s_effective_root_ready = 1;
    }

    cprisk_secure_zero(session_key, sizeof(session_key));

    return 0;
}

int cprisk_get_device_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;
    if (!s_device_key_ready)
        return -1;
    memcpy(out_key, s_device_key, CPRISK_ARMOR_KEY_SIZE);
    return 0;
}

int cprisk_get_effective_root(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;
    if (!s_effective_root_ready)
        return -1;
    memcpy(out_key, s_effective_root, CPRISK_ARMOR_KEY_SIZE);
    return 0;
}
