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
