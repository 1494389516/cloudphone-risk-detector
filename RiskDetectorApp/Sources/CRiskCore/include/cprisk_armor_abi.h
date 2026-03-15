#ifndef CPRISK_ARMOR_ABI_H
#define CPRISK_ARMOR_ABI_H

#include <stdint.h>

#define CPRISK_ARMOR_ABI_VERSION 1u

#define CPRISK_ARMOR_KEY_SIZE 32u
#define CPRISK_ARMOR_HASH_SIZE 32u

#define CPRISK_ARMOR_SEGMENT_DATA "__DATA"

#define CPRISK_ARMOR_SECTION_STRTAB "__swift5_types2"
#define CPRISK_ARMOR_SECTION_LOADER "__swift5_proto2"
#define CPRISK_ARMOR_SECTION_PROTECTED_DATA "__swift5_mpenum"
#define CPRISK_ARMOR_SECTION_ANCHOR_A "__swift5_aa"
#define CPRISK_ARMOR_SECTION_ANCHOR_B "__swift5_ab"
#define CPRISK_ARMOR_SECTION_ANCHOR_C "__swift5_ac"
#define CPRISK_ARMOR_SECTION_ANCHOR_D "__swift5_ad"
#define CPRISK_ARMOR_SECTION_FULL_HASH "__swift5_acfun"

#define CPRISK_ARMOR_BOOTSTRAP_STRING_ID 1u

#define CPRISK_ARMOR_STRTAB_MAGIC 0x43505354u  /* table guard sentinel */
#define CPRISK_ARMOR_LOADER_MAGIC 0x4350524Bu  /* descriptor guard sentinel */

#define CPRISK_ARMOR_ANCHOR_LANE_COUNT 4u
#define CPRISK_ARMOR_ANCHOR_LANE_SIZE 8u
#define CPRISK_ARMOR_FULL_HASH_SECTION_SIZE (CPRISK_ARMOR_HASH_SIZE * 2u)

#pragma pack(push, 1)

struct cprisk_armor_strtab_header {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
};

struct cprisk_armor_strtab_index_entry {
    uint32_t string_id;
    uint32_t data_offset;
    uint32_t data_length;
};

struct cprisk_armor_loader_header {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
};

struct cprisk_armor_loader_entry {
    char     segment_name[16];
    char     section_name[16];
    uint32_t key_id;
    uint32_t flags;
    uint64_t vm_addr;
    uint64_t size;
    uint8_t  content_hash[CPRISK_ARMOR_HASH_SIZE];
};

#pragma pack(pop)

_Static_assert(sizeof(struct cprisk_armor_strtab_header) == 12,
               "cprisk strtab header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_strtab_index_entry) == 12,
               "cprisk strtab index ABI drift");
_Static_assert(sizeof(struct cprisk_armor_loader_header) == 12,
               "cprisk loader header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_loader_entry) == 88,
               "cprisk loader entry ABI drift");
_Static_assert(CPRISK_ARMOR_ANCHOR_LANE_COUNT * CPRISK_ARMOR_ANCHOR_LANE_SIZE ==
                   CPRISK_ARMOR_HASH_SIZE,
               "split anchor sections must reconstruct a 32-byte hash");

/* ── compile-time salt obfuscation ──────────────────────────────────── */

#define CPRISK_SALT_XOR_KEY 0xA7

static inline void cprisk_decode_salt(const uint8_t *encoded, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(encoded[i] ^ CPRISK_SALT_XOR_KEY);
    out[len] = '\0';
}

#endif /* CPRISK_ARMOR_ABI_H */
