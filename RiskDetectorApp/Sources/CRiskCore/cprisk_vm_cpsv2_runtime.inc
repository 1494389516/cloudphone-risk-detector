/* Included after key derivation. No allocation or code read before validation. */
static int cprisk_vm_cpsv2_observe_i(const struct mach_header_64 *hdr, uint32_t *tag) {
#if defined(__APPLE__)
    if (!hdr || !tag || hdr->ncmds > 4096u || hdr->sizeofcmds > 0x2000000u) return 0;
    uint8_t uuid[16] = {0};
    unsigned uuid_count = 0;
    const uint8_t *cmds = (const uint8_t *)(hdr + 1);
    size_t offset = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (offset > hdr->sizeofcmds || hdr->sizeofcmds - offset < 8u) return 0;
        uint32_t kind = cprisk_cpsv2_u32(cmds + offset);
        uint32_t size = cprisk_cpsv2_u32(cmds + offset + 4);
        if (size < 8u || size > hdr->sizeofcmds - offset) return 0;
        if (kind == LC_UUID) {
            if (size != 24u || ++uuid_count != 1u) return 0;
            memcpy(uuid, cmds + offset + 8, sizeof(uuid));
        }
        offset += size;
    }
    if (uuid_count != 1u || offset != hdr->sizeofcmds) return 0;
    unsigned long manifest_size = 0, text_size = 0;
    const uint8_t *manifest = cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_VMP_SELF_SPANS, &manifest_size);
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &text_size);
    uintptr_t base = (uintptr_t)hdr;
    if (!manifest || manifest_size != CPRISK_CPSV2_BYTES || !text || (uintptr_t)text < base
        || text_size > UINTPTR_MAX - (uintptr_t)text) return 0;
    uint8_t snapshot[CPRISK_CPSV2_BYTES];
    memcpy(snapshot, manifest, sizeof(snapshot));
    /* Deliberately separate from the pointer-free manifest. Taking these
     * addresses also retains each required function in the linked image. */
    const void *const identities[CPRISK_CPSV2_COUNT] = {
#define CPRISK_CPSV2_IDENTITY(name) (const void *)&name,
#include "cprisk_vm_cpsv2_roster.inc"
#undef CPRISK_CPSV2_IDENTITY
    };
    uint64_t expected_rvas[CPRISK_CPSV2_COUNT];
    for (unsigned i = 0; i < CPRISK_CPSV2_COUNT; i++) {
        if ((uintptr_t)identities[i] < base) return 0;
        expected_rvas[i] = (uintptr_t)identities[i] - base;
    }
    cprisk_cpsv2_range ranges[CPRISK_CPSV2_COUNT];
    if (!cprisk_cpsv2_parse(snapshot, sizeof(snapshot), uuid, expected_rvas,
                            (uintptr_t)text - base, text_size, ranges)) return 0;

    uint8_t material[32] = {0}, key[32];
    if (cprisk_get_runtime_material(material) != 0) {
        cprisk_secure_zero(material, sizeof(material));
        return 0;
    }
    cprisk_vm_selfchk_hmac_key_i(material, key);
    cprisk_secure_zero(material, sizeof(material));
    *tag = cprisk_cpsv2_tag(key, snapshot, base, ranges);
    cprisk_secure_zero(key, sizeof(key));
    return 1;
#else
    (void)hdr; (void)tag;
    return 0; /* No shipping non-Mach-O substitute. */
#endif
}
