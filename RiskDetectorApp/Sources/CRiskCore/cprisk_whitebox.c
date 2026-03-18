#include "include/CRiskCore.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include "include/cprisk_macho.h"

#define CPRISK_WHITEBOX_DOMAIN_COUNT 5u
#define CPRISK_WHITEBOX_STATE_SIZE 32u
#define CPRISK_WHITEBOX_ROUND_COUNT 4u
#define CPRISK_WHITEBOX_TABLE_WIDTH 256u
#define CPRISK_WHITEBOX_TABLE_STRIDE (CPRISK_WHITEBOX_STATE_SIZE * CPRISK_WHITEBOX_TABLE_WIDTH)
#define CPRISK_WHITEBOX_DOMAIN_TABLE_BYTES (CPRISK_WHITEBOX_ROUND_COUNT * CPRISK_WHITEBOX_TABLE_STRIDE)

enum {
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG = 1u,
    CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY = 2u,
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED = 3u,
    CPRISK_WHITEBOX_DOMAIN_LOADER_KEY = 4u,
    CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL = 5u
};

static const uint8_t s_empty_byte_i = 0;
static const uint8_t s_zero_state_i[CPRISK_WHITEBOX_STATE_SIZE] = {0};
static const uint8_t s_overall_tag_label_i[] = "cprisk.whitebox.tag.v1";

#pragma pack(push, 1)
struct cprisk_whitebox_domain_record_i {
    uint32_t domain_id;
    uint32_t round_count;
    uint32_t table_offset;
    uint32_t table_length;
    uint8_t permutation[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t final_mask[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t round_constants[CPRISK_WHITEBOX_ROUND_COUNT * CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t record_digest[CPRISK_ARMOR_HASH_SIZE];
};
#pragma pack(pop)

_Static_assert(sizeof(struct cprisk_whitebox_domain_record_i) == 240,
               "whitebox domain record ABI drift");

struct cprisk_whitebox_bundle_i {
    struct cprisk_armor_whitebox_header header;
    const uint8_t *code;
    size_t code_len;
    const uint8_t *data;
    size_t data_len;
    const uint8_t *tag;
    const struct cprisk_whitebox_domain_record_i *records;
    size_t record_count;
};

struct cprisk_whitebox_test_bundle_i {
    uint8_t *meta;
    size_t meta_len;
    uint8_t *code;
    size_t code_len;
    uint8_t *data;
    size_t data_len;
    uint8_t *tag;
    size_t tag_len;
    int active;
};

static struct cprisk_whitebox_test_bundle_i s_test_bundle_i = {0};

static void cprisk_test_clear_whitebox_bundle_i(void) {
    if (s_test_bundle_i.meta) {
        cprisk_secure_zero(s_test_bundle_i.meta, s_test_bundle_i.meta_len);
        free(s_test_bundle_i.meta);
    }
    if (s_test_bundle_i.code) {
        cprisk_secure_zero(s_test_bundle_i.code, s_test_bundle_i.code_len);
        free(s_test_bundle_i.code);
    }
    if (s_test_bundle_i.data) {
        cprisk_secure_zero(s_test_bundle_i.data, s_test_bundle_i.data_len);
        free(s_test_bundle_i.data);
    }
    if (s_test_bundle_i.tag) {
        cprisk_secure_zero(s_test_bundle_i.tag, s_test_bundle_i.tag_len);
        free(s_test_bundle_i.tag);
    }
    memset(&s_test_bundle_i, 0, sizeof(s_test_bundle_i));
}

static int cprisk_test_copy_bytes_i(uint8_t **out,
                                    const uint8_t *src,
                                    size_t len) {
    if (!out || !src || len == 0)
        return -1;
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy)
        return -1;
    memcpy(copy, src, len);
    *out = copy;
    return 0;
}

int cprisk_test_set_whitebox_bundle(
    const uint8_t *meta,
    size_t meta_len,
    const uint8_t *code,
    size_t code_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *tag,
    size_t tag_len
) {
    if (!meta || meta_len < sizeof(struct cprisk_armor_whitebox_header) ||
        !code || code_len == 0 ||
        !data || data_len == 0 ||
        !tag || tag_len == 0) {
        return -1;
    }

    cprisk_test_clear_whitebox_bundle_i();

    if (cprisk_test_copy_bytes_i(&s_test_bundle_i.meta, meta, meta_len) != 0 ||
        cprisk_test_copy_bytes_i(&s_test_bundle_i.code, code, code_len) != 0 ||
        cprisk_test_copy_bytes_i(&s_test_bundle_i.data, data, data_len) != 0 ||
        cprisk_test_copy_bytes_i(&s_test_bundle_i.tag, tag, tag_len) != 0) {
        cprisk_test_clear_whitebox_bundle_i();
        return -1;
    }

    s_test_bundle_i.meta_len = meta_len;
    s_test_bundle_i.code_len = code_len;
    s_test_bundle_i.data_len = data_len;
    s_test_bundle_i.tag_len = tag_len;
    s_test_bundle_i.active = 1;
    return 0;
}

void cprisk_test_clear_whitebox_bundle(void) {
    cprisk_test_clear_whitebox_bundle_i();
}

static const struct mach_header_64 *cprisk_whitebox_hdr_i(void) {
    return cprisk_find_own_header((const void *)cprisk_whitebox_hdr_i);
}

static const uint8_t *cprisk_nonnull_bytes_i(const uint8_t *ptr) {
    return ptr ? ptr : &s_empty_byte_i;
}

static void cprisk_hex_encode_i(const uint8_t *src, size_t len, char *out_hex) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2] = hex[(src[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex[src[i] & 0x0F];
    }
    out_hex[len * 2] = '\0';
}

static size_t cprisk_cstrnlen_i(const char *value, size_t max_len) {
    size_t len = 0;
    if (!value)
        return 0;
    while (len < max_len && value[len] != '\0')
        len++;
    return len;
}

static int cprisk_ct_ascii_eq_i(const char *lhs, const char *rhs, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)lhs[i] ^ (uint8_t)rhs[i];
    return diff == 0 ? 0 : -1;
}

static uint8_t cprisk_rotl8_i(uint8_t value, unsigned int shift) {
    shift &= 7U;
    if (shift == 0U)
        return value;
    return (uint8_t)((value << shift) | (value >> (8U - shift)));
}

static int cprisk_read_whitebox_header_i(
    struct cprisk_armor_whitebox_header *out_header,
    int *present_out
) {
    if (present_out)
        *present_out = 0;

    if (s_test_bundle_i.active) {
        if (s_test_bundle_i.meta_len < sizeof(struct cprisk_armor_whitebox_header))
            return 0;
        if (present_out)
            *present_out = 1;
        if (out_header) {
            memcpy(out_header,
                   s_test_bundle_i.meta,
                   sizeof(struct cprisk_armor_whitebox_header));
        }
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_whitebox_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sec_size = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_WHITEBOX_META,
        &sec_size);
    if (!sec || sec_size < sizeof(struct cprisk_armor_whitebox_header))
        return 0;

    if (present_out)
        *present_out = 1;
    if (out_header)
        memcpy(out_header, sec, sizeof(struct cprisk_armor_whitebox_header));
    return 0;
}

static int cprisk_whitebox_header_valid_i(
    const struct cprisk_armor_whitebox_header *header
) {
    if (!header)
        return 0;
    if (header->magic != CPRISK_ARMOR_WHITEBOX_MAGIC)
        return 0;
    if (header->version < CPRISK_ARMOR_WHITEBOX_ABI_VERSION)
        return 0;
    return 1;
}

static int cprisk_whitebox_tag_matches_i(
    const uint8_t expected[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t *actual,
    size_t actual_len
) {
    if (!actual || actual_len != CPRISK_ARMOR_HASH_SIZE)
        return -1;
    return cprisk_hmac_verify(expected, actual, CPRISK_ARMOR_HASH_SIZE);
}

static int cprisk_whitebox_config_digest_valid_i(
    const struct cprisk_armor_whitebox_header *header,
    const uint8_t *code,
    size_t code_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *tag,
    size_t tag_len
) {
    if (!header || !code || !data || !tag)
        return -1;
    if (tag_len != CPRISK_ARMOR_HASH_SIZE)
        return -1;

    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, code, code_len);
    cprisk_sha256_update(&ctx, data, data_len);
    cprisk_sha256_update(&ctx, tag, tag_len);
    cprisk_sha256_final(&ctx, digest);

    const int rc = cprisk_hmac_verify(header->config_digest,
                                      digest,
                                      sizeof(digest));
    cprisk_secure_zero(digest, sizeof(digest));
    return rc;
}

static int cprisk_whitebox_payload_coverage_valid_i(
    const struct cprisk_whitebox_domain_record_i *records,
    size_t record_count,
    size_t code_len
) {
    size_t total = 0;
    for (size_t i = 0; i < record_count; i++) {
        const size_t start_i = (size_t)records[i].table_offset;
        const size_t len_i = (size_t)records[i].table_length;
        const size_t end_i = start_i + len_i;

        if (start_i > code_len || len_i > code_len - start_i)
            return -1;
        if (total > code_len - len_i)
            return -1;
        total += len_i;

        for (size_t j = i + 1; j < record_count; j++) {
            const size_t start_j = (size_t)records[j].table_offset;
            const size_t len_j = (size_t)records[j].table_length;
            const size_t end_j = start_j + len_j;

            if (start_j > code_len || len_j > code_len - start_j)
                return -1;
            if (!(end_i <= start_j || end_j <= start_i))
                return -1;
        }
    }

    return total == code_len ? 0 : -1;
}

static int cprisk_whitebox_permutation_valid_i(const uint8_t permutation[32]) {
    uint32_t seen = 0;
    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++) {
        const uint8_t value = permutation[i];
        if (value >= CPRISK_WHITEBOX_STATE_SIZE)
            return -1;
        if ((seen & (1u << value)) != 0u)
            return -1;
        seen |= (1u << value);
    }
    return seen == 0xFFFFFFFFu ? 0 : -1;
}

static int cprisk_whitebox_record_digest_valid_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    const struct cprisk_whitebox_domain_record_i *record
) {
    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx ctx;

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx,
                         bundle->code + record->table_offset,
                         (size_t)record->table_length);
    cprisk_sha256_update(&ctx,
                         record->permutation,
                         sizeof(record->permutation));
    cprisk_sha256_update(&ctx,
                         record->final_mask,
                         sizeof(record->final_mask));
    cprisk_sha256_update(&ctx,
                         record->round_constants,
                         sizeof(record->round_constants));
    cprisk_sha256_final(&ctx, digest);

    const int rc = cprisk_hmac_verify(record->record_digest,
                                      digest,
                                      sizeof(digest));
    cprisk_secure_zero(digest, sizeof(digest));
    return rc;
}

static int cprisk_whitebox_validate_bundle_i(struct cprisk_whitebox_bundle_i *out_bundle) {
    unsigned long meta_size = 0;
    unsigned long code_size = 0;
    unsigned long data_size = 0;
    unsigned long tag_size = 0;
    const uint8_t *meta = NULL;
    const uint8_t *code = NULL;
    const uint8_t *data = NULL;
    const uint8_t *tag = NULL;

    if (s_test_bundle_i.active) {
        meta = s_test_bundle_i.meta;
        meta_size = (unsigned long)s_test_bundle_i.meta_len;
        code = s_test_bundle_i.code;
        code_size = (unsigned long)s_test_bundle_i.code_len;
        data = s_test_bundle_i.data;
        data_size = (unsigned long)s_test_bundle_i.data_len;
        tag = s_test_bundle_i.tag;
        tag_size = (unsigned long)s_test_bundle_i.tag_len;
    } else {
        const struct mach_header_64 *hdr = cprisk_whitebox_hdr_i();
        if (!hdr)
            return -1;
        meta = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_META,
            &meta_size);
        code = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_CODE,
            &code_size);
        data = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_DATA,
            &data_size);
        tag = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_WHITEBOX_TAG,
            &tag_size);
    }

    if (!meta || meta_size < sizeof(struct cprisk_armor_whitebox_header))
        return -1;
    if (!code || code_size == 0 || !data || data_size == 0 || !tag)
        return -1;

    const struct cprisk_armor_whitebox_header *header =
        (const struct cprisk_armor_whitebox_header *)meta;
    if (!cprisk_whitebox_header_valid_i(header))
        return -1;

    const size_t code_len = (size_t)code_size;
    const size_t data_len = (size_t)data_size;
    if (code_len > SIZE_MAX - data_len)
        return -1;
    const size_t payload_len = code_len + data_len;
    /* payload_size covers only the executable white-box payload body (code + data).
       The detached tag section is authenticated independently and excluded from
       this field by the producer. */
    if (header->payload_size != 0u &&
        (size_t)header->payload_size != payload_len)
        return -1;
    if (tag_size != CPRISK_ARMOR_HASH_SIZE)
        return -1;
    if ((data_len % sizeof(struct cprisk_whitebox_domain_record_i)) != 0u)
        return -1;

    const size_t record_count = data_len / sizeof(struct cprisk_whitebox_domain_record_i);
    if (record_count != CPRISK_WHITEBOX_DOMAIN_COUNT)
        return -1;

    const struct cprisk_whitebox_domain_record_i *records =
        (const struct cprisk_whitebox_domain_record_i *)data;
    struct cprisk_whitebox_bundle_i bundle_view;
    memset(&bundle_view, 0, sizeof(bundle_view));
    memcpy(&bundle_view.header, header, sizeof(bundle_view.header));
    bundle_view.code = code;
    bundle_view.code_len = code_len;
    bundle_view.data = data;
    bundle_view.data_len = data_len;
    bundle_view.tag = tag;
    bundle_view.records = records;
    bundle_view.record_count = record_count;

    uint8_t overall_tag[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256_ctx overall_ctx;
    cprisk_sha256_init(&overall_ctx);
    cprisk_sha256_update(&overall_ctx,
                         s_overall_tag_label_i,
                         sizeof(s_overall_tag_label_i) - 1u);
    cprisk_sha256_update(&overall_ctx, code, code_len);
    cprisk_sha256_update(&overall_ctx, data, data_len);
    cprisk_sha256_final(&overall_ctx, overall_tag);
    if (cprisk_whitebox_tag_matches_i(overall_tag, tag, (size_t)tag_size) != 0) {
        cprisk_secure_zero(overall_tag, sizeof(overall_tag));
        return -1;
    }
    cprisk_secure_zero(overall_tag, sizeof(overall_tag));

    if (cprisk_whitebox_config_digest_valid_i(header,
                                              code,
                                              code_len,
                                              data,
                                              data_len,
                                              tag,
                                              (size_t)tag_size) != 0) {
        return -1;
    }

    if (cprisk_whitebox_payload_coverage_valid_i(records, record_count, code_len) != 0)
        return -1;

    uint32_t domain_mask = 0;
    for (size_t i = 0; i < record_count; i++) {
        const struct cprisk_whitebox_domain_record_i *record = &records[i];
        if (record->domain_id < CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG ||
            record->domain_id > CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL)
            return -1;
        if (record->round_count != CPRISK_WHITEBOX_ROUND_COUNT)
            return -1;
        if (record->table_length != CPRISK_WHITEBOX_DOMAIN_TABLE_BYTES)
            return -1;
        if (cprisk_whitebox_permutation_valid_i(record->permutation) != 0)
            return -1;
        if (cprisk_whitebox_record_digest_valid_i(&bundle_view, record) != 0)
            return -1;

        const uint32_t bit = 1u << (record->domain_id - 1u);
        if ((domain_mask & bit) != 0u)
            return -1;
        domain_mask |= bit;
    }

    if (domain_mask != ((1u << CPRISK_WHITEBOX_DOMAIN_COUNT) - 1u))
        return -1;

    if (out_bundle) {
        memcpy(out_bundle, &bundle_view, sizeof(*out_bundle));
    }
    cprisk_secure_zero(&bundle_view.header, sizeof(bundle_view.header));
    return 0;
}

static const struct cprisk_whitebox_domain_record_i *cprisk_whitebox_record_for_domain_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    uint32_t domain_id
) {
    if (!bundle || !bundle->records)
        return NULL;
    for (size_t i = 0; i < bundle->record_count; i++) {
        if (bundle->records[i].domain_id == domain_id)
            return &bundle->records[i];
    }
    return NULL;
}

static int cprisk_whitebox_eval_record_i(
    const struct cprisk_whitebox_bundle_i *bundle,
    const struct cprisk_whitebox_domain_record_i *record,
    const uint8_t input[32],
    uint8_t out[32]
) {
    if (!bundle || !record || !input || !out)
        return -1;

    const uint8_t *tables = bundle->code + record->table_offset;
    uint8_t state[CPRISK_WHITEBOX_STATE_SIZE];
    uint8_t next[CPRISK_WHITEBOX_STATE_SIZE];
    memcpy(state, input, sizeof(state));

    for (size_t round = 0; round < CPRISK_WHITEBOX_ROUND_COUNT; round++) {
        const uint8_t *round_tables = tables + round * CPRISK_WHITEBOX_TABLE_STRIDE;
        const uint8_t *round_constants =
            record->round_constants + round * CPRISK_WHITEBOX_STATE_SIZE;

        for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++) {
            const uint8_t *table = round_tables + i * CPRISK_WHITEBOX_TABLE_WIDTH;
            const uint8_t table_value = table[state[i]];
            const uint8_t mixed = (uint8_t)(table_value ^
                                            state[(i + 1u) % CPRISK_WHITEBOX_STATE_SIZE] ^
                                            round_constants[i]);
            next[i] = cprisk_rotl8_i(
                mixed,
                (unsigned int)(((i + round) % 7u) + 1u));
        }

        for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++)
            state[i] = next[record->permutation[i]];
    }

    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++)
        out[i] = (uint8_t)(state[i] ^ record->final_mask[i]);

    cprisk_secure_zero(state, sizeof(state));
    cprisk_secure_zero(next, sizeof(next));
    return 0;
}

static uint32_t cprisk_base_capabilities_i(void) {
    return CPRISK_ARMOR_CAP_RUNTIME_DERIVE_KEY |
           CPRISK_ARMOR_CAP_RUNTIME_SIGN_HELPER |
           CPRISK_ARMOR_CAP_RUNTIME_VERIFY_HELPER |
           CPRISK_ARMOR_CAP_WHITEBOX_FRAMEWORK;
}

uint32_t cprisk_get_armor_capabilities(void) {
    uint32_t capabilities = cprisk_base_capabilities_i();
    struct cprisk_whitebox_bundle_i bundle;
    memset(&bundle, 0, sizeof(bundle));

    if (cprisk_whitebox_validate_bundle_i(&bundle) == 0)
        capabilities |= CPRISK_ARMOR_CAP_WHITEBOX_SECTION_LAYOUT;

    cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
    return capabilities;
}

int cprisk_whitebox_probe(struct cprisk_whitebox_probe_result *out_probe) {
    if (!out_probe)
        return -1;

    memset(out_probe, 0, sizeof(*out_probe));
    out_probe->abi_version = CPRISK_ARMOR_WHITEBOX_ABI_VERSION;
    out_probe->capabilities = cprisk_base_capabilities_i();
    out_probe->flags = CPRISK_WHITEBOX_PROBE_FLAG_COMPILED;

    struct cprisk_armor_whitebox_header header;
    int present = 0;
    memset(&header, 0, sizeof(header));

    if (cprisk_read_whitebox_header_i(&header, &present) == 0 && present) {
        out_probe->flags |= CPRISK_WHITEBOX_PROBE_FLAG_METADATA_PRESENT;
        out_probe->metadata_version = header.version;
    }

    struct cprisk_whitebox_bundle_i bundle;
    memset(&bundle, 0, sizeof(bundle));
    if (cprisk_whitebox_validate_bundle_i(&bundle) == 0) {
        out_probe->flags |= CPRISK_WHITEBOX_PROBE_FLAG_METADATA_VALID;
        out_probe->flags |= CPRISK_WHITEBOX_PROBE_FLAG_ENGINE_READY;
        out_probe->capabilities |= CPRISK_ARMOR_CAP_WHITEBOX_SECTION_LAYOUT;
        out_probe->metadata_version = bundle.header.version;
    }

    cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
    cprisk_secure_zero(&header, sizeof(header));
    return 0;
}

int cprisk_whitebox_available(void) {
    return cprisk_whitebox_validate_bundle_i(NULL) == 0 ? 1 : 0;
}

int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Entry trace check: deterministic but incorrect PRF output */
    if (cprisk_is_being_traced()) {
        const uint8_t *src = input ? input : s_zero_state_i;
        cprisk_sha256_ctx pctx;
        cprisk_sha256_init(&pctx);
        cprisk_sha256_update(&pctx, src, CPRISK_WHITEBOX_STATE_SIZE);
        cprisk_sha256_final(&pctx, out);
        return 0;
    }
#endif

    struct cprisk_whitebox_bundle_i bundle;
    memset(&bundle, 0, sizeof(bundle));
    if (cprisk_whitebox_validate_bundle_i(&bundle) != 0)
        return -1;

    const struct cprisk_whitebox_domain_record_i *record =
        cprisk_whitebox_record_for_domain_i(&bundle, domain_id);
    if (!record) {
        cprisk_secure_zero(&bundle.header, sizeof(bundle.header));
        return -1;
    }

    const int rc = cprisk_whitebox_eval_record_i(
        &bundle,
        record,
        input ? input : s_zero_state_i,
        out);
    cprisk_secure_zero(&bundle.header, sizeof(bundle.header));

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Exit trace check: debugger may attach mid-evaluation */
    if (rc == 0 && cprisk_is_being_traced()) {
        const uint8_t *src = input ? input : s_zero_state_i;
        cprisk_sha256_ctx pctx;
        cprisk_sha256_init(&pctx);
        cprisk_sha256_update(&pctx, src, CPRISK_WHITEBOX_STATE_SIZE);
        cprisk_sha256_final(&pctx, out);
    }
#endif

    return rc;
}

int cprisk_derive_effective_signing_key(
    const uint8_t *base_key,
    size_t base_key_len,
    uint8_t out_key[32]
) {
    if (!out_key)
        return -1;
    if (cprisk_runtime_material_ready() == 0)
        return -1;
    if (!base_key && base_key_len != 0)
        return -1;

    uint8_t runtime_material[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_get_runtime_material(runtime_material) != 0)
        return -1;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Corrupt runtime material under debugger so derived key is silently wrong */
    if (cprisk_is_being_traced()) {
        for (size_t pi = 0; pi < CPRISK_ARMOR_HASH_SIZE; pi++)
            runtime_material[pi] ^= 0xA5u;
    }
#endif

    cprisk_hmac_sha256(runtime_material,
                       CPRISK_ARMOR_HASH_SIZE,
                       cprisk_nonnull_bytes_i(base_key),
                       base_key_len,
                       out_key);
    cprisk_secure_zero(runtime_material, sizeof(runtime_material));
    return 0;
}

int cprisk_derive_effective_signing_key_hex(
    const uint8_t *base_key,
    size_t base_key_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!out_hex)
        return -1;

    uint8_t derived_key[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_derive_effective_signing_key(base_key, base_key_len, derived_key) != 0)
        return -1;

    cprisk_hex_encode_i(derived_key, sizeof(derived_key), out_hex);
    cprisk_secure_zero(derived_key, sizeof(derived_key));
    return 0;
}

int cprisk_hmac_sha256_hex(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!out_hex)
        return -1;
    if (!key && key_len != 0)
        return -1;
    if (!msg && msg_len != 0)
        return -1;

    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_hmac_sha256(cprisk_nonnull_bytes_i(key),
                       key_len,
                       cprisk_nonnull_bytes_i(msg),
                       msg_len,
                       digest);
    cprisk_hex_encode_i(digest, sizeof(digest), out_hex);
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

int cprisk_sign_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
) {
    if (!out_hex)
        return -1;
    if (!msg && msg_len != 0)
        return -1;

    uint8_t derived_key[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_derive_effective_signing_key(base_key, base_key_len, derived_key) != 0)
        return -1;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Flip select key bytes under debugger — signature silently invalid */
    if (cprisk_is_being_traced()) {
        derived_key[0]  ^= 0xFFu;
        derived_key[7]  ^= 0xFFu;
        derived_key[15] ^= 0xFFu;
        derived_key[23] ^= 0xFFu;
    }
#endif

    const int rc = cprisk_hmac_sha256_hex(derived_key,
                                          sizeof(derived_key),
                                          msg,
                                          msg_len,
                                          out_hex);
    cprisk_secure_zero(derived_key, sizeof(derived_key));
    return rc;
}

int cprisk_verify_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const char *expected_hex
) {
    if (!expected_hex)
        return -1;

    const size_t expected_len = cprisk_cstrnlen_i(
        expected_hex, CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1);
    if (expected_len != CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE)
        return -1;

    char computed_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1];
    memset(computed_hex, 0, sizeof(computed_hex));
    if (cprisk_sign_with_derived_key(base_key,
                                     base_key_len,
                                     msg,
                                     msg_len,
                                     computed_hex) != 0) {
        cprisk_secure_zero(computed_hex, sizeof(computed_hex));
        return -1;
    }

    const int rc = cprisk_ct_ascii_eq_i(
        computed_hex,
        expected_hex,
        CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE);
    cprisk_secure_zero(computed_hex, sizeof(computed_hex));
    return rc;
}
