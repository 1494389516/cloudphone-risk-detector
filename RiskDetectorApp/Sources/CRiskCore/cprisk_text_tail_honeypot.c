/*
 * One page of __TEXT padding — never referenced by code. Runtime may
 * vm_protect(PROT_NONE) it as an anti-dump honeypot (sequential reads hit it).
 *
 * Issue 81: this page contains NO fake credential strings (no passwords,
 * tokens, keys, or anything that looks like a credential). At build time
 * it is all zeros; at runtime it is overwritten with OS entropy (see
 * cprisk_text_honeypot_fill_entropy_i in cprisk_text_encrypt.c). A
 * honeypot must never carry plausible credentials — those would be
 * harvested as real secrets.
 */
#include <stdint.h>

__attribute__((used, section("__TEXT,__cprisk_pad"), aligned(4096)))
static const uint8_t cprisk_text_honeypot_pad[4096] = {0};
