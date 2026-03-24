/*
 * One page of __TEXT padding — never referenced by code. Runtime may
 * vm_protect(PROT_NONE) it as an anti-dump honeypot (sequential reads hit it).
 */
#include <stdint.h>

__attribute__((used, section("__TEXT,__cprisk_pad"), aligned(4096)))
static const uint8_t cprisk_text_honeypot_pad[4096] = {0};
