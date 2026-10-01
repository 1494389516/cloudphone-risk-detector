static uint64_t cprisk_gf2_xorshift64(uint64_t s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

static uint64_t cprisk_gf2_fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a 64-bit offset basis
    for (size_t i = 0u; i < len; ++i) {
        h ^= (uint64_t)data[i];
        h *= 0x100000001b3ULL;            // FNV-1a 64-bit prime
    }
    return h;
}
