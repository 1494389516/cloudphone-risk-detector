static void cprisk_whitebox_strong_mix_layer_i(
    const uint8_t in[CPRISK_WHITEBOX_STATE_SIZE],
    const uint8_t *round_constants,
    uint8_t out[CPRISK_WHITEBOX_STATE_SIZE]
) {
    for (size_t i = 0; i < CPRISK_WHITEBOX_STATE_SIZE; i++) {
        const uint8_t rc = round_constants[(i * 7u + 3u) % CPRISK_WHITEBOX_STATE_SIZE];
        const uint8_t lane0 = in[i];
        const uint8_t lane1 = cprisk_rotl8_i(in[(i + 7u) % CPRISK_WHITEBOX_STATE_SIZE], 1u);
        const uint8_t lane2 = cprisk_rotl8_i(in[(i + 13u) % CPRISK_WHITEBOX_STATE_SIZE], 3u);
        const uint8_t lane3 = cprisk_rotl8_i(in[(i + 23u) % CPRISK_WHITEBOX_STATE_SIZE], 5u);
        out[i] = (uint8_t)(lane0 ^ lane1 ^ lane2 ^ lane3 ^ rc);
    }
}
