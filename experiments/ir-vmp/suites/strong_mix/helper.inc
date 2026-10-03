static uint8_t cprisk_rotl8_i(uint8_t value, unsigned int shift) {
    shift &= 7U;
    if (shift == 0U)
        return value;
    return (uint8_t)((value << shift) | (value >> (8U - shift)));
}
