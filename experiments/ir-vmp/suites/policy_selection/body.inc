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
