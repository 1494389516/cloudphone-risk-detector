/* A1: original global reads retained. Not the proposed production parameter ABI. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "constants.inc"
#include "types.inc"
#ifndef CPRISK_VMP_PREFIX
#error "Define CPRISK_VMP_PREFIX"
#endif
#define JOIN_I(a,b) a##b
#define JOIN(a,b) JOIN_I(a,b)
#define API(n) JOIN(CPRISK_VMP_PREFIX,n)
_Static_assert(sizeof(cprisk_adbg_runtime_plan_t) == 48, "plan size");
_Static_assert(_Alignof(cprisk_adbg_runtime_plan_t) == 8, "plan alignment");
_Static_assert(offsetof(cprisk_adbg_runtime_plan_t, policy_union_bits) == 20, "policy offset");
_Static_assert(offsetof(cprisk_adbg_runtime_plan_t, seed) == 24, "seed offset");
_Static_assert(offsetof(cprisk_adbg_runtime_plan_t, probe_immediate) == 40, "probe offset");
_Static_assert(sizeof(cprisk_adbg_runtime_entry_t) == 32, "entry size");
_Static_assert(_Alignof(cprisk_adbg_runtime_entry_t) == 8, "entry alignment");
_Static_assert(offsetof(cprisk_adbg_runtime_entry_t, policy_bits) == 20, "entry policy offset");
_Static_assert(offsetof(cprisk_adbg_runtime_entry_t, entry_flags) == 24, "flags offset");
_Static_assert(offsetof(cprisk_adbg_runtime_entry_t, scatter_slot) == 28, "scatter offset");
static cprisk_adbg_runtime_plan_t s_adbg_plan_i;
static cprisk_adbg_runtime_entry_t s_adbg_entries_i[CPRISK_MAX_ENTRY_COUNT];
static uint32_t s_adbg_entry_count_i;

/* Test setup/observation are native and serial; never counted as VM targets. */
void API(set_state)(const cprisk_adbg_runtime_plan_t *plan,
                    const cprisk_adbg_runtime_entry_t *entries, uint32_t count) {
    memcpy(&s_adbg_plan_i, plan, sizeof(*plan));
    memcpy(s_adbg_entries_i, entries, sizeof(s_adbg_entries_i));
    s_adbg_entry_count_i = count;
}
int API(state_matches)(const cprisk_adbg_runtime_plan_t *plan,
                      const cprisk_adbg_runtime_entry_t *entries, uint32_t count) {
    return s_adbg_entry_count_i == count &&
        memcmp(&s_adbg_plan_i, plan, sizeof(*plan)) == 0 &&
        memcmp(s_adbg_entries_i, entries, sizeof(s_adbg_entries_i)) == 0;
}
#define cprisk_antidebug_select_policy_bits_i API(cprisk_antidebug_select_policy_bits_i)
#if defined(CPRISK_VMP_PROTECTED) && defined(__clang__)
#define static __attribute__((noinline, annotate("obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0)")))
#else
#define static
#endif
#include "body.inc"
#undef static
