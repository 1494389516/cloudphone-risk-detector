#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter_internal.h"

#include <string.h>

int cprisk_test_vm_branch_ind_identity(
    uint64_t imm,
    uint64_t *out_encoded_pc_after,
    uint64_t *out_steps
) {
    cprisk_vm_interp_frame_t fr;
    cprisk_vm_run_result_t result;
    const uint64_t expected_pc =
        ((uint64_t)CPRISK_VM_INSN_WIDTH * (uint64_t)CPRISK_VM_INSN_WIDTH);
    const int is_semi_identity =
        ((imm & CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_MASK) == CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_TAG);
    const int is_semi_semantic =
        ((imm & CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_MASK) == CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_TAG);

    const uint32_t forward_span = is_semi_semantic
        ? (uint32_t)((imm >> 8) & 0xFFu) : 0u;
    const uint32_t total_insn_slots = 3u + forward_span;

    memset(&fr, 0, sizeof(fr));
    memset(&result, 0, sizeof(result));

    fr.out = &result;
    fr.vpc_a = (uint64_t)CPRISK_VM_INSN_WIDTH;
    fr.vpc_b = 0u;
    fr.blen = CPRISK_VM_INSN_WIDTH * total_insn_slots;
    fr.encoded_pc = 0u;

    if (cprisk_vm_oph_branch_ind(
            &fr,
            0u,
            CPRISK_VM_OP_BRANCH_IND,
            imm,
            0u,
            0u) != CPRISK_VM_FLOW_CONTINUE) {
        return -1;
    }
    if (result.status != 0u || result.poison_flags != 0u) {
        return -1;
    }
    if (fr.steps != 1u) {
        return -1;
    }
    if (is_semi_identity && fr.encoded_pc != expected_pc) {
        return -1;
    }
    if (is_semi_semantic) {
        const uint64_t min_pc = (uint64_t)CPRISK_VM_INSN_WIDTH * (uint64_t)CPRISK_VM_INSN_WIDTH;
        const uint64_t max_pc = (uint64_t)(1u + forward_span) * CPRISK_VM_INSN_WIDTH
                                * (uint64_t)CPRISK_VM_INSN_WIDTH;
        if (fr.encoded_pc < min_pc || fr.encoded_pc > max_pc) {
            return -1;
        }
    }

    if (out_encoded_pc_after != NULL) {
        *out_encoded_pc_after = fr.encoded_pc;
    }
    if (out_steps != NULL) {
        *out_steps = fr.steps;
    }
    return 0;
}

int cprisk_test_vm_branch_ind_semi_semantic(
    uint64_t imm,
    uint64_t *out_encoded_pc_after,
    uint64_t *out_steps
) {
    if ((imm & CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_MASK) != CPRISK_VM_BRANCH_IND_SEMI_SEMANTIC_TAG) {
        return -1;
    }
    const uint32_t forward_span = (uint32_t)((imm >> 8) & 0xFFu);
    const uint32_t total_insn_slots = 16u + forward_span;

    cprisk_vm_interp_frame_t fr;
    cprisk_vm_run_result_t result;
    memset(&fr, 0, sizeof(fr));
    memset(&result, 0, sizeof(result));

    fr.out = &result;
    fr.vpc_a = (uint64_t)CPRISK_VM_INSN_WIDTH;
    fr.vpc_b = 0u;
    fr.blen = CPRISK_VM_INSN_WIDTH * total_insn_slots;
    fr.encoded_pc = 0u;

    if (cprisk_vm_oph_branch_ind(
            &fr, 0u, CPRISK_VM_OP_BRANCH_IND, imm, 0u, 0u) != CPRISK_VM_FLOW_CONTINUE) {
        return -1;
    }
    if (result.status != 0u || result.poison_flags != 0u) {
        return -1;
    }
    if (fr.steps != 1u) {
        return -1;
    }
    const uint64_t min_pc = (uint64_t)CPRISK_VM_INSN_WIDTH * (uint64_t)CPRISK_VM_INSN_WIDTH;
    const uint64_t max_pc = (uint64_t)(1u + forward_span) * CPRISK_VM_INSN_WIDTH
                            * (uint64_t)CPRISK_VM_INSN_WIDTH;
    if (fr.encoded_pc < min_pc || fr.encoded_pc > max_pc) {
        return -1;
    }

    if (out_encoded_pc_after != NULL) {
        *out_encoded_pc_after = fr.encoded_pc;
    }
    if (out_steps != NULL) {
        *out_steps = fr.steps;
    }
    return 0;
}
