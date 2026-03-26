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
    const uint64_t identity_imm =
        (imm & ~CPRISK_VM_BRANCH_IND_MODE_MASK) | CPRISK_VM_BRANCH_IND_MODE_IDENTITY;
    const uint64_t expected_pc =
        ((uint64_t)CPRISK_VM_INSN_WIDTH * (uint64_t)CPRISK_VM_INSN_WIDTH);

    memset(&fr, 0, sizeof(fr));
    memset(&result, 0, sizeof(result));

    fr.out = &result;
    fr.vpc_a = (uint64_t)CPRISK_VM_INSN_WIDTH;
    fr.vpc_b = 0u;
    fr.blen = CPRISK_VM_INSN_WIDTH * 3u;
    fr.encoded_pc = 0u;

    if (cprisk_vm_oph_branch_ind(
            &fr,
            0u,
            CPRISK_VM_OP_BRANCH_IND,
            identity_imm,
            0u,
            0u) != CPRISK_VM_FLOW_CONTINUE) {
        return -1;
    }
    if (result.status != 0u || result.poison_flags != 0u) {
        return -1;
    }
    if (fr.steps != 1u || fr.encoded_pc != expected_pc) {
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
