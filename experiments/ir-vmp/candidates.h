#ifndef CPRISK_IR_VMP_CANDIDATES_H
#define CPRISK_IR_VMP_CANDIDATES_H
#include "../../RiskDetectorApp/Sources/CRiskCore/vm_stack_crypto.h"
#define CPRISK_DECLARE(P) \
int P##vm_stack_crypto_init(vm_stack_crypto_ctx_t *, uint64_t, const uint8_t [32]); \
uint64_t P##vm_stack_encrypt_push(const vm_stack_crypto_ctx_t *, uint64_t); \
int P##vm_stack_push_encrypted(vm_stack_crypto_ctx_t *, uint64_t *, uint32_t *, uint32_t, uint64_t);
CPRISK_DECLARE(plain_)
CPRISK_DECLARE(protected_)
#undef CPRISK_DECLARE
#endif
