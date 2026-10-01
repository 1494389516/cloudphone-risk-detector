/* Compile this exact SDK source twice. No handwritten replacement algorithm. */
#ifndef CPRISK_VMP_PREFIX
#error "CPRISK_VMP_PREFIX must be plain_ or protected_"
#endif
#define CPRISK_JOIN_INNER(a,b) a##b
#define CPRISK_JOIN(a,b) CPRISK_JOIN_INNER(a,b)
#define CPRISK_NAME(n) CPRISK_JOIN(CPRISK_VMP_PREFIX,n)
#define vm_stack_crypto_init CPRISK_NAME(vm_stack_crypto_init)
#define vm_stack_encrypt_push CPRISK_NAME(vm_stack_encrypt_push)
#define vm_stack_decrypt_pop CPRISK_NAME(vm_stack_decrypt_pop)
#define vm_stack_push_encrypted CPRISK_NAME(vm_stack_push_encrypted)
#define vm_stack_pop_encrypted CPRISK_NAME(vm_stack_pop_encrypted)
#define vm_stack_peek_encrypted CPRISK_NAME(vm_stack_peek_encrypted)
#define vm_stack_load_encrypted CPRISK_NAME(vm_stack_load_encrypted)
#define vm_stack_store_encrypted CPRISK_NAME(vm_stack_store_encrypted)
#define vm_stack_crypto_clear CPRISK_NAME(vm_stack_crypto_clear)
#define vm_stack_encrypt_region CPRISK_NAME(vm_stack_encrypt_region)
#define vm_stack_decrypt_region CPRISK_NAME(vm_stack_decrypt_region)
#define vm_stack_verify_integrity CPRISK_NAME(vm_stack_verify_integrity)
#include "../../RiskDetectorApp/Sources/CRiskCore/vm_stack_crypto.h"
#if defined(CPRISK_VMP_PROTECTED) && defined(__clang__)
#define CPRISK_TARGET __attribute__((noinline, annotate("obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0)")))
#else
#define CPRISK_TARGET
#endif
CPRISK_TARGET int vm_stack_crypto_init(vm_stack_crypto_ctx_t *, uint64_t, const uint8_t [32]);
CPRISK_TARGET uint64_t vm_stack_encrypt_push(const vm_stack_crypto_ctx_t *, uint64_t);
CPRISK_TARGET int vm_stack_push_encrypted(vm_stack_crypto_ctx_t *, uint64_t *, uint32_t *, uint32_t, uint64_t);
#include "../../RiskDetectorApp/Sources/CRiskCore/vm_stack_crypto.c"
