#include <stdint.h>
#include <stddef.h>
#include "constants.inc"
#ifndef CPRISK_VMP_PREFIX
#error "Define CPRISK_VMP_PREFIX"
#endif
#define JOIN_I(a,b) a##b
#define JOIN(a,b) JOIN_I(a,b)
/* Keep the exact original helper body; require inlining to avoid xollvm's
 * unaccepted i8-return native call ABI. preflight rejects any surviving call.
 * This declaration-only experiment transform is included in dependency hashes. */
#define static static inline __attribute__((always_inline))
#include "helper.inc"
#undef static
#define cprisk_whitebox_strong_mix_layer_i JOIN(CPRISK_VMP_PREFIX,cprisk_whitebox_strong_mix_layer_i)
#if defined(CPRISK_VMP_PROTECTED) && defined(__clang__)
#define static __attribute__((noinline, annotate("obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0)")))
#else
#define static
#endif
#include "body.inc"
#undef static
