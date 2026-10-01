/* Exact extracted SDK static function bodies; verify_sources.py enforces provenance. */
#include <stdint.h>
#include <stddef.h>
#ifndef CPRISK_VMP_PREFIX
#error "Define CPRISK_VMP_PREFIX"
#endif
#define JOIN_I(a,b) a##b
#define JOIN(a,b) JOIN_I(a,b)
#define cprisk_gf2_xorshift64 JOIN(CPRISK_VMP_PREFIX,cprisk_gf2_xorshift64)
#define cprisk_gf2_fnv1a JOIN(CPRISK_VMP_PREFIX,cprisk_gf2_fnv1a)
#if defined(CPRISK_VMP_PROTECTED) && defined(__clang__)
#define TARGET __attribute__((noinline, annotate("obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0)")))
#else
#define TARGET
#endif
/* Change linkage only to expose the exact bodies to the cross-object harness. */
#define static TARGET
#include "gf2_candidates.inc"
#undef static
