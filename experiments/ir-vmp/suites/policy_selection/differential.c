#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "constants.inc"
#include "types.inc"
#ifndef CPRISK_TEST_SEED
#define CPRISK_TEST_SEED 1
#endif
#ifndef CPRISK_RANDOM_CASES
#define CPRISK_RANDOM_CASES 10000
#endif
#define DECLARE(P) \
 uint32_t P##cprisk_antidebug_select_policy_bits_i(uint32_t,int,uint32_t*,uint64_t*); \
 void P##set_state(const cprisk_adbg_runtime_plan_t*,const cprisk_adbg_runtime_entry_t*,uint32_t); \
 int P##state_matches(const cprisk_adbg_runtime_plan_t*,const cprisk_adbg_runtime_entry_t*,uint32_t);
DECLARE(plain_)
DECLARE(protected_)
static uint64_t rng = CPRISK_TEST_SEED;
static unsigned cases;
static uint64_t next(void) { rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL line=%d case=%u seed=%llu\n",__LINE__,cases,(unsigned long long)CPRISK_TEST_SEED); return 1; } } while(0)

static int compare(const cprisk_adbg_runtime_plan_t *p,
                   const cprisk_adbg_runtime_entry_t *e, uint32_t n,
                   uint32_t probes, int high, unsigned nullable) {
    struct count_out { uint32_t a, value, b; } c[2];
    struct mix_out { uint64_t a, value, b; } m[2];
    memset(c,0xa5,sizeof(c)); memset(m,0x5a,sizeof(m));
    plain_set_state(p,e,n); protected_set_state(p,e,n);
    uint32_t x=plain_cprisk_antidebug_select_policy_bits_i(probes,high,
        nullable&1 ? NULL:&c[0].value,nullable&2 ? NULL:&m[0].value);
    uint32_t y=protected_cprisk_antidebug_select_policy_bits_i(probes,high,
        nullable&1 ? NULL:&c[1].value,nullable&2 ? NULL:&m[1].value);
    CHECK(x==y); CHECK(memcmp(&c[0],&c[1],sizeof(c[0]))==0);
    CHECK(memcmp(&m[0],&m[1],sizeof(m[0]))==0);
    /* Independent value oracle, including the cancellation with selection fixed. */
    uint32_t bits=0, count=0; uint64_t mix=0;
    uint64_t seed=p->seed ^ ((uint64_t)probes<<11) ^ ((uint64_t)p->probe_immediate<<3) ^ UINT64_C(0x9e3779b97f4a7c15);
    for(uint32_t i=0;i<n;i++) {
        uint64_t rest=seed ^ ((uint64_t)e[i].scatter_slot<<32) ^ ((uint64_t)e[i].entry_flags<<9);
        uint64_t gate=e[i].identifier_hash ^ rest;
        if(e[i].policy_bits && ((e[i].policy_bits&1u) || (high ? gate%4!=0 : gate%8==0))) {
            bits|=e[i].policy_bits; count++; mix^=rest;
        }
    }
    CHECK(x==(bits ? bits:p->policy_union_bits));
    CHECK(c[0].value==(nullable&1 ? UINT32_C(0xa5a5a5a5):count));
    CHECK(m[0].value==(nullable&2 ? UINT64_C(0x5a5a5a5a5a5a5a5a):mix));
    for(unsigned i=0;i<2;i++) {
        CHECK(c[i].a==UINT32_C(0xa5a5a5a5) && c[i].b==UINT32_C(0xa5a5a5a5));
        CHECK(m[i].a==UINT64_C(0x5a5a5a5a5a5a5a5a) && m[i].b==UINT64_C(0x5a5a5a5a5a5a5a5a));
    }
    CHECK(plain_state_matches(p,e,n)); CHECK(protected_state_matches(p,e,n));
    ++cases; return 0;
}
int main(void) {
    cprisk_adbg_runtime_plan_t p;
    cprisk_adbg_runtime_entry_t e[CPRISK_MAX_ENTRY_COUNT];
    const int risks[]={0,1,-1,2,-7,INT_MIN,INT_MAX};
    const uint32_t counts[]={0,1,CPRISK_MAX_ENTRY_COUNT};
    for(unsigned pattern=0;pattern<6;pattern++) for(unsigned n=0;n<3;n++) {
        memset(&p,0,sizeof(p)); memset(e,0,sizeof(e));
        p.policy_union_bits=0xfe; p.seed=pattern&1?UINT64_MAX:0; p.probe_immediate=pattern;
        for(unsigned j=0;j<CPRISK_MAX_ENTRY_COUNT;j++) {
            e[j].identifier_hash=pattern==2 ? UINT64_C(0x9e3779b97f4a7c15) ^ p.seed ^ ((uint64_t)p.probe_immediate<<3) : (uint64_t)j;
            e[j].policy_bits=pattern==0?0:pattern==1?1:2u<<(j%6);
            e[j].scatter_slot=pattern>=3?UINT32_MAX:0;
            e[j].entry_flags=pattern>=4?UINT32_MAX:0;
        }
        for(unsigned h=0;h<7;h++) for(unsigned out=0;out<4;out++)
            CHECK(compare(&p,e,counts[n],0,risks[h],out)==0);
    }
    for(unsigned k=0;k<CPRISK_RANDOM_CASES;k++) {
        memset(&p,0,sizeof(p)); memset(e,0,sizeof(e));
        p.seed=next(); p.policy_union_bits=(uint32_t)next(); p.probe_immediate=(uint32_t)next();
        for(unsigned j=0;j<CPRISK_MAX_ENTRY_COUNT;j++) {
            e[j].identifier_hash=next(); e[j].policy_bits=(uint32_t)next();
            e[j].entry_flags=(uint32_t)next(); e[j].scatter_slot=(uint32_t)next();
        }
        uint32_t n=(uint32_t)(next()%65), probes=(uint32_t)next();
        CHECK(compare(&p,e,n,probes,risks[k%7],k%4)==0);
    }
    printf("PASS cases=%u random_cases=%u seed=%llu\n",cases,CPRISK_RANDOM_CASES,(unsigned long long)CPRISK_TEST_SEED);
    return 0;
}
