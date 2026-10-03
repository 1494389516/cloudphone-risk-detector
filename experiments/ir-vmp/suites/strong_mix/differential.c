#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef CPRISK_TEST_SEED
#define CPRISK_TEST_SEED 1
#endif
#ifndef CPRISK_RANDOM_CASES
#define CPRISK_RANDOM_CASES 10000
#endif
void plain_cprisk_whitebox_strong_mix_layer_i(const uint8_t*,const uint8_t*,uint8_t*);
void protected_cprisk_whitebox_strong_mix_layer_i(const uint8_t*,const uint8_t*,uint8_t*);
static uint64_t rng=CPRISK_TEST_SEED;
static unsigned cases;
static uint64_t next(void) { rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"FAIL line=%d case=%u seed=%llu\n",__LINE__,cases,(unsigned long long)CPRISK_TEST_SEED);return 1; } } while(0)
static uint8_t rotate(uint8_t n,unsigned s) { return (uint8_t)((unsigned)n*(1u<<s)+(unsigned)n/(1u<<(8-s))); }
static int compare(const uint8_t in[32],const uint8_t rc[32]) {
    uint8_t input[34],constants[34],input_copy[34],constants_copy[34],a[34],b[34];
    memset(input,0xc3,sizeof(input)); memset(constants,0x3c,sizeof(constants));
    memcpy(input+1,in,32); memcpy(constants+1,rc,32);
    memcpy(input_copy,input,34); memcpy(constants_copy,constants,34);
    memset(a,0xa5,34); memset(b,0xa5,34);
    plain_cprisk_whitebox_strong_mix_layer_i(input+1,constants+1,a+1);
    CHECK(memcmp(input,input_copy,34)==0 && memcmp(constants,constants_copy,34)==0);
    protected_cprisk_whitebox_strong_mix_layer_i(input+1,constants+1,b+1);
    CHECK(memcmp(input,input_copy,34)==0 && memcmp(constants,constants_copy,34)==0);
    CHECK(memcmp(a,b,34)==0); CHECK(a[0]==0xa5 && a[33]==0xa5);
    for(unsigned i=0;i<32;i++) CHECK(a[i+1]==(uint8_t)(in[i]^rotate(in[(i+7)%32],1)^rotate(in[(i+13)%32],3)^rotate(in[(i+23)%32],5)^rc[(i*7+3)%32]));
    ++cases;return 0;
}
int main(void) {
    uint8_t in[32],rc[32];
    for(unsigned p=0;p<4;p++) {
        for(unsigned i=0;i<32;i++) { in[i]=p<2?(p?255:0):(i&1?0x55:0xaa); rc[i]=p==3?255:in[i]; }
        CHECK(compare(in,rc)==0);
    }
    for(unsigned side=0;side<2;side++) for(unsigned bit=0;bit<256;bit++) {
        memset(in,0,32);memset(rc,0,32);(side?rc:in)[bit/8]=(uint8_t)(1u<<(bit%8));
        CHECK(compare(in,rc)==0);
    }
    for(unsigned value=0;value<256;value++) {
        memset(in,(int)value,32);memset(rc,(int)(255-value),32);CHECK(compare(in,rc)==0);
    }
    for(unsigned k=0;k<CPRISK_RANDOM_CASES;k++) {
        for(unsigned i=0;i<32;i++) {in[i]=(uint8_t)next();rc[i]=(uint8_t)next();}
        CHECK(compare(in,rc)==0);
    }
    printf("PASS cases=%u random_cases=%u seed=%llu\n",cases,CPRISK_RANDOM_CASES,(unsigned long long)CPRISK_TEST_SEED);
    return 0;
}
