/* Semantic baseline and transformed/native differential test. Not a VMP proof. */
#include "candidates.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

static unsigned cases;
static uint64_t seed = UINT64_C(0x783cb86db73074ac);
static uint64_t next_u64(void) {
    seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
    return seed;
}
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL line=%d case=%u: %s\n", __LINE__, cases, #c); return 1; } } while (0)

int main(void) {
    const uint64_t edges[] = {0,1,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffffffff),UINT64_C(0xaaaaaaaaaaaaaaaa)};
    for (unsigned i=0; i<4096; ++i) {
        uint8_t key[32], original_key[32];
        for (unsigned j=0; j<32; ++j) key[j]=(uint8_t)next_u64();
        if(i<2) memset(key,i?255:0,sizeof(key));
        memcpy(original_key,key,sizeof(key));
        uint64_t id=i<6?edges[i]:next_u64(), value=i<6?edges[i]:next_u64();
        vm_stack_crypto_ctx_t a,b;
        memset(&a,0xa5,sizeof(a)); memset(&b,0xa5,sizeof(b));
        int ra=plain_vm_stack_crypto_init(&a,id,key), rb=protected_vm_stack_crypto_init(&b,id,key);
        CHECK(ra==rb && ra==VM_STACK_OK); CHECK(memcmp(&a,&b,sizeof(a))==0);
        CHECK(memcmp(key,original_key,sizeof(key))==0);
        CHECK(a.stack_rot>=8 && a.stack_rot<=63);
        vm_stack_crypto_ctx_t saved=a;
        CHECK(plain_vm_stack_encrypt_push(&a,value)==protected_vm_stack_encrypt_push(&b,value));
        CHECK(memcmp(&a,&saved,sizeof(a))==0 && memcmp(&b,&saved,sizeof(b))==0);
        uint64_t sa[10],sb[10];
        for(unsigned j=0;j<10;++j) sa[j]=sb[j]=next_u64();
        uint32_t spa=i%9,spb=spa;
        /* Valid buffer indexes only; capacity rejection is tested independently. */
        uint32_t capacity=i%4==0?spa:8;
        if(i%7==0) a.initialized=b.initialized=0;
        if(i%11==0) a.access_count=b.access_count=UINT32_MAX;
        vm_stack_crypto_ctx_t before=a; uint64_t before_stack[10]; memcpy(before_stack,sa,sizeof(sa));
        uint32_t before_sp=spa;
        ra=plain_vm_stack_push_encrypted(&a,sa+1,&spa,capacity,value);
        rb=protected_vm_stack_push_encrypted(&b,sb+1,&spb,capacity,value);
        CHECK(ra==rb && spa==spb); CHECK(memcmp(&a,&b,sizeof(a))==0); CHECK(memcmp(sa,sb,sizeof(sa))==0);
        CHECK(sa[0]==before_stack[0] && sa[9]==before_stack[9]);
        if(ra!=VM_STACK_OK) { CHECK(spa==before_sp); CHECK(memcmp(sa,before_stack,sizeof(sa))==0); CHECK(memcmp(&a,&before,sizeof(a))==0); }
        else { CHECK(spa==before_sp+1); CHECK(a.access_count==(uint32_t)(before.access_count+1)); }
        ++cases;
    }
    uint8_t key[32]={0}; vm_stack_crypto_ctx_t a,b;
    memset(&a,0xa5,sizeof(a)); b=a;
    CHECK(plain_vm_stack_crypto_init(NULL,0,key)==protected_vm_stack_crypto_init(NULL,0,key));
    CHECK(plain_vm_stack_crypto_init(&a,0,NULL)==VM_STACK_ERROR_INVALID_PARAM);
    CHECK(protected_vm_stack_crypto_init(&b,0,NULL)==VM_STACK_ERROR_INVALID_PARAM);
    CHECK(memcmp(&a,&b,sizeof(a))==0);
    CHECK(plain_vm_stack_encrypt_push(NULL,UINT64_MAX)==UINT64_MAX);
    CHECK(protected_vm_stack_encrypt_push(NULL,UINT64_MAX)==UINT64_MAX);
    plain_vm_stack_crypto_init(&a,0,key); protected_vm_stack_crypto_init(&b,0,key);
    uint64_t sa[2]={11,22},sb[2]={11,22}; uint32_t pa=0,pb=0;
    for(unsigned mode=0;mode<3;++mode) {
        vm_stack_crypto_ctx_t before=a;
        int ra=plain_vm_stack_push_encrypted(mode==0?NULL:&a,mode==1?NULL:sa,mode==2?NULL:&pa,2,1);
        int rb=protected_vm_stack_push_encrypted(mode==0?NULL:&b,mode==1?NULL:sb,mode==2?NULL:&pb,2,1);
        CHECK(ra==VM_STACK_ERROR_INVALID_PARAM && rb==ra);
        CHECK(pa==0 && pb==0 && sa[0]==11 && sa[1]==22 && memcmp(sa,sb,sizeof(sa))==0);
        CHECK(memcmp(&a,&before,sizeof(a))==0 && memcmp(&b,&before,sizeof(b))==0);
        ++cases;
    }
    /* All source-valid rotations: avoid inventing semantics for shift-by-64 UB. */
    for(unsigned rot=8;rot<=63;++rot) {
        a.stack_rot=b.stack_rot=(uint8_t)rot;
        CHECK(plain_vm_stack_encrypt_push(&a,UINT64_MAX)==protected_vm_stack_encrypt_push(&b,UINT64_MAX));
        ++cases;
    }
    printf("PASS cases=%u seed=783cb86db73074ac\n",cases);
    return 0;
}
