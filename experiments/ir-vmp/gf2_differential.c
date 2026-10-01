#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define DECLARE(P) uint64_t P##cprisk_gf2_xorshift64(uint64_t); uint64_t P##cprisk_gf2_fnv1a(const uint8_t *,size_t);
DECLARE(plain_)
DECLARE(protected_)
static uint64_t seed=UINT64_C(0x783cb86db73074ac);
static uint64_t next_u64(void) { seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;return seed; }
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"FAIL line=%d case=%u\n",__LINE__,cases);return 1; } } while(0)
int main(void) {
 unsigned cases=0;
 uint64_t edges[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffffffff),UINT64_C(0xaaaaaaaaaaaaaaaa)};
 uint8_t data[258],before[258];
 CHECK(plain_cprisk_gf2_xorshift64(0)==0);CHECK(protected_cprisk_gf2_xorshift64(0)==0);
 CHECK(plain_cprisk_gf2_fnv1a(NULL,0)==UINT64_C(0xcbf29ce484222325));
 CHECK(protected_cprisk_gf2_fnv1a(NULL,0)==UINT64_C(0xcbf29ce484222325));
 CHECK(plain_cprisk_gf2_fnv1a((const uint8_t *)"hello",5)==UINT64_C(0xa430d84680aabd0b));
 CHECK(protected_cprisk_gf2_fnv1a((const uint8_t *)"hello",5)==UINT64_C(0xa430d84680aabd0b));
 for(unsigned i=0;i<4096;++i) {
  uint64_t x=i<6?edges[i]:next_u64();
  CHECK(plain_cprisk_gf2_xorshift64(x)==protected_cprisk_gf2_xorshift64(x));
  for(unsigned j=0;j<sizeof(data);++j)data[j]=(uint8_t)next_u64();
  if(i<2)memset(data,i?255:0,sizeof(data));
  memcpy(before,data,sizeof(data));
  size_t len=i%257;
  CHECK(plain_cprisk_gf2_fnv1a(data+1,len)==protected_cprisk_gf2_fnv1a(data+1,len));
  CHECK(memcmp(before,data,sizeof(data))==0);
  ++cases;
 }
 printf("PASS cases=%u seed=783cb86db73074ac\n",cases);
 return 0;
}
