/* Reuse deterministic platform dependencies; do not call the 2A fixtures. */
#define main unused_phase2a_main
#include "../vm-post-handler-2a/harness.c"
#undef main

static unsigned integration_errors;
static void plain_wire(unsigned lane, unsigned encrypted) {
    uint8_t dispatch[272]={0},code[18]={0};
    cprisk_vmp_dispatch_header_t *dh=(void*)dispatch;
    dh->magic=CPRISK_VMP_MAGIC_DISPATCH;dh->version=1;dh->class_table_size=256;
    memset(dispatch+16,255,256);
    dispatch[16+0x35]=CPRISK_VM_OP_NOP;dispatch[16+0x76]=CPRISK_VM_OP_HALT;
    code[0]=0x35;code[9]=0x76;
    cprisk_vmp_bytecode_header_t bh={CPRISK_VMP_MAGIC_BYTECODE,1,0,0};
    cprisk_vm_run_result_t out={0};out.status=CPRISK_VM_STATUS_STEP_LIMIT;
    cprisk_vm_interp_frame_t f={0};
    f.bh=&bh;f.out=&out;f.code=code;f.blen=sizeof(code);
    f.dispatch_sec=dispatch;f.dispatch_hdr=dh;f.func_id=42;f.vpc_a=1;
    f.path_lane=lane;f.step_limit_cap=8;f.semantic_family=1;f.max_subcall_depth=4;
    f.enc_op=encrypted;f.opcode_seed_root=0x12345678;
    if(encrypted) {
        /* Independent producer formula from VMBytecodeEmitter.opcodeMixByte. */
        for(unsigned i=0;i<2;i++) {
            uint64_t state=42u ^ i ^ f.opcode_seed_root ^ UINT64_C(0x4F50434D49583152);
            code[i*9]^=(uint8_t)cprisk_splitmix64_next_i(&state);
        }
    }
    if(lane==0)cprisk_vm_interp_loop_a(&f);else cprisk_vm_interp_loop_b(&f);
    if(out.status!=CPRISK_VM_STATUS_OK || out.poison_flags!=0 || out.steps!=2 ||
       out.last_dispatch_class!=CPRISK_VM_OP_HALT || out.last_opcode!=0x76)integration_errors++;
}
int main(void) {
    const uint64_t ids[]={0,1,42,UINT64_MAX};
    const uint32_t pcs[]={0,1,31,256,UINT32_MAX};
    const uint64_t masks[]={1,2,UINT64_MAX,UINT64_C(0x4F50434F4445464A),UINT64_C(0x123456789ABCDEF0)};
    FILE *nonzero = fopen("nonzero.bin", "wb");
    if (!nonzero) return 2;
    unsigned zero_errors=0,cases=0,nonzero_cases=0;
    uint64_t digest=UINT64_C(14695981039346656037);
    atomic_store(&s_vm_session_mix_i,0x13579BDF);
    for(unsigned i=0;i<4;i++)for(unsigned j=0;j<5;j++)for(unsigned raw=0;raw<256;raw++) {
        cases++;
        if(cprisk_vmp_opcode_fault_byte_i(0,ids[i],pcs[j],raw)!=0)zero_errors++;
        for(unsigned k=0;k<5;k++) {
            uint8_t byte=cprisk_vmp_opcode_fault_byte_i(masks[k],ids[i],pcs[j],raw);
            if (fputc(byte, nonzero) == EOF) return 2;
            digest=(digest^byte)*UINT64_C(1099511628211);nonzero_cases++;
        }
    }
    if (fclose(nonzero) != 0) return 2;
    for(unsigned lane=0;lane<3;lane++)for(unsigned enc=0;enc<2;enc++)plain_wire(lane,enc);
    printf("{\"zero_cases\":%u,\"zero_errors\":%u,\"nonzero_cases\":%u,\"nonzero_digest\":\"%016llx\",\"loop_cases\":6,\"loop_errors\":%u}\n",cases,zero_errors,nonzero_cases,(unsigned long long)digest,integration_errors);
    return 0;
}
