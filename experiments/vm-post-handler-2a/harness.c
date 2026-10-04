/* Differential host harness. Includes a byte-identical interpreter body except
 * test-only normalization of data-only code addresses (see run.py). */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "interpreter-under-test.c"
static int wb_fail;
int cprisk_get_session_key(uint8_t x[32]) { memset(x, 0x31, 32); return 0; }
int cprisk_get_runtime_material(uint8_t x[32]) { memset(x, 0x52, 32); return 0; }
int cprisk_runtime_material_ready(void) { return 1; }
uint32_t cprisk_cff_get_vm_link_token(void) { return 0; }
uint64_t cprisk_cff_runtime_spn_sbox_seed(void) { return 0x12345678; }
uint64_t cprisk_crypto_trace_now_i(void) { return 7; }
void cprisk_crypto_trace_record_span_ticks_i(uint64_t x) { (void)x; }
void cprisk_crypto_trace_primitive_enter_i(void) {}
int cprisk_frida_runtime_snapshot(cprisk_frida_runtime_snapshot_t *x) { memset(x,0,sizeof(*x)); return 0; }
int cprisk_whitebox_evaluate_domain(uint32_t d,const uint8_t x[32],uint8_t y[32]) {
    for(unsigned i=0;i<32;i++) y[i]=x[(i+3)&31]^(uint8_t)(d+i);
    return wb_fail ? -1 : 0;
}
static void ins(uint8_t *p,unsigned op,uint64_t imm) { p[0]=(uint8_t)op; memcpy(p+1,&imm,8); }
static void dump(const void *p,size_t n) { const unsigned char *s=p; for(size_t i=0;i<n;i++) printf("%02x",s[i]); }
static void run_case(unsigned op,unsigned scenario,unsigned lane,unsigned seed,unsigned mode) {
    uint8_t section[2048]={0}, dispatch[272]={0};
    cprisk_vmp_bytecode_header_t *bh=(void*)section;
    bh->magic=CPRISK_VMP_MAGIC_BYTECODE; bh->version=1; bh->entry_count=1;
    cprisk_vmp_bytecode_entry_t *entry=(void*)(section+16);
    entry->function_id=99; entry->bytecode_offset=512; entry->bytecode_length=9;
    entry->reserved=0xA5000000u | (3u<<16) | (1u<<8);
    ins(section+512,CPRISK_VM_OP_RET,0);
    cprisk_vmp_dispatch_header_t *dh=(void*)dispatch;
    dh->magic=CPRISK_VMP_MAGIC_DISPATCH; dh->version=1; dh->class_table_size=256;
    for(unsigned i=0;i<256;i++)dispatch[16+i]=(uint8_t)i;
    uint8_t *code=section+64;
    for(unsigned i=0;i<40;i++)ins(code+i*9,CPRISK_VM_OP_NOP,0);
    uint64_t imm=0xF100001Fu;
    if(op==CPRISK_VM_OP_BRANCH_REL || op==CPRISK_VM_OP_CALL)imm=18;
    if(op==CPRISK_VM_OP_VM_CALL_FUNC)imm=99;
    if(op==CPRISK_VM_OP_BRANCH_IND)imm=CPRISK_VM_BRANCH_IND_SEMI_IDENTITY_TAG;
    ins(code,op,imm); ins(code+9,CPRISK_VM_OP_HALT,0);
    if(op==CPRISK_VM_OP_CALL)ins(code+18,CPRISK_VM_OP_RET,0);
    cprisk_vm_run_result_t out={0}; out.status=CPRISK_VM_STATUS_STEP_LIMIT;
    cprisk_vm_interp_frame_t f={0};
    f.b_sec=section; f.bsz=sizeof(section); f.bh=bh; f.code=code; f.blen=27;
    f.bc_hdr_total=16; f.entry_stride=32; f.dispatch_sec=dispatch; f.dispatch_hdr=dh;
    f.func_id=42; f.out=&out; f.vpc_a=1; f.semantic_family=1;
    f.max_subcall_depth=4; f.step_limit_cap=32; f.path_lane=lane;
    f.session_mix=seed+1; f.opaque_session_mix=seed+17; f.opaque_chain=seed+23;
    f.opaque_pid=1; f.acc_lane_map[1]=1; f.acc_lane_map[2]=2;
    for(unsigned i=0;i<32;i++){f.acc[i]=(uint8_t)(seed+i);f.acc_aux[i]=(uint8_t)(seed^i);}
    for(unsigned i=0;i<8;i++) f.vregs[i]=seed+i;
    if(mode&1) { bh->reserved|=CPRISK_VMP_BC_FLAG_VPC_NONLINEAR; f.vpc_a=31; f.vpc_b=47; }
    cprisk_vm_encode_pc_i(bh,0,f.vpc_a,f.vpc_b,&f.encoded_pc,&out);
    if(mode&2) { f.m3_opaque=1; f.m3_dead=1; }
    if(scenario==1)f.blen=8; /* fetch bound */
    if(scenario==2){ins(code,CPRISK_VM_OP_BRANCH_REL,0);f.step_limit_cap=260;} /* limit + periodic WB/hash */
    if(scenario==3){ins(code,CPRISK_VM_OP_BRANCH_REL,UINT64_MAX);}
    if(scenario==4){f.return_sp=f.max_subcall_depth;ins(code,CPRISK_VM_OP_CALL,18);}
    if(scenario==5){ins(code,CPRISK_VM_OP_VM_CALL_FUNC,999);} /* missing nested callee */
    if(scenario==6){f.vm_snap_sp=CPRISK_VM_MAX_VM_NEST_DEPTH;ins(code,CPRISK_VM_OP_VM_CALL_FUNC,99);}
    if(scenario==7){ins(code,CPRISK_VM_OP_BRANCH_IND,0);f.blen=9;}
    /* Build test wire/class pairs using the CURRENT decoder, including its
     * opcode fault transform at mask==0. Identity wire bytes do not reach all
     * logical opcodes in this baseline. Do not change production decoding. */
    unsigned char assigned[256]={0}; memset(dispatch+16,255,256);
    for(unsigned body=0;body<2;body++) {
        uint8_t *p=body?section+512:code; unsigned n=body?1:3;
        for(unsigned index=0;index<n;index++) {
            uint8_t logical=p[index*9]; int found=0;
            for(unsigned raw=0;raw<256;raw++) {
                uint8_t decoded=(uint8_t)raw ^ cprisk_vmp_opcode_fault_byte_i(0,42,index,(uint8_t)raw);
                if(!assigned[decoded] || dispatch[16+decoded]==logical) {
                    assigned[decoded]=1;dispatch[16+decoded]=logical;
                    p[index*9]=(uint8_t)raw;found=1;break;
                }
            }
            if(!found)abort();
        }
    }
    f.bc_seg_hash_enabled=(mode>>2)&1;
    if(f.bc_seg_hash_enabled)cprisk_sha256(f.code,f.blen,f.bc_seg_hash_expect);
    if(scenario==8){f.bc_seg_hash_enabled=1;memset(f.bc_seg_hash_expect,0xAA,32);}
    /* Actual production hardening hooks, initialized with the fixed frame. */
    cprisk_vm_hardening_init(&f);
    cprisk_vm_sync_barrier_init(&f.sync_barrier_ctx);
    if(lane==0)cprisk_vm_interp_loop_a(&f);else cprisk_vm_interp_loop_b(&f);
    /* All output bytes, including zero-initialized padding, plus internal state
     * omitted by loop finish. Never serialize pointers or ASLR addresses. */
    printf("%u/%u/%u/%u/%u/%d ",op,scenario,lane,seed,mode,wb_fail);
    dump(&out,sizeof(out));dump(f.acc,sizeof(f.acc));dump(f.acc_aux,sizeof(f.acc_aux));
    dump(f.vregs,sizeof(f.vregs));dump(&f.encoded_pc,sizeof(f.encoded_pc));
    dump(&f.steps,sizeof(f.steps));puts("");
}
int main(void){
    atomic_store(&s_vm_session_mix_i,0x13579BDF);
    for(wb_fail=0;wb_fail<2;wb_fail++)for(unsigned lane=0;lane<3;lane++)
    for(unsigned mode=0;mode<8;mode++)for(unsigned seed=0;seed<4;seed++){
        for(unsigned op=0;op<24;op++)run_case(op,0,lane,seed,mode);
        run_case(255,0,lane,seed,mode);run_case(254,0,lane,seed,mode);
        for(unsigned s=1;s<=8;s++)run_case(0,s,lane,seed,mode);
    }
    return 0;
}
uint32_t cprisk_emulator_probe(void) { return 0; }
int cprisk_emulator_is_hostile(uint32_t f) { (void)f; return 0; }
void cprisk_emulator_mark_watchdog_stuck(void) {}
uint8_t cprisk_cff_spn_sbox_lookup(uint8_t x) { return x; }
