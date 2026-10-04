#!/usr/bin/env python3
"""Generate a validation-only context-threaded engine from exact A/B prefixes.

No production routing changes: CPSV v1 does not cover the generated handlers.
The source prefix extraction is checked explicitly so drift fails generation.
"""
import argparse
import hashlib
import pathlib
import re

NAMES = ['nop', 'ret', 'raw_region', 'halt', 'add', 'branch_rel',
         'branch_cond', 'call', 'mov_wide', 'adr_add', 'cond_select',
         'load_store', 'xor_mix', 'or_lane', 'and_lane', 'rol_acc',
         'vm_call_func', 'vreg_mov', 'vreg_alu', 'vreg_mem', 'sub_lane',
         'mul_lane', 'add_rol_acc', 'branch_ind', 'poison', 'unknown']


def generate(source):
    lines = ['''/* Generated validation-only engine; include after interpreter source. */
#ifndef __clang__
#error "Context-threaded validation requires Clang musttail; no recursive fallback"
#endif
#if !__has_attribute(musttail)
#error "Compiler must guarantee tail transfers"
#endif
#include "include/cprisk_vm_oph_variants.h"
typedef struct {
    cprisk_vm_interp_frame_t *fr;
    uint8_t op, logical;
    uint64_t imm;
    uint32_t pc, hvar;
} cprisk_thread_context_i;
typedef void (*cprisk_thread_fn_i)(cprisk_thread_context_i *);
#ifndef CPRISK_THREAD_OBSERVE
#define CPRISK_THREAD_OBSERVE(lane, name) ((void)0)
#endif
''']
    for lane in ['a', 'b']:
        start = source.index('void cprisk_vm_interp_loop_' + lane + '(struct cprisk_vm_interp_frame *fr)\n{')
        begin = source.index('    while (fr->steps < fr->step_limit_cap) {', start)
        stop = source.index('        {\n            const cprisk_vm_flow_t flow =', begin)
        prefix = source[begin:stop]
        assert prefix.count('const uint8_t logical = cprisk_vm_dispatch_lookup(') == 1
        assert 'cprisk_vm_dispatch_oph_core_i(' not in prefix
        lines += [f'/* Original {lane.upper()} prefix SHA256: {hashlib.sha256(prefix.encode()).hexdigest()} */',
                  f'static __attribute__((always_inline)) inline int cprisk_thread_prepare_{lane}_i(cprisk_thread_context_i *ctx) {{',
                  '    cprisk_vm_interp_frame_t *fr = ctx->fr;', prefix,
                  '        ctx->op = op; ctx->logical = logical; ctx->imm = imm;',
                  '        ctx->pc = pc; ctx->hvar = hvar;',
                  '        return 1;\n    }\n    return 0;\n}']
        for name in NAMES:
            lines.append(f'static void cprisk_thread_{lane}_{name}_i(cprisk_thread_context_i *ctx);')
        lines += [f'static __attribute__((always_inline)) inline cprisk_thread_fn_i cprisk_thread_select_{lane}_i(uint8_t logical) {{',
                  '    switch (logical) {']
        for name in NAMES[:-1]:
            lines.append(f'    case CPRISK_VM_OP_{name.upper()}: return cprisk_thread_{lane}_{name}_i;')
        lines += [f'    default: return cprisk_thread_{lane}_unknown_i;', '    }\n}']
        for name in NAMES:
            args = 'fr, ctx->op, ctx->logical, ctx->imm, ctx->pc, ctx->hvar'
            # Poison/unknown intentionally bypass WB/post-handler, as the old core does.
            call = (f'cprisk_vm_oph_{name}({args})' if name in ['poison', 'unknown'] else
                    f'cprisk_vm_dispatch_leaf_wb_wrapped_i({args}, cprisk_vm_oph_select_{name})')
            lines += [f'static __attribute__((noinline)) void cprisk_thread_{lane}_{name}_i(cprisk_thread_context_i *ctx) {{',
                      f'    CPRISK_THREAD_OBSERVE({lane}, {name});',
                      '    cprisk_vm_interp_frame_t *fr = ctx->fr;',
                      f'    const cprisk_vm_flow_t flow = {call};',
                      '    if (flow == CPRISK_VM_FLOW_LEAVE) return;',
                      f'    if (!cprisk_thread_prepare_{lane}_i(ctx)) return;',
                      f'    cprisk_thread_fn_i next = cprisk_thread_select_{lane}_i(ctx->logical);',
                      '    __attribute__((musttail)) return next(ctx);', '}']
        finish = ('    cprisk_vm_interp_finish_run_lane0_i(fr);' if lane == 'a' else
                  '    if (fr->path_lane == 1u) cprisk_vm_interp_finish_run_lane1_i(fr);\n'
                  '    else cprisk_vm_interp_finish_run_lane2_i(fr);')
        lines += [f'static void cprisk_thread_run_{lane}_i(cprisk_vm_interp_frame_t *fr) {{',
                  '    /* This frame owns ctx until the entire tail chain returns. */',
                  '    cprisk_thread_context_i ctx = { .fr = fr };',
                  f'    if (cprisk_thread_prepare_{lane}_i(&ctx)) {{',
                  f'        cprisk_thread_fn_i first = cprisk_thread_select_{lane}_i(ctx.logical);',
                  '        first(&ctx);\n    }', finish, '}']
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    pathlib.Path(a.output).write_text(generate(pathlib.Path(a.source).read_text()))
