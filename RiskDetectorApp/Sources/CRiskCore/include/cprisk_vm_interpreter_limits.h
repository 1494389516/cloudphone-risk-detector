#ifndef CPRISK_VM_INTERPRETER_LIMITS_H
#define CPRISK_VM_INTERPRETER_LIMITS_H

/** Shared with \c cprisk_vm_oph_*.c (must match \c cprisk_vm_interpreter.c). */
#define CPRISK_VM_DISPATCH_CACHE_BYTES 32u
/** One wire opcode byte + 8-byte immediate per instruction. */
#define CPRISK_VM_INSN_WIDTH 9u
#define CPRISK_VM_MAX_SUBCALL_DEPTH 32u
#define CPRISK_VM_MAX_VM_NEST_DEPTH 8u

#endif /* CPRISK_VM_INTERPRETER_LIMITS_H */
