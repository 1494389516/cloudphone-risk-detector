# Context-threaded dispatch candidate — stage 2B validation

This is an **experimental, non-production implementation**. It does not enable full
VM replacement or route the shipped SDK into the candidate. CPSV v1 remains intact.
The candidate is generated from the exact A/B prefixes in the interpreter at
`8e8d40350271f531e5881c445b383d44757131d9`; source drift stops the differential runner.

## Architecture implemented

There are 52 context handlers: A/B each have 24 canonical opcodes, poison and unknown.
Each has signature `void (cprisk_thread_context_i *)`, executes its selected semantic
leaf, then prepares the next instruction locally and performs a Clang `musttail`
indirect call to the next context handler. The context lives in the driver frame,
not in a handler frame whose lifetime ends at a tail call. Unsupported compilers
fail compilation; there is no recursive-call fallback.

Fetch/decode and the A/B-specific pre-hooks are `always_inline` in each handler.
The only local retry loops are the original opaque/dead pre-dispatch retries: they
do not execute an opcode. The driver initializes once and finalizes once after the
tail chain exits; it does not dispatch every instruction. A and B remain separate,
including immediate/opcode order, bitmask predicates (NOT modulo periods), tags,
cluster calls and A's sync barrier.

Existing `cprisk_vm_oph_select_*` pools remain semantic helpers, returning flow to
their context handler. White-box wrapping and the shared noinline post-hook retain
the original ordering. Poison and unknown continue bypassing that post-hook, just
as the old core does. No code-address arithmetic masquerades as a guarantee: the
old leaf's reversible pointer XOR did not mutate state; the candidate calls the
same semantic selector through the existing WB wrapper.

This is context threading through new handlers, **not a change to the signatures
of the old semantic helpers**. Old helpers and loops remain the differential oracle
and the production implementation. No raw host pointer is serialized into bytecode;
the existing encoded VPC, wire format and opcode dispatch mapping are sufficient
to derive each next context handler at runtime.

## Completed local evidence

Ubuntu Clang 18.1.3, x86_64, deterministic platform substitutes:

| Check | O0 | O2 |
| --- | --- | --- |
| Full existing result/state corpus | 6528/6528 identical | 6528/6528 identical |
| Executed context handlers | 52/52 | 52/52 |
| Stress, per lane 0/1/2 | 200000 steps, all equal | 200000 steps, all equal |
| Stress process stack limit | 1 MiB | 1 MiB |
| Observed handler-local stack address span | 8 bytes | 48 bytes |

Probe spans are empirical, ABI/compiler-dependent observations, not total stack
usage. The compile-time musttail constraint and IR/machine checks provide the
structural guarantee. The probe corpus/stress have instrumentation; object inspection
uses the uninstrumented implementation.

The corpus includes CALL/RET/nested-call, error exits, hash failure and both WB
outcomes. Complete initialized public output plus acc banks, vregs, encoded_pc and
steps are serialized. All other internal frame fields are not yet serialized.
Code-address data is normalized only in generated test copies. Platform substitutes
and the corpus are inherited from 2A; this is not Swift producer parity or real
self-expect injection validation. Counters prove context-handler entry, not exhaustive
variant/condition coverage. Host correctness does not measure attack resistance.

ARM64 freestanding ELF at O0/O2/Os: all 52 functions have one `musttail` IR transfer
and an indirect machine branch; prepare/select have no outlined definitions. Three
objects per optimization are byte-identical. This is object evidence, not a linked
Apple image or LTO/armor acceptance. Raw outputs are reproducible; summary reports
are in `evidence/`.

## Reproduce

```sh
python3 experiments/vm-threaded-dispatch/run.py --cc clang --opt O0 --output /tmp/thread-O0
python3 experiments/vm-threaded-dispatch/run.py --cc clang --opt O2 --output /tmp/thread-O2
python3 experiments/vm-threaded-dispatch/inspect_arm64.py --cc clang --objdump llvm-objdump --output /tmp/thread-arm64
```

On macOS the host comparisons deliberately force the same non-Apple path and use
Darwin dead stripping. Apple objects use real SDK headers:

```sh
python3 experiments/vm-threaded-dispatch/inspect_arm64.py --apple --cc "$(xcrun -f clang)" --objdump "$(xcrun -f llvm-objdump)" --output /tmp/thread-apple
python3 experiments/vm-threaded-dispatch/apple_release.py --ref d07b76404e19cd3dffd790fae55158c329d164c0 --output /tmp/stage2a-apple
```

The second command runs three clean stock iPhoneOS Release App builds, identifies
the post-hook in live linker maps, measures its final file-backed TEXT region and
checks direct calls/branches. It records actual owning images and mapped symbol
sizes; does not infer size from arbitrary adjacent symbols. A missing/stripped
function fails instead of being counted as verification. It does not run armor,
self-expect injection or any iPhone benchmark.

The old 2A runner now accepts `--candidate-ref d07b764...` to reproduce its historical
source-only noinline change after the later semantic fix. Its strict annotation-only
assertion remains enabled. The zero-fault runner now accepts Darwin linking.

## Remaining production gates

- **CPSV coverage is unresolved.** The old 3-to-4 proposal only adds POST_HANDLER;
  it does not cover these 52 context-handler regions. It cannot be reused to claim
  integrity of the candidate. Define a bounded multi-span/section contract, include
  actual dispatch handlers and drivers as appropriate, update producer and consumer
  together, finalize after code-mutating passes, and test descriptor/code tampering.
- Preserve old Loop A address consumers or explicitly migrate them. It remains
  production code here, not a stale anchor pretending to protect the candidate.
- Integrate the candidate behind an explicit private build policy only after that
  contract is implemented. Reject required-threaded requests on unsupported compilers.
- Validate final Apple linked/LTO/armor output, actual emitted bytecode and full
  initialization/finalization, not just isolated interpreter frames.
- Measure real `evaluate()` P95 with proof of VM execution. No device timings exist
  in these host reports. The legacy full-tier guard remains correct and unchanged.
- IR-VMP production kernels, lifecycle contract and SDK linkage are a separate
  unfinished route. This experiment does not satisfy those acceptance gates.

Release eligibility remains false. CI artifacts must be inspected; adding a workflow
is not evidence that its jobs ran or passed.
