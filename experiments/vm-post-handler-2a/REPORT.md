# VM post-handler 2A — implementation and validation

Baseline: `5d8febd30b317082200dd399ff5d0ac64f37df1a`. Scope: 2A only; no tail dispatch, no CPSV mutation.

## Implementation

The baseline already has ONE shared out-of-line C definition named `cprisk_vm_oph_post_handler_i`. Its callers are in `cprisk_vm_dispatch_leaf_wb_wrapped_i`, not directly in Loop A/B. Moving or wrapping the function again would add an unnecessary boundary. The production change adds `__attribute__((noinline))` to that existing definition and a comment explaining the boundary. The body, signature, callers, and all other production files remain unchanged.

Preserved order: bytecode SHA256 check (including failure early return), auxiliary update, inline-WB-done early return, periodic WB. XOR pre-mask/handler/unmask remains in the original wrapper. All loop hooks, fake dependency acc effects, A-only sync barrier, B bitmask cadences, handler returns, and cleanup remain unchanged. `run.py` asserts the entire interpreter source equals the baseline after removing exactly the annotation/comment.

This is one explicitly non-inlined shared function, not a newly introduced API or symbol. `noinline` is a compiler constraint; it does not promise fixed machine-code size or whole-program linker uniqueness for all possible toolchains.

## Behavioral differential

LLVM/Clang 22.1.8, Linux x86_64, `-O2`: 6,528/6,528 cases are byte-identical before/after. SHA256 of both serialized result streams:

`f31deb389b6da6d172da2c2c960c41e188d65125209458e216d981a742920046`

Matrix: 3 lanes (A, B lane1, B lane2), 4 deterministic initial states, 8 combinations of affine/nonlinear PC, opaque/dead flags, bytecode hashing, and 2 WB outcomes. Each combination executes 24 opcodes, poison, unknown, plus eight boundary scenarios: fetch bound, step limit, invalid relative branch, CALL depth overflow, missing nested callee, nested depth overflow, short indirect-branch body, and bytecode hash mismatch. Normal CALL runs CALL/RET/HALT; normal VM_CALL_FUNC switches to a callee RET and restores the caller. All 192 step-limit fixtures actually end with status STEP_LIMIT and steps=260.

Additional coverage-instrumented execution confirms all 24 canonical opcode handlers plus poison and unknown were entered; before/after invocation counts also agree. Coverage and native executions are the SAME corpus, not independent additional cases. The complete initialized run-result object is compared, including status, poison flags, whitebox rc, steps, last opcode/class, vregs and both acc banks. Internal acc banks/vregs/encoded_pc/steps are additionally serialized. Padding is zero-initialized.

Actual production loop bodies, opcode handlers/variants, SHA256, hardening hooks, CFF fusion, and sync barrier execute. Mach-O discovery is disabled on the host; session/runtime material, whitebox domain evaluation, CFF S-box, emulator probes and crypto-trace timing use deterministic test substitutes. Data-only interpreter code-address references are replaced by a recorded stable address map because those addresses feed session/opaque state. Runtime self-expect injection and Apple platform paths are NOT tested. No production source is normalized or stubbed.

Coverage caught a fixture issue before acceptance: the baseline's opcode-fault transform is nonidentity even with mask zero, so identity wire bytes did not reach every requested logical opcode. Fixtures now construct wire/class pairs through that existing decoder. This baseline behavior is NOT fixed in 2A; the corpus does not establish Swift emitter/runtime parity. Earlier incomplete-coverage runs are not acceptance evidence.

Reproduce:

```sh
python experiments/vm-post-handler-2a/run.py --clang /path/to/llvm/bin/clang --output /tmp/vm-post-native
python experiments/vm-post-handler-2a/run.py --clang /path/to/llvm/bin/clang --coverage --output /tmp/vm-post-coverage
```

## AArch64 object evidence (not Apple Release)

Target `aarch64-none-elf`, LLVM 22.1.8, `-ffreestanding`, declaration-only libc header substitutes and the Mach-O lookup shim. Source is the actual, non-address-normalized interpreter. These are ELF .text offsets, NOT linked Mach-O VMAs or runtime addresses.

| Optimization | Post-handler .text offset | Length, bytes | Repeated builds |
|---|---:|---:|---|
| -O0 | 0x5308 | 25,308 | 3/3 identical offset and length |
| -O2 | 0x3c20 | 9,028 | 3/3 identical offset and length |
| -Oz | 0x1e88 | 6,352 | 3/3 identical offset and length |

Both baseline and modified objects have the same offsets and sizes in this matrix. All six .text sections per optimization (three before, three after) have identical SHA256. Whole object hashes can differ because the input filenames differ; comparisons use .text bytes separately.

At -O2, wrapper references to the post-handler are `R_AARCH64_JUMP26` at 0x39b8 and `R_AARCH64_CALL26` at 0x3c00. The first is an existing compiler-generated sibling tail branch from the WB wrapper, NOT a new handler-to-handler tail-dispatch implementation. The actual handler continues returning flow to its old caller. The independent symbol and both out-of-line transfer sites are retained. The baseline compiler already chose not to inline this large function; this change makes that boundary explicit.

Cross-optimization size is demonstrably NOT stable. That does not disqualify a per-build measured span. It disqualifies hardcoding one universal function length. `asm volatile` is not a length guarantee; a dedicated section controls placement/grouping, not instruction count. Do not add padding or assembly barriers merely to pretend otherwise.

Reproduce:

```sh
python experiments/vm-post-handler-2a/inspect_arm64.py --llvm-bin /path/to/llvm/bin --output /tmp/vm-post-arm64
```

No Swift, Xcode or Apple SDK is installed here. Neither `swift build` nor iphoneos Release was executed. AArch64 ELF inspection is supplementary evidence and does NOT satisfy the requested final Apple Release gate. That gate must repeat symbol/call-site inspection after linking, LTO if enabled, armor passes, and self-expect injection on the actual supported Xcode build.

## Loop A dependencies

Baseline references (line numbers in baseline interpreter):

- CPSV static span: 1650; default 64-byte prefix, legacy message/hash paths 1732/1787.
- Data-only bait metadata: 1927. Its address enters the bait/session mixing chain; code layout is a runtime input.
- Normal lane0 execution: 4652.
- `VMSelfExpectInjector.swift`: legacy symbol fallback plus CPSV count/kind/length validation.
- `cff_policy.yaml:86` and `cff_policy_appstore_safe.yaml:128`: policy targets by symbol name.
- Public interpreter header and self-expect CLI document the prefix contract.

The sync barrier does not consume Loop A's address or length; Loop A is its caller. No further direct address/length dependency was found in the repository search. This does not prove absence in external binary consumers. Loop A's source structure is unchanged. In the measured non-Apple matrix the whole .text is unchanged too; Apple layout must be checked separately.

## CPSV proposal only — NOT implemented

1. Candidate span count is **3 → 4**: preserve EXEC, LOOP_A, DISPATCH; add POST_HANDLER (proposed kind 4). Preserve all old IDs. The initial proposal requires each selected function region to be contiguous and have an authoritative measured extent; if code splitting violates that, fail generation rather than guess. A later multi-range contract would require explicit design.
2. There is already an independent **CPSV format version**: `CPRISK_VMP_SELF_SPAN_VERSION` in C and `VMSelfExpectInjector.spanVersion` in Swift, currently 1. No additional version field is needed. A future variable-span contract should explicitly introduce CPSV v2 while leaving the overall armor ABI and public VM entry signatures unchanged. This is a proposal requiring approval; 2A changes neither version.
3. Do NOT attempt to keep identical byte length across -O0/-O2/-Oz. Pin the release toolchain/options, then obtain exact span extents from the final transformed linked image using retained symbols plus authoritative function-boundary/linker information. Verify no folded/split aliases, section bounds, four-byte ARM64 alignment, and nonoverlap. A dedicated function section can assist boundary discovery but is not itself a size or no-fold guarantee. Reproducibility compares identical inputs/toolchain; legitimate size changes regenerate the manifest/expectation.
4. Producer (`VMSelfExpectInjector.swift`): add v1/v2 parsing, remove v2 count==3/exact 48+64+64 and selfByteCount==176 assumptions, accept an explicit validated kind/extent roster for four spans, update SegmentMeta and diagnostics, and compute the expectation over the validated ordered ranges. Keep v1 fallback ONLY for v1 legacy images, never silently fall back from malformed v2. The post-link pipeline must finalize span metadata after all code-mutating passes and before expectation injection/signing. Do not infer span size from the next arbitrary symbol alone.
5. Consumer: replace the v2 static 3-entry/64-byte struct assertion and count==3 resolver with bounded v2 handling; replace fixed 176-byte HMAC message collection with bounded streaming hashing/MAC; keep FNV and HMAC producer/consumer inputs identical. Validate count, kinds, region bounds, offsets, lengths and overflow before reading. Keep v1 behavior separately for actual v1 artifacts. Suggested v2 caps: four spans, <=64 KiB each, <=256 KiB total; reject unsupported layouts. These are proposed policy limits, not existing ABI constants.
6. Bind the span descriptor (version/count/kind/relative offset/length) into the v2 expectation along with code bytes, so truncating or redirecting a range cannot silently reduce coverage. Relative image offsets avoid hashing ASLR-dependent pointer values; this would be an explicit CPSV v2 layout change. Runtime should validate expected identities against a compiled symbol roster and permitted TEXT ranges; comparing the section to an alias of itself is not independent validation. The exact producer/runtime normalized descriptor encoding must be specified together.
7. A post-handler span covers its own machine-code region, including whatever helpers the compiler inlined there. It does not automatically protect every out-of-line SHA/WB/aux dependency. Document those bounds; do not label four spans as whole-VM integrity coverage. Hashes/seal-derived decode material must be regenerated and exercised with actual producer output.

## Performance and remaining gates

`evaluate()` P95: **not measured**, because the Apple SDK application cannot execute in this environment. No host VM timing is relabeled as evaluate latency. Identical AArch64 .text in the measured matrix shows no instruction change there; it is not an end-to-end timing result and does not prove zero overhead on Apple Clang/LTO.

On the Apple/device runner, use identical inputs, session/feature settings, device/OS/power state, warmup and interleaved old/new measurements; record sample count, P50/P95, raw timings and variance. Include proof that the intended runtime path was exercised: `partial` metadata-only protection can leave evaluate() native, making a zero delta uninformative about VM costs.

2A code and host evidence are ready for review. Apple Release disassembly and evaluate() performance remain blocked by environment. Do not mark all acceptance gates passed or begin 2B on the basis of this report.
