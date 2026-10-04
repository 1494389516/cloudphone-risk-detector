> 2026-10-04：按维护者要求移除仓库中的单元测试、差分/回归测试源码、测试运行脚本及对应测试 CI。下文测试命令和结果作为历史记录保留；需要复现时请使用删除前的提交 `16543b971eaeb247e8720f8aa927d45fe97e90c0`。代码生成、CPSV 布局生成和发布证据校验工具仍保留。

# Threaded candidate: concrete CPSV integration boundary

Status: design only. This file does not enable a format or claim runtime coverage.
The earlier 3→4 proposal was for stage 2A's post-handler only and is insufficient
for the new context-threaded engine.

## Proposed required roster

Keep v1 parsing and its original IDs separate. A v2 roster for this candidate would
have **58 ranges**, not four:

| Group | Count | Proposed IDs |
| --- | ---: | --- |
| Existing EXEC / LOOP_A / DISPATCH anchors | 3 | 1 / 2 / 3 |
| Shared post-handler | 1 | 4 |
| Context lifetime/finish drivers A / B | 2 | 5 / 6 |
| Context handlers A | 26 | 0x100 + canonical logical ID; poison 0x1ff; unknown 0x1fe |
| Context handlers B | 26 | 0x200 + canonical logical ID; poison 0x2ff; unknown 0x2fe |

LOOP_A remains a compatibility anchor during migration; hashing it is not evidence
that the threaded route is protected. Required kinds must match an independently
compiled roster of actual function identities. This roster still does not cover all
out-of-line semantic variant bodies, hash/whitebox helpers or platform hooks; do not
label it whole-VM integrity. Expanding that threat-model scope is a separate decision.

## Producer/runtime contract that must precede default routing

- Use the existing independent CPSV version field for v2. Do not bump global armor
  ABI. Define fixed little-endian descriptor serialization and hash it together with
  code bytes. V2 parser errors must not fall back to v1 or to unhashed execution.
- Use image-relative addresses in the serialized v2 payload; do not serialize
  ASLR-dependent runtime pointers. Do not overwrite live chained-fixup slots with
  RVAs. Reserve a pointer-free manifest section for post-link population and keep
  independent function references in the runtime roster.
- Measure the exact ranges after all code-mutating passes; use retained linker
  maps/function boundaries matched to the final image identity. If folding,
  splitting or stripping makes an extent ambiguous, reject generation. Never
  substitute a fixed prefix or the next arbitrary symbol's address.
- Proposed bounded parser limits: exactly the supported required roster, at most
  64 entries, at most 64 KiB per range, at most 1 MiB total. Validate arithmetic,
  TEXT bounds, instruction alignment, duplicate/missing kinds and overlaps before
  reading any bytes. These are proposed limits, not existing constants.
- Replace the fixed 176-byte message collection with bounded streaming input on
  both sides. Preserve v1's interpretation for actual v1 images. The existing
  truncated expectation tag must not be represented as full-width authentication;
  widening that payload needs an explicit companion-format design.
- Runtime identity checks must compare the manifest to an independent expected
  roster, not `memcmp` the section with a C alias of the same bytes.
- Produce expectations after manifest finalization and code transformation, before
  signing. Test the final signed deployment pipeline separately; a stock Xcode
  Release symbol check cannot validate injection ordering.

## Required negative and differential gates

1. Missing/duplicate/unknown kind, zero or unaligned length, overflow, out-of-TEXT,
   overlap, stale image identity, v2 truncation and descriptor redirect all reject.
2. A byte change in each of the 58 selected ranges changes the expected check and
   triggers the intended poison/failure path. An unrelated unselected helper is not
   falsely described as protected.
3. Independent producer/runtime golden messages match byte-for-byte, both for v1
   preservation and v2 descriptor+range ordering.
4. Actual emitted bytecode executes through the threaded entry; old loops are not
   silently selected. Unsupported musttail targets fail a required-threaded build.
5. Final Apple artifact retains all required contexts and their tail transfers.
6. Compare full entry/prelude/VM/finalization behavior, then measure real evaluate()
   latency with proof of VM execution. Host-frame comparisons cannot replace this.

The default SDK route must remain unchanged until these checks exist and pass.
