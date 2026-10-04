> 2026-10-04：按维护者要求移除仓库中的单元测试、差分/回归测试源码、测试运行脚本及对应测试 CI。下文测试命令和结果作为历史记录保留；需要复现时请使用删除前的提交 `16543b971eaeb247e8720f8aa927d45fe97e90c0`。代码生成、CPSV 布局生成和发布证据校验工具仍保留。

# IR-VMP vNext implementation checkpoint

Baseline: `aa9aba7d17f3efa00b04f63793d1cd9bfca7719b`. This change implements the
configuration and original-business-function experiment stages of the supplied
2026-10-03 specification, plus the restricted LLVM input checker. **It does not
integrate a protected object into the production SDK.** SDK defaults and the old
Mach-O full-tier guard remain unchanged. No Detector thresholds, public APIs,
white-box formulas, network DTOs or Agent code change.

## Implemented scope

| Specification stage | This checkpoint |
| --- | --- |
| PR-01: strict policy and evidence | Strict JSON schema/loader, source/dependency identities, pinned toolchain/patch, planned registry, separate evidence dimensions, strict legacy YAML at the actual pass entry. Compatibility `parse` remains available. |
| PR-02: original business candidates | Exact original policy-selection globals/types/body/constants and strong-mix body/helper; native and real VM differential harnesses; independent value checks, canaries, input preservation, five seeds. |
| PR-03: production private C kernels | **Not implemented.** A's synchronization contract is unresolved; B's complete domain/SDK consumer suite is not available. No production refactor is presented as verified. |
| PR-04: input checker and opt-in SDK build | LLVM API preflight implemented and exercised; stock SDK/Apple link integration, final Mach-O callpath checks and bytecode format verifier remain **not implemented**. `vnext.py` is an experiment/acceptance driver, not an SDK builder. |
| PR-05: real SDK on physical iPhone | **Not run**; signing, provisioning, device and production callpath evidence absent. The previous independent GF2 App is not relabelled as SDK evidence. |
| PR-06: L1/L2/L3 | **Not implemented**; only L0 annotation is accepted. Multiple seeds here measure correctness, not resistance or diversity benefits. |
| PR-07: release | Negative gate and CI baseline/config tests implemented. Production evidence adapters and performance/resilience acceptance remain **not implemented**. Release is ineligible. |

The registry intentionally remains `planned`. A run report may record conversion
and host-semantic passes without changing the registry's production status.
`production_enabled=false` is one necessary release condition, not a user-set
override for missing evidence. Unknown production evidence adapters reject pass
claims. Hashes provide reproducibility and corruption detection, not external
attestation or a client trust root.

## Reproduce

From the repository root, using Python 3.12:

```sh
python3 -m venv /tmp/ir-vmp-tools
/tmp/ir-vmp-tools/bin/python -m pip install -r experiments/ir-vmp/requirements.txt
/tmp/ir-vmp-tools/bin/python experiments/ir-vmp/vnext.py validate
/tmp/ir-vmp-tools/bin/python experiments/ir-vmp/vnext.py run --output /tmp/business-native
/tmp/ir-vmp-tools/bin/python experiments/ir-vmp/vnext.py run --sanitize --output /tmp/business-sanitized
```

Both results must say `BASELINE_ONLY_PASS`, never `HOST_VMP_PASS`. Sanitized
native results cover the same input corpus and must not be added to it as
independent coverage. In a ptrace-restricted environment only, LeakSanitizer may
need `ASAN_OPTIONS=detect_leaks=0`; the runner records this environment explicitly.
ASan/UBSan results do not prove VM memory safety.

Build the pinned plugin with the existing `build_plugin.py --patch-set
pointer-gep-v2` workflow. The build now matches `llvm-config --has-rtti` and loads
the resulting plugin into the matching `opt` before declaring `built`. This fixes
a reproduced failure on the official Linux LLVM package: the shared library
linked, but loading failed with an unresolved LLVM RTTI symbol. Linux VM harness
linking also explicitly includes `libm`, needed by the fixed interpreter's
unused floating-point handlers. Target floating-point IR remains rejected.

```sh
python3 experiments/ir-vmp/build_preflight.py \
  --llvm-root /path/to/llvm22 --output /tmp/preflight-build

python3 experiments/ir-vmp/vnext.py run --mode xollvm \
  --clang /path/to/llvm22/bin/clang --opt /path/to/llvm22/bin/opt \
  --plugin /tmp/xollvm-build/cmake/Obfuscator.so \
  --plugin-provenance /tmp/xollvm-build/plugin-provenance.json \
  --preflight /tmp/preflight-build/preflight --output /tmp/business-vm

CPRISK_PREFLIGHT=/tmp/preflight-build/preflight \
  python3 -m unittest discover -s experiments/ir-vmp/tests -v

python3 experiments/ir-vmp/vnext.py verify-release \
  --evidence /tmp/business-vm/release-evidence.json
```

The final command must return nonzero: host VM success is insufficient for release.
If the official toolchain's `llvm-config` names unavailable system libraries, the
checker builder accepts explicit `--system-library NAME=/absolute/library` flags.
Every override, command and library hash is recorded; no silent toolchain change
is made. The Linux execution used system `libzstd.so.1` and `libxml2.so.2`.

`off` is accepted only with `required=false` and reports `UNPROTECTED`. Canary and
release profiles are parsed strictly but return a production-integration blocker;
they cannot successfully build an SDK or trigger old armor `--all`. No Xcode or
SwiftPM production build mode is advertised by this checkpoint.

## Candidate validity and transformations

**A: policy selection.** The experiment retains the original global-read model;
test setup and state observation are separate native functions. It does not
replace reads with a by-value snapshot or claim concurrent reset is supported.
Both compiler invocations assert struct sizes, alignments and used offsets.
Each seed executes 504 deterministic cases and 10,000 random cases. Cases cover
0/1/64 entries, zero policies, unconditional runtime gates, selection/fallback,
all four nullable output combinations, and `high_risk` values
`0, 1, -1, 2, -7, INT_MIN, INT_MAX`.

The independent mix oracle cancels the direct identifier term *after selecting
the entries*. It does not assume changing identifiers preserves selection. Count
and mix are not connected to the production protocol or promoted to integrity tags.

**B: strong mix.** Three valid, disjoint 32-byte buffers are the supported domain;
null/overlapping inputs are not claimed as valid. The original rotation helper is
copied exactly. The experiment declaration adds `always_inline`: at `-O0` the
unannotated helper otherwise produces an i8-return external call outside the
accepted backend call ABI. Preflight rejects any surviving helper call. Both
native and VM builds use this recorded transformation; the formula is untouched.
Vectorization is disabled explicitly. Each seed executes 772 deterministic cases
(patterns, 256 input bits, 256 constant bits, all byte values) and 10,000 random
cases. Complete domain evaluation with legal bundles remains a separate missing gate.

## Global lifecycle finding blocking A2

`cprisk_integrity.c` has plain global plan/entry/count state. It is written by
`cprisk_antidebug_load_plan_i`, reset by `cprisk_init_protection` and cleanup, and
replaced/reset by the public test hooks. Selection and inline-patch routines read
it. The load routine sets `loaded` before finishing parsing; atomics for inline
patch flags do not synchronize these plan fields. A Swift initialization path uses
`armorInitLock`, but that does not establish a common C-side synchronization
contract for every reader, reset, test hook or multiple SDK instances.

This is a static lifecycle finding, not a reproduced concurrent exploit. Before
production parameterization, define the valid initialization/reset concurrency
contract and verify all callers. Do not silently add snapshot semantics or fix
data races inside a VMP refactor. Original serial behavior is the experiment scope.

## Evidence and remaining platform boundaries

See `validation/vnext-linux-x86_64-2026-10-03/summary.json` for exact commands,
completed counts, compiler/plugin/source hashes and recorded blockers. Raw JSON
reports are preserved alongside it. Build intermediates/binaries can be reproduced
from the source and provenance; they are not checked into Git.

The official LLVM 22.1.8 Linux archive was checked against GitHub's published
SHA-256 and its release signature using LLVM's published release keys. The archive
extractor reported owner-change errors under the container's UID mapping; files
were extracted and the compiler/checker/plugin were subsequently built and run.
No claim of external supply-chain attestation is made.

New negative tests cover duplicate keys/targets/seeds, unknown fields/versions,
wrong types and NaN/Infinity, source/patch identity drift, forged eligibility,
missing targets, stale reports, wrong plugin versions/hashes, disconnected engine
calls, corrupted return/count/output values and LLVM unsupported IR boundaries.
The legacy Swift tests preserve both shipped policies' compatibility semantics
and confirm that explicit full requests still throw. They run in macOS CI; this
Linux environment has no Swift/Xcode toolchain.

GF2 and stack native baselines remain intact. The new Linux GF2 real VM regression
passes; Linux stack VM is blocked because its initialization IR contains
`llvm.memset.p0.i64`, which the fixed backend skips. This is not inherited as a pass
from the historical macOS stack result, and the existing rejection is not relaxed.

Next implementation dependencies are A's lifecycle contract, B's complete domain
consumer harness, separately reviewed native kernel extraction, native-object SDK
linking with exactly one implementation, final artifact/callpath and bytecode
checks, then physical iPhone, performance and resilience gates. The SDK remains
native until those steps are completed.
