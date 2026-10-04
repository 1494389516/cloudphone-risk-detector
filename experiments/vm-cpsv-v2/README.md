# CPSV v2 and integrated context-threaded runtime

This implements the contract proposed in PR #98. Shipping defaults remain legacy
(`CPRISK_VM_THREADED_DISPATCH=0`). Defining it to 1 compiles the real interpreter's
A/B program drivers through the checked-in context-threaded engine. Unsupported
musttail compilers fail compilation. A threaded image requires a finalized v2
manifest and keyed expectation on every program preparation, regardless of the
optional bytecode M3 flags. Invalid/uninjected images fail before opcode execution;
there is no legacy/unhashed fallback.

## Contract and pipeline

- CPSV independently advances to version 2; global armor ABI and v1 stay unchanged.
- 58 ranges: legacy anchors 1–3, post-handler 4, lifetime drivers 5–6, 26 contexts
  per lane (canonical 0–23, poison 255, unknown 254). The runtime independently
  references the function identities; it never trusts the manifest as its roster.
- 32-byte header: LE magic/version/count/reserved, 16-byte Mach-O LC_UUID.
  Then 58 entries of LE u64 image RVA, u32 byte length, u32 kind (960 bytes total).
  The reservation is pointer-free, so post-link injection cannot overwrite dyld
  chained-fixup slots. The separate 8-byte CPSH expectation is reserved by the host linker (the
  existing Xcode project already uses `-sectcreate`). Do not also emit a C
  reservation: ld concatenates contributions, creating an invalid 16-byte section.
- Validate exact size/count/order, UUID, identity, instruction alignment, nonzero
  lengths, TEXT bounds, overlap and overflow; cap ranges at 64 KiB and total at
  1 MiB. Snapshot descriptors before validation/hash. This is not protection
  against an attacker concurrently rewriting executable pages during hashing.
- Hash the entire manifest followed by range bytes in roster order, using the
  existing custom-pad SHA256 MAC and existing material-derived key. Streaming
  keeps stack memory bounded. CPSH still truncates to 32 bits; no full-width MAC
  security claim is made.
- Build with the flag, retain an authoritative linker map and symbols, run code
  transformations, then supply final measured extents in a JSON sidecar:
  `{"imageSHA256":"...", "ranges":[{"name":"cprisk_vm_execute",
  "address":4294967296, "length":1234}, ...]}`. Addresses/lengths here are schematic.
  The sidecar is trusted build input, bound to the exact pre-injection image SHA256.
  Lengths must describe the final transformed functions. Do not use a stale
  linker map after size-changing transforms. Stripped/ambiguous extents reject.
- Generate the sidecar with `python3 experiments/vm-cpsv-v2/layout.py --image IMAGE
  --linkmap LINKMAP --output LAYOUT.json`. The tool rejects a map from a different
  image path, missing/folded/overlapping functions and out-of-TEXT extents.
- Run `cprisk-vm-self-expect --in IMAGE --hmac --material-hex MATERIAL
  --cpsv2-layout LAYOUT.json`, then sign. The Swift producer checks symbol identity
  and LC_FUNCTION_STARTS boundaries, patches the reservations and invalidates old signing metadata without moving
  protected code sections. `--fnv` cannot enable v2. Secrets should normally use the existing root
  key/environment mechanism rather than literal shell arguments.

`generate_runtime.py --check` verifies that checked-in handler preparation matches
original A/B prefixes. It preserves variant selection, poison/unknown bypass,
XOR mask ordering, fake dependencies, A-only barriers and lane finish behavior.
Legacy loops remain address/self-check compatibility anchors and test oracles.
The new route never returns to them per opcode. Shared post-handler checks remain
out of line; preparation/selection is inlined at each context's tail.

## Validation and remaining gates

- `run.py`: real C parser and streaming MAC vs independent Python oracle; optional
  `--swiftc` validates the same malformed/golden messages with the Swift codec.
- `../vm-threaded-dispatch/run.py --integrated`: fixed-input three-way comparison
  of pinned legacy, current legacy and current compiled threaded runtime; all 24
  opcodes, poison/unknown, bounds, step cap, CALL/RET/nested, plain/encrypted wire.
  Uses platform substitutes and normalized data-only code addresses. It does not
  claim entire SDK entry/finalization or self-check seal parity.
- `../vm-threaded-dispatch/inspect_arm64.py --integrated [--apple]`: 52 separate
  machine-code handlers, each musttail in IR and indirect ARM64 branch, three
  repeated objects at O0/O2/Os. Object evidence, not final iOS deployment proof.
- `apple_fixture.py`: real Swift injector and real C observer on an ad-hoc-signed
  native arm64 Mach-O fixture; all 58 ranges individually mutated and rejected,
  manifest mutations, uninjected image and stale sidecar rejected. Fixture roster
  functions are inert; this is not a production VM execution claim.

Before making threaded dispatch the shipping default: final post-armor iOS image
injection/retention/tail-transfer checks, actual emitted bytecode through the SDK
entry (including prelude/finalization), and real device evaluate() P95 with proof
of VM execution must pass. Hashing full ranges costs more than the old 176-byte
prefix; host opcode-loop timing cannot establish its impact. No performance
acceptance or complete virtualization of seven business functions is claimed.

## Recorded Apple integration evidence

Run 37183576996 (revision `f329ef89fac9f3df5f4e7951716cd9184ccfbdce`)
passed C/Swift parity (2,983 cases), the signed native fixture (58 code mutations
and seven manifest mutations rejected), integrated O0/O2 equivalence and stack
stress, and all 52 handler tail checks at O0/O2/Os with three identical objects per
configuration. JSON evidence and artifact provenance are in `evidence/apple/`.

`apple_linked.py` additionally builds the actual app with the threaded flag,
requires all 58 functions in the final iPhoneOS Release image, injects v2 using
that image's linker map, and checks all 52 linked handler indirect tail branches.
It deliberately fails if Xcode ignores the flag or drops the required functions.
This is stock Release plus self-expect injection, not the complete armor pipeline.

The first actual Release injection exposed an existing MachOKit classification
bug: `S_THREAD_LOCAL_ZEROFILL` (`__thread_bss`) was incorrectly treated as stored
file bytes. The shared section classifier now treats it like the other zero-fill
types. This is a prerequisite parser correction, not a change to another pass's
algorithm. The native fixture now includes TLS zero-fill and checks the numeric
type against Apple's own loader header to retain a regression case.
