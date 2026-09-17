# SDK implementation evidence

Pinned source SHA: `6aeaf6783247258eba3f516efebd006561d4471c`.
Working tree changes only; no commit/branch operation performed by sub-agent.

| Issue | Trigger / minimal reproduction | Changed function or artifact | State |
|---|---|---|---|
| C01 | Create v3 envelope with `attestationKeyId`, assertions, trust, serialize actual upload bytes: previously proof fields absent | `GrpcReportPayload.init`, `toJSONDictionary`, `ReportEnvelope.toGrpcCompatiblePayload`; `FusionTransportTests.testTransportPreservesProofAndBindingFields` | Code implemented; native verification pending |
| C02 | Existing documentation nested Timestamp upload cannot deserialize active flat millisecond JSON | `contracts/*.schema.json`, active proto additive context, legacy proto notice, Python reference, shared 20 vectors | Partial: no generated Swift DTO, production collector or universal numeric canonicalization |
| C03 | Required hardware=true, key present, assertion absent: old send still succeeded | `ReportEnvelope` init/create/Codable/copy paths retain requirement; `GrpcReportPayload.validatedJSONDictionary` rejects | Code implemented; native verification pending |
| C05 | Public IP/account unhashed domain SHA can be enumerated; local evidence key leaks IP | Collector omits IP/ASN/account digest outputs; churn evidence drops key; server `pseudonymize` standard HMAC namespaces | Partial: reference helper not deployed collector resolver; whole report privacy audit pending |
| C06 | One local installation rotates five hw hashes, emitted distinct_devices=5 | `LocalDeviceClusterDetector.recordAndDetect` emits local_identity_churn + local scope; evaluation groups by installation; exact old score/threshold retained | Code implemented; native verification pending |
| G05 | Same model with distinct IDs has unrelated hw hashes and cannot be compared for similarity | `GraphNodeDescriptor.installationKey/hardwareAttributes`; collector populates separate identity hint / explainable vector | Partial: server resolved identity and similarity consumer integration pending |

## Actual executions

Before implementation:

- `python -m unittest discover -s contracts/tests -v`: exit 1,
  `ModuleNotFoundError: No module named 'contracts.report_contract'`.
  This is the new missing-contract test red, **not** proof of reproducing the
  original Swift bug at runtime.
- `cd RiskDetectorApp && swift test --filter FusionTransportTests`: exit 127,
  `/bin/bash: line 1: swift: command not found`. Native red/green unavailable.

After implementation:

- `python -m unittest discover -s contracts/tests -v`: exit 0, 8 tests passed,
  including 20 vector subcases and tampered attestation-key negatives.
- `git diff --check`: exit 0.

No all-repository test pass, end-to-end collector pass, real-device App Attest
verification, or native bug closure is claimed. Parent integrator should keep this
PR draft until a supported Apple runner executes tests and reviews protocol rollout.

## Side effects and migration

- HTTP upload adds kind/version and proof/context fields. Collector allow-list
  rollout precedes clients. Protocol fingerprints unchanged.
- IP/ASN/account client digests become nil: consumers must resolve their own trusted
  network/account identifiers, and cannot rely on old values remaining available.
- Churn signal identifier/category changes intentionally; legacy regression cases
  retained with migrated expected semantics. RiskDetectionEngine only gains the
  new signal ID with identical 55 weight. No unrelated detector or threshold edits.
- Local churn no longer sets the old compressed graph-cluster bit, avoiding false
  cross-device semantics; old historical graph IDs remain supported.
- Native DTO is still handwritten. Reference accepts unknown trust-level strings,
  rejects timestamp seconds and typed SDK/business-event confusion. It rejects
  floating-point payloads explicitly pending a universal canonical format.
