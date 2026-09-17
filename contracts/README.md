# Fusion contract migration — C01 C02 C03 C05 C06 G05

Baseline SDK: `6aeaf6783247258eba3f516efebd006561d4471c`.

`report-upload.schema.json` freezes the active **HTTP JSON** wire format. It is
not ProtoJSON and not a binary gRPC message: snake_case keys, numeric Unix
milliseconds, base64 bytes, raw string trust levels (unknown values retained).
The historical `cprisk.v1` documentation proto is read-only legacy reference.
The active `cloudphone.risk.v1` proto has additive proof/context fields; generated
Swift protobuf transport is a separate pending migration, not claimed complete.
`kind` and `contract_version` are new HTTP discriminator fields; collectors must
upgrade their allow-list before client rollout. Existing signatures are unchanged.

SDK reports, authenticated business events and decision requests have separate
schemas. A decision request references evidence; it does not forward SDK payloads
into an LLM. Challenge is a distinct action; no review translation is defined.

## Verification

```
python -m unittest discover -s contracts/tests -v
cd RiskDetectorApp
swift test --filter 'FusionTransportTests|FusionGraphTests|GraphModuleTests'
```

20 checked-in vectors cover v2/v2h/v2a/v2d/v3, proof absent/present and field
mapping absent/present. Both Python and Swift consume those fixtures. The keys in
them are test-only **effective request keys**: armor and HKDF derivation are not
covered. Python execution passed; Swift execution is pending a supported Apple
build host. The Python reference rejects floating-point JSON because Foundation
number formatting has not been frozen cross-language. Do not deploy this helper
as a production acceptance gate.

The SDK's historical MAC uses 0x6D/0xA3 pads, not standard HMAC. This patch preserves
that existing signature protocol. A cryptographic migration needs its own version.
The reference validates transport digest/signature only. Session auth, freshness,
atomic replay consumption, field-mapping registry, app/device/scene checks and
Apple assertion verification remain collector responsibilities. A valid signature
never proves a genuine human, and a client trust-level string never grants trust.

`requireHardwareAttestation` is preserved through create, copies and Codable, and
checked by all validated byte/JSON transports. It is local policy, not a trusted
client policy assertion; collector enforcement must be independent. Direct use of
the low-level unvalidated dictionary remains available for compatibility.

## Identity and feature provenance

The SDK omits raw SHA256 IP/ASN/account identity hints. Resolve authenticated account
and server-observed IP inside the collector, using `pseudonymize()` with a server
secret and explicit tenant/app/domain/key-version namespace. No secret belongs in
SDK or Agent. This server reference helper is not yet wired into a collector.
Installation hint and non-unique hardware attribute vector are separate. Old `hp`
is retained as a compatibility exact-match/churn hint; no hash-distance similarity.
All SDK attributes are client claims, including inner `server`/`sr` objects. They
must never populate trusted server aggregation. Top-level server aggregates are
rejected by the reference boundary.

The compatibility type `LocalDeviceClusterDetector` now emits
`local_identity_churn`, local-installation scope, and distinct local fingerprints.
It emits no IP/account key or distinct-device count. Its score and threshold are
unchanged. Historical cluster signal remains understood; local churn does not set
the compressed graph-cluster bit. Native regression assertions were migrated to
this explicit semantic correction, not removed.

## Remaining gates

Native Swift build/tests, create -> actual upload -> production collector validation,
real-device App Attest/armor checks, universal floating canonicalization, generated
DTO adoption, and production tenant identity resolver integration are **pending**.
No claim of all native bugs fixed or full-repository tests passing is made.
