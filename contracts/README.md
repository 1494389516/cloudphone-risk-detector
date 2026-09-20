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

Test suites and dedicated fixtures were removed at the maintainer's request.
The remaining CI checks generated contract consistency and builds the SDK/armor tools:

```sh
python3 contracts/generate.py --check
swift build --package-path RiskDetectorApp
swift build --package-path cprisk-armor
```

These are build checks, not transport, cryptographic or behavioral regression tests.
The SDK transmits its already-canonical signed bytes. Python validates JSON syntax
and consumes those exact bytes; it does not reproduce Foundation number formatting.
The verifier remains one component of the Collector acceptance gate, not an
authentication or replay store.

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
the compressed graph-cluster bit. Historical regression assertions covered this semantic correction; the test
files have since been removed at the maintainer's request.

## Generated active transport

`report-upload.schema.json` is the source for Python structural validation and
Swift `GeneratedReportWire.swift`, called by the actual GrpcReportPayload transport.
Run `python contracts/generate.py --check` to reject stale generated boundaries.
The historical protobuf documentation is not a second active transport.
`verify_upload_with_base_key` derives v2h keys with RFC 5869, including the SDK's
BE32 emulator flags (server requires zero). Armor mode must supply an authorized
runtime-derived key through `verify_upload`, never a static-key fallback.

## Remaining external gates

`.github/workflows/fusion-contract.yml` checks generated contracts, compiles the
SDK and armor tools, and parses the Xcode project. It does not run test suites.
Real-device App Attest/armor checks still require
physical Apple hardware and an authorized application environment. No Detector or
threshold changes are included. Collector integration is implemented in the paired
Agent PR rather than exposing its credentials to the SDK or Agent tools.

## Collector App Attest enrollment and fresh assertion path

Configure `AppAttestSigner.configureEnrollment(challenge:submit:)` with authenticated
Collector callbacks. The challenge callback obtains an enrollment challenge and
returns its ID plus decoded base64 bytes. The submit callback sends the exact
`attestKey` object, key ID and challenge ID, and throws unless the Collector accepts
it. Only then does SDK persist the new `server_enrolled.v2` Keychain entry. Old
locally-attested-only keys cannot silently skip server enrollment.

For a report, obtain a fresh assertion challenge and call
`AppAttestSigner.createCollectorEnvelope(payloadData:reportId:sessionToken:signingKey:keyId:serverChallenge:)`.
This explicit v3 path generates both App Attest assertions before the envelope MAC:
primary proof signs SHA256(canonical report bytes), second proof signs SHA256(server
challenge bytes). Send via the normal `toGrpcRequestBytes(context:)` transport.
The Collector consumes challenge, increasing counter and evidence in one transaction.
Do not use the armor-only v2a path against a static-key Collector acceptance policy.

The server pins the operator-provided Apple App Attestation Root CA, validates the
certificate chain, nonce extension, App ID, counter=0, key ID, environment and COSE
key. Unhandled authenticator extensions fail closed. Synthetic CA tests prove the
validation code path, not a genuine Apple device; real-device validation is required.
