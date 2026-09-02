# Stability and Versioning

From **v1.0.0**, `fissible/attest` follows [semantic versioning](https://semver.org/). This
document defines exactly what "stable" covers.

## `@api` — the supported surface

Classes, interfaces, enums, and traits marked `@api`, together with their public methods and
properties, are the supported surface. Within the `1.x` line:

- No breaking changes to their signatures or documented behavior.
- Additions are additive (new optional parameters, new methods) and will not break existing
  callers.

Breaking changes to the `@api` surface require a major version bump.

## `@internal` — implementation detail

Anything marked `@internal` — **and anything not marked `@api`** — is implementation detail. It
may change or be removed in any release, including a patch. Do not depend on it.

## The `@api` surface

**Write & storage** — `EvidenceChain`, `ChainStore`, `RawChainStore`, `FileChainStore`,
`AppendContext`, `ChainLockUnavailable`, `ContextMismatch`

**Envelope** — `Binary`, `EvidenceEnvelope`, `SignedEnvelope`, `PayloadValidator`,
`InvalidPayload`

**Signing** — `Signer`, `SodiumSigner`, `KeyPair`, `Fingerprint`

**Canonical** — `JcsEncoder`

**Verification** — `Verifier`, `StaticVerifier`, `VerificationPolicy`, `SignatureVerifier`,
`TrustedKey`, `VerificationResult`, `VerificationOutcome`, `ChainStats`, `Warning`,
`SignatureVerificationResult`, `KeyMatch`

**Bundle** — `BundleExporter`, `BundleReader`, `BundleManifest`, `ChainSegmentMeta`,
`ClaimedKeyMeta`, `BundleExportException`, `InvalidBundle`, `InvalidBundleManifest`,
`BundleSupportUnavailable`

Bundles are the only feature that needs `ext-zip`, which is a `suggest` rather than a `require`.
Opening a bundle for read or write without it throws `BundleSupportUnavailable` — deliberately
not `InvalidBundle`, so an environment gap is never reported as a verification failure.

**Anchor** — `AnchorOutcome` (the enum is `@api` because it is named by `VerificationPolicy`)

**Testing support** — `Testing\ChainStoreContractTests`, `Testing\AnchorClaimStoreContractTests`

## Wire & format stability

Independently of the PHP API, these on-disk / interchange formats are frozen within `1.x`
(additions are additive; removals or renames require a format-version bump):

- Canonical envelope JSON (RFC 8785 JCS) and the signed-envelope frame.
- Binary sentinel: `{"$binary": "<base64>"}`.
- Bundle format: `fissible.attest.bundle/v1`.
- CLI JSON schemas: `attest.cli.result.v1`, `attest.cli.export.v1`, `attest.cli.anchor.v1`,
  `attest.cli.upgrade.v1`.
- Anchor-id domain separator `attest-anchor-v1`; Merkle algorithm `sha256-rfc6962`.

Note: even where a canonicalization *class* (`JcsEncoder`, `PayloadValidator`) is `@api`, its
byte *output* is additionally frozen here — signatures are computed over it, so it cannot change
without breaking existing evidence.

## CLI contract

The CLI's commands, options, exit codes, and `--json` output schemas are stable surface,
documented in the README. The PHP classes under `src/Cli/` that implement them are `@internal`.

## Experimental: anchoring

The anchoring subsystem — OpenTimestamps submission and Bitcoin header verification
(`src/Anchor/**`, `src/Headers/**`, `src/Merkle/**`) — is **`@experimental`** in `1.x`. It is
usable and tested, but its PHP API may change in a minor release; it graduates to `@api` after
live-network validation against real calendars and Bitcoin confirmations.

Consequences:

- `AnchorOutcome` is `@api` (it is part of `VerificationPolicy`). Of its ranked values, only
  `REMOTE_HEADER_CONFIRMED` and `BITCOIN_VERIFIED` result from a check against block headers;
  `LOCAL_ONLY`, `PENDING`, and `UPGRADED_NO_HEADERS` are read from the chain's own signed
  content and can be produced by any holder of a trusted signing key. Policies that need
  external time binding must require one of the two header-confirmed outcomes.
- A stable `VerificationResult` may carry an experimental `AnchorVerification` via its
  `->anchorVerification` property. The presence and shape of that sub-object is not yet frozen.
- `Testing\AnchorClaimStoreContractTests` is `@api` test support for adapters, even though
  `AnchorClaimStore` itself remains experimental.
