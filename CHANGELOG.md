# Changelog

## [Unreleased]

### Changed
- Promoted `Testing\AnchorClaimStoreContractTests` to `@api` so storage adapters can rely on both shipped contract-test traits as stable test support.

## [1.1.1] — 2026-06-13

### Fixed
- Allow Symfony 8 components for applications already on Symfony 8 while preserving PHP 8.2/8.3 compatibility through Symfony's own package requirements.

## [1.1.0] — 2026-06-13

### Added
- Shipped reusable storage contract test traits under `Fissible\Attest\Testing\*` so adapters can test their `ChainStore` and `AnchorClaimStore` implementations against the canonical core contract instead of copy-pasting traits from `tests/`.

## [1.0.0] — 2026-06-09

First stable release. From 1.0.0, `fissible/attest` follows semantic versioning — the supported public API is the set of classes marked `@api`. See [`STABILITY.md`](STABILITY.md).

### Added
- Optional `fsync` flag on `FileChainStore` (default off). When enabled, each append issues an OS-level `fsync()` after `fflush()` for power-loss durability, at a per-append throughput cost. Uses PHP's native `fsync()` (PHP ≥ 8.1; core requires ≥ 8.2). The `.meta.json` / `index.json` sidecars continue to rely on atomic rename and are not separately fsynced.
- **Stability commitment.** The supported public surface is annotated `@api`; `@internal` (or unmarked) classes are implementation detail and may change in any release. On-disk and interchange formats are frozen within 1.x (additions additive; removals/renames require a format-version bump): canonical envelope JSON (RFC 8785), the `{"$binary": …}` sentinel, the `fissible.attest.bundle/v1` bundle, and the `attest.cli.*.v1` CLI JSON schemas. The CLI contract (commands, options, exit codes, `--json` schemas) is stable even though `src/Cli/` is internal. See [`STABILITY.md`](STABILITY.md).

### Changed
- **Breaking (format):** the canonical binary wrapper is now `{"$binary": "<base64>"}` (was `{"_attest_binary": "<base64>"}`), and the `$binary` key is reserved — `PayloadValidator` rejects user payloads that use it directly. Because an envelope's signature covers its canonical bytes, alpha-era envelopes that carry binary blobs will no longer verify under the new wrapper; there is no transparent migration.

### Experimental
- The anchoring subsystem — OpenTimestamps submission and Bitcoin header verification (`src/Anchor`, `src/Headers`, `src/Merkle`) — is `@experimental` in 1.x: usable and tested, but its PHP API may change in a minor release; it graduates to `@api` after live-network validation. `AnchorOutcome` remains `@api`. A stable `VerificationResult` may carry an experimental `AnchorVerification` via `->anchorVerification`.

## [0.4.2-alpha] — 2026-06-07

### Fixed
- `verify` and `bundle:verify` now register OpenTimestamps verification drivers when the optional Guzzle PSR-18 stack is installed, allowing upgraded OTS receipts to satisfy `--min-anchor` policies instead of being limited to local-only receipt verification.
- `upgrade --anchor-id` is idempotent for anchors that are already past `pending`; it returns exit 0 with an `unchanged` entry instead of reporting that no pending anchor was found.
- `upgrade` now passes the configured calendar URLs as the OpenTimestamps upgrade allowlist, keeping upgrade requests constrained to the operator-selected calendars.

### Tests
- Activated CLI coverage for OpenTimestamps anchoring, upgrade, verification, bundle export, bundle verification, calendar-unavailable handling, and provider-disagreement exits through injectable PSR-18 calendar and header-provider seams.

## [0.4.1-alpha] — 2026-06-05

### Added
- `release.sh` and `.cliff.toml` copied from `fissible/.github`; `.github/workflows/release.yml` wires the reusable release workflow so tag pushes auto-create a GitHub Release. Note: the canonical `release.sh` assumes pure semver and currently cannot bump `0.x.y-alpha` directly — manual tag procedure remains the path for `-alpha` releases until either the script is patched upstream or VERSION drops the suffix.
- `AnchorCommand` and `UpgradeCommand` accept an optional `(callable(): OpenTimestampsCalendarClient)|null` constructor parameter as a PSR-18 client injection seam. The default null falls back to `OpenTimestampsCalendarClient::withGuzzle()`. This unblocks mockable CLI tests for OTS calendar interactions in the next chunk.

### Changed
- `BundleExporter` now falls back to the key's hex fingerprint (rather than the literal string `'unnamed'`) when `withClaimedKey()` is called without an explicit `key_id`. The manifest's `key_id` is informational only — claimed keys are never auto-trusted by the verifier — but the fingerprint is the canonical identifier when no human-readable name was provided.

## [0.4.0-alpha] — 2026-06-05

### Added
- **Bundle format `fissible.attest.bundle/v1`** — portable ZIP container with `manifest.json`, `chains/{hash}.jsonl`, `proof_envelopes/{hash}.jsonl`, optional `receipts/{anchor_id}.ots`, optional `keys/{fingerprint}.pub`. Members stored uncompressed; reader enforces per-member + total size + compression-ratio guards.
- `Fissible\Attest\Bundle\{BundleConstants, BundleEntryPath, BundleManifest, ChainSegmentMeta, AnchorMeta, ClaimedKeyMeta, BundleExporter, BundleWriter, BundleReader, BundleStore}` plus typed exceptions (`InvalidBundle`, `InvalidBundleManifest`, `BundleExportException`).
- `Fissible\Attest\Chain\PathSafety` helper for CLI write-path validation.
- **`attest` CLI** (`bin/attest`) with five commands: `verify`, `bundle:export`, `bundle:verify`, `anchor`, `upgrade`. Spec §13 exit-code mapping (0/1/2/3/4/5). Stable JSON output schemas: `attest.cli.result.v1`, `attest.cli.export.v1`, `attest.cli.anchor.v1`, `attest.cli.upgrade.v1`.
- `Fissible\Attest\Verification\StaticVerifier::verifyChain()` — spec §6 facade.
- **Verifier**: new `detachedAnchorEnvelopes` constructor parameter so external callers (notably `BundleVerifyCommand`) can feed proof envelopes that aren't in the chain segment. Detached envelopes pass through `DetachedAnchorVerifier` classification.

### Changed
- `VerificationResult::$stats` renamed to `$chainStats` (spec §11).
- `PathMapper` now rejects forward and back slashes in `chain_id` (spec §7.2).

### Fixed (from Chunk 2.5)
- **Binary payload end-to-end through JCS**: `PayloadValidator::ensure()` returns the canonical payload form (`Binary` → `{"_attest_binary": "<base64>"}` array stand-in); `EvidenceChain::record()` stores that canonical form. Previously `Binary::ofRaw(...)` would fail at signing with `JCS: unsupported type Fissible\Attest\Envelope\Binary`.
- **Full signed-envelope 64KB cap (spec §5.3)**: `SignedEnvelope::sign()` and `EnvelopeCodec::decodeSigned()` enforce `MAX_SIGNED_ENVELOPE_BYTES = 65536` on the total signed canonical envelope. Payload-side cap lowered to 60KB to leave envelope-frame headroom (derived from envelope cap, not a magic literal).
- **Detached anchor signature verification**: `Verifier` now runs every anchor envelope through `DetachedAnchorVerifier` before `AnchorSetResolver`. INVALID signatures drop the group with a `DETACHED_ANCHOR_INVALID_SIGNATURE` warning; valid-but-untrusted signatures cannot satisfy `--min-anchor` under `requireTrustedKey=true` (`DETACHED_ANCHOR_UNTRUSTED` warning). New: `DetachedAnchorClassification` enum, `DetachedAnchorVerifier` class, `ClassifiedDetachedAnchor` value object.

### Dependencies
- `symfony/console: ^6.4 || ^7.0` added to `require` for the CLI.

### Notes
- v0.x APIs, bundle format, and CLI JSON schemas remain alpha. Field meanings are pinned within v0.4.x; future additions will be additive.
- Bundles store members uncompressed for byte-accounting symmetry; the reader still enforces a compression-ratio guard against bundles produced by other writers.

## [0.2.0-alpha] — 2026-06-04

### Added
- RFC 6962-style SHA-256 Merkle tree primitives for signed envelope byte ranges.
- Anchor value objects, deterministic `anchor_id` derivation, and `attest.anchor.submitted` / `attest.anchor.upgraded` payload parsing.
- File-backed anchor claim store and anchor orchestration service with raw canonical byte anchoring where the store supports it.
- OpenTimestamps proof codec, calendar client, and driver with pending and upgraded receipt handling.
- `NullDriver` for explicit local-only anchor receipts.
- Bitcoin Core RPC and Esplora header providers with active-chain height lookup.
- Signature/key verification helpers for trusted Ed25519 key matching by `key_id` or fingerprint.
- Verifier state machine for chain integrity, raw-byte canonical identity, trusted-key policy, exact/range anchor coverage, `minAnchorOutcome`, and provider disagreement handling.

## [0.1.0-alpha] — 2026-05-25

Proof-of-life release. Not on Packagist. Use via path repository for local testing only.

### Added
- `Fissible\Attest\Canonical\JcsEncoder` — RFC 8785 canonical JSON encoder (subset; floats rejected, integers stay within JS-safe ±2⁵³−1, UTF-16 code-unit key ordering).
- `Fissible\Attest\Envelope\PayloadValidator` — type policy with 64KB canonical cap.
- `Fissible\Attest\Envelope\Binary` — opaque binary blob wrapper, 64KB cap.
- `Fissible\Attest\Envelope\InvalidPayload` — exception for payload policy violations.
- `Fissible\Attest\Signing\KeyPair` — Ed25519 keypair (generate + deterministic fromSeed).
- `Fissible\Attest\Signing\Signer` interface + `SodiumSigner` implementation.
- `Fissible\Attest\Signing\SignatureVerification` — detached verify helper.
- `Fissible\Attest\Signing\Fingerprint` — sha256 over raw 32-byte pubkey.
- `Fissible\Attest\Envelope\EvidenceEnvelope` — unsigned envelope value object.
- `Fissible\Attest\Envelope\SignedEnvelope` — signed envelope with two-form canonical bytes (per spec §5).
- `Fissible\Attest\Envelope\EnvelopeCodec` — round-trip byte-identical decode/encode.
- `Fissible\Attest\Chain\ChainStore` — interface with callback-shaped `append()`.
- `Fissible\Attest\Chain\AppendContext` — store-supplied envelope context.
- `Fissible\Attest\Chain\ContextMismatch` + `ChainLockUnavailable` exceptions.
- `Fissible\Attest\Chain\PathMapper` — safe filename derivation, control-char rejection.
- `Fissible\Attest\Chain\FileChainStore` — JSONL + per-chain `flock()` + atomic metadata + global index.
- `Fissible\Attest\Chain\EvidenceChain` — friendly wrapper hiding the callback shape.
- Concurrent-append test: 8 forked workers × 100 envelopes assert single linear chain.

### Known limitations
- Pure-PHP `fflush()` is used for durability (no portable `fsync`); sufficient against process crashes, weaker against power loss. A driver hook for OS-level fsync may land later.
- File rotation deferred to v1.1; one active JSONL per chain.
- Official RFC 8785 vector suite import deferred (upstream vectors include float/scientific-notation cases this subset rejects; selective import work belongs in a follow-up).

### Not yet implemented (deferred to later chunks)
- OpenTimestamps anchor driver
- Block header providers (Bitcoin Core RPC, Esplora)
- Verifier
- Bundle format + CLI
- Laravel adapter
