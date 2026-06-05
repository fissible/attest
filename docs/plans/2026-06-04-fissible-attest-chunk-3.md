# fissible/attest - Chunk 3 Plan Outline

> Bundle export/import plus CLI wiring for anchoring, upgrading, and verification policy.

**Planning status:** This is an outline, not an executable implementation plan. It is intended to lock down format and workflow decisions before a Chunk-2-style task plan is written with file paths, method signatures, test cases, and commit boundaries.

**Goal:** Turn the Chunk 2 library primitives into operator-facing workflows: export portable proof bundles, verify them offline where possible, and expose core commands for anchoring, upgrading, and policy-driven verification.

**Scope:** `fissible/attest` core library first. Laravel integration is an explicit follow-up after the core APIs and CLI shapes settle.

## Product Shape

Chunk 3 should make these workflows concrete:

- Produce a portable proof bundle for a chain range.
- Verify a bundle without needing the original chain store.
- Verify a live chain store with `minAnchorOutcome` and provider-disagreement policy.
- Submit and upgrade anchors from CLI commands.
- Emit machine-readable verification results suitable for CI, cron, and Laravel jobs.

## Decisions To Lock Before Expansion

These decisions are pinned for the v1 bundle/CLI expansion:

- Bundle format: align with design spec Section 12: ZIP container with `manifest.json`, `chains/{sha256(chain_id)}.jsonl`, `proof_envelopes/{sha256(chain_id)}.jsonl`, optional `receipts/{anchor_id}.ots`, and optional `keys/{fingerprint}.pub`.
- Bundle trust model: the bundle has no integrity layer of its own. Trust comes from signed envelopes, externally trusted keys, anchor receipts, and live header providers where policy requires them. Bundled keys are claimed keys only.
- Verification result storage: no "last verification result" is stored in `fissible.attest.bundle/v1`. Verification output is produced by commands and may be saved by operators, but it is not trusted input to `Verifier`.
- Anchor export scope: v1 exports proof envelopes whose payload `[from_seq, to_seq]` exactly matches the requested chain segment. Wider overlapping anchors are not eligible because subset inclusion proofs are deferred from v1.
- CLI exit codes: align with design spec Section 13's outcome-specific mapping unless the spec is deliberately amended first.

## Pre-Expansion Blockers

Chunk 3 should not move from outline to executable implementation until these Chunk 1/2 alignment issues are either fixed or explicitly sequenced ahead of bundle verification:

- Binary payloads are accepted by `PayloadValidator` but not encodable by `JcsEncoder`; `Binary::ofRaw(...)` fails during signing. Fix the canonicalization path before v1.0.
- The 64KB cap is currently measured over canonical payload bytes, while the spec requires total signed canonical envelope size to be capped. Clamp full envelope size at signing or append validation.
- Detached/post-range anchor envelopes are collected by `Verifier` without signature verification. That is load-bearing for bundle `proof_envelopes/`, whose first validation step must be Ed25519 signature verification and external-trust classification.

## Proposed Task Groups

### 3.1 Bundle Format

Define the versioned bundle format from design spec Section 12.

Required members:

- `manifest.json`
- `chains/{sha256(chain_id)}.jsonl`
- `proof_envelopes/{sha256(chain_id)}.jsonl`

Optional members:

- `receipts/{anchor_id}.ots`
- `keys/{fingerprint}.pub`

Manifest fields:

- `format`: fixed string, `fissible.attest.bundle/v1`.
- `created_at`: RFC 3339 UTC timestamp.
- `issuer_hint`: optional informational string.
- `note`: optional informational string.
- `chains`: list of exported chain segments with chain ID, member path, `from_seq`, `to_seq`, envelope count, and head hash.
- `anchors`: list of detached proof envelopes with anchor ID, chain ID, exact range, Merkle algorithm, root, driver, state, proof envelope ID, and optional receipt cache path.
- `claimed_keys`: optional key metadata and member paths. These are never trusted by bundle presence alone.

Rules:

- Reject duplicate member names, absolute paths, `..` path segments, symlink entries, control chars, and unknown top-level prefixes.
- Reject entries outside `manifest.json`, `chains/`, `proof_envelopes/`, `keys/`, and `receipts/`.
- Enforce per-member and total bundle size limits before parsing JSON or OpenTimestamps receipts.
- Enforce a compression-ratio guard against zip bombs. The writer may store JSONL entries uncompressed for simpler byte accounting, but the format is still ZIP and the reader's safety checks carry the security boundary.
- Manifest hashes and counts are corruption checks only. They are not an authentication or tamper-resistance layer.
- Receipt bytes remain in signed canonical anchor envelopes as `base64:` fields in `proof_envelopes/`; `receipts/` is only a derived cache for external OTS tooling.
- If a `receipts/{anchor_id}.ots` file is present but does not byte-match the proof envelope's `receipt_bytes`, warn and ignore the cache file.

Deferred from v1:

- Signed bundle manifests.
- Persisted "last verification result".
- Full-chain archive bundles.
- Subset proofs for ranges covered only by wider anchors.

### 3.2 Bundle Codec And Validator

Add bundle read/write APIs:

- `BundleExporter` to collect chain bytes, detached proof envelopes, receipt-cache files, claimed keys, and metadata.
- `BundleReader` to validate structure and size limits.
- `BundleManifest` value object for manifest fields.
- Typed exceptions for unsupported version, malformed ZIP, missing member, duplicate member, oversize member, and manifest/member digest mismatch.

Validation rules:

- Accept `fissible.attest.bundle/v1` only.
- Decode raw envelope JSONL members only after member size and path checks pass.
- Compare advisory manifest counts, paths, hashes, and ranges with actual member bytes.
- Validate that chain record bytes decode to signed envelopes for the declared chain and requested range before passing them to `Verifier`.
- Validate each proof envelope signature and classify it against externally trusted keys before using its receipt for anchor verification.
- Validate that proof envelope `target_chain`, `[from_seq, to_seq]`, `merkle_algorithm`, `root`, and `anchor_id` bind exactly to the exported segment.

Acceptance coverage:

- Bundle round-trip is byte-stable for raw envelope members.
- Missing required members fail with typed errors.
- Over-large bundles and receipt payloads are rejected before expensive parsing.
- Invalid proof-envelope signatures fail before receipt verification.
- Valid but externally untrusted proof-envelope signatures produce `INTEGRITY_VERIFIED_UNTRUSTED` unless policy allows untrusted verification.
- Wider overlapping anchors are rejected as ineligible for v1 bundle proof.
- Bundle verification produces the same result as live chain verification for equivalent inputs.
- Manifest hashes detect accidental corruption but are documented as non-security checks.

### 3.3 Bundle-Backed Store Adapter

Provide a verifier-compatible store adapter over bundle contents:

- Implements `ChainStore` read methods plus `RawChainStore`; append operations are unsupported.
- Yields raw signed canonical bytes exactly as stored in the bundle.
- Exposes detached proof envelopes included in `proof_envelopes/`.
- Does not allow append.

Trust model:

- The adapter does not make the bundle trustworthy.
- `Verifier` still proves chain integrity through canonical bytes, sequence links, signatures, externally trusted keys, anchor receipts, and header providers.
- Claimed keys in `keys/` are convenience inputs only. Without external trust input, verification remains `INTEGRITY_VERIFIED_UNTRUSTED`.
- If the bundle omits needed proof envelopes or trusted keys, verification fails or reports the same warnings a live verification would.

Implementation requirement:

- Do not let detached proof envelopes bypass signature verification. Either extend `Verifier` with an explicit detached proof envelope input path or make the bundle adapter expose them through a verifier path that verifies signatures before `AnchorSetResolver` uses them.

This keeps the existing `Verifier` state machine as the authority instead of creating a parallel bundle verifier.

### 3.4 CLI Skeleton

Add a small framework-free CLI entrypoint under `bin/attest`:

- Composer `bin` declaration.
- Command-class dispatch with clear exit codes.
- JSON output mode for automation.
- Human output mode for operators.
- Direct command-class unit tests, not process-fork integration tests, for the first slice.

Commands to include in the first CLI slice:

- `attest verify`
- `attest bundle export`
- `attest bundle verify`
- `attest anchor`
- `attest upgrade`

CLI wiring rules:

- Commands that need local chain access require `--storage-root <dir>` unless a documented default is configured.
- Commands that need HTTP fail fast with a clear message if no PSR-18 client is available. The default CLI wiring may use Chunk 2's opt-in `OpenTimestampsCalendarClient::withGuzzle()` path when Guzzle is installed.

Exit codes:

- `0`: `VERIFIED`, or non-verification command completed successfully with no required work.
- `1`: CLI/configuration/runtime error before a `VerificationOutcome` is produced.
- `2`: `INTEGRITY_VERIFIED_UNTRUSTED` unless `--allow-untrusted` downgrades it to `0`.
- `3`: `ANCHOR_BELOW_MIN`.
- `4`: `INVALID_CHAIN`, `INVALID_SIGNATURE`, or `INVALID_ANCHOR`.
- `5`: `PROVIDER_DISAGREEMENT` unless `--allow-provider-disagreement` downgrades to the strongest passing outcome.

### 3.5 Verify Command

Wire live chain verification:

- `--storage-root <dir>`
- `--chain <id>`
- `--from <seq>`
- `--to <seq>`
- `--trusted-key <key-id>=<base64-public-key>`
- `--trusted-key-file <path>`
- `--min-anchor <value>`
- `--allow-provider-disagreement`
- `--allow-untrusted`
- `--bitcoin-core-rpc <url>`
- `--bitcoin-core-cookie <path>`
- `--esplora-url <url>`
- `--json`

`--min-anchor` accepted values are lowercase and exact:

- `local_only`
- `pending`
- `upgraded_no_headers`
- `remote_header_confirmed`
- `bitcoin_verified`

`--allow-untrusted` maps to `VerificationPolicy(requireTrustedKey: false)`. Without it, the CLI keeps Chunk 2's default `requireTrustedKey=true`.

JSON output schema v1:

```json
{
  "format_version": "attest.cli.result.v1",
  "command": "verify",
  "outcome": "verified",
  "verified": true,
  "exit_code": 0,
  "chain_stats": {},
  "signature_summary": {},
  "anchor_coverage": [],
  "anchor_verification": null,
  "headers_consulted": [],
  "warnings": []
}
```

Field names are stable for v1. Future versions may add fields but must not change these meanings without a format-version bump.

### 3.6 Bundle Export Command

Export a live chain range to a bundle:

- `attest bundle export --storage-root <dir> --chain <id> --from <seq> --to <seq> --out <path>`
- Reads raw canonical bytes where available.
- Walks forward past `--to` through the end of the chain and collects proof envelopes whose declared target exactly matches `[from, to]`.
- Refuses to export a proof bundle when only wider overlapping anchors exist; callers must export the full anchored range until subset proofs land.
- Does not implement `--include-all-anchors` as an overlap mode in v1. Ambiguous/overlapping coverage remains a live-chain verifier warning, not a bundle export feature.
- Emits a warning for pending anchors recommending `attest upgrade` before export when stronger receipts may be available.
- Allows explicit claimed-key metadata inclusion.
- Writes to a temporary file in the destination directory and then renames atomically.

The exporter should not claim the bundle is tamper-proof. It exports evidence that can be independently verified.

### 3.7 Bundle Verify Command

Verify a bundle using the same policy flags as live verification:

- No chain store required.
- Header providers are still live dependencies when `--min-anchor` requires active-chain confirmation.
- `attest bundle verify --min-anchor bitcoin_verified --bitcoin-core-rpc ...` reads chain bytes and receipts from the bundle, then calls the configured Bitcoin Core node for header verification.
- Header providers are optional only for thresholds that do not require them.
- Detached proof envelopes are signature-verified and classified against trusted keys before their receipt bytes are used.
- Claimed keys from the bundle are not sufficient trust input by themselves.
- Output includes warnings for no providers, provider unknowns, ambiguous coverage, and untrusted signatures.

Bundle verification proves the bundle contents against trusted keys and anchors. It does not prove that the bundle is a complete archive of the original chain outside the requested range.

### 3.8 Anchor And Upgrade Commands

Expose the library anchoring services:

- `attest anchor --storage-root <dir> --chain <id> --from <seq> --to <seq> --driver opentimestamps`
- `attest upgrade --storage-root <dir> --chain <id> --anchor-id <id>`
- `attest upgrade --storage-root <dir> --chain <id> --all-pending`
- PSR HTTP client wiring via optional Guzzle factory.
- Calendar URL and minimum calendar options.
- No network in tests; use mocked clients in command-class tests.

Claim contention behavior:

- If another process already holds the anchor claim and no matching completed anchor envelope exists yet, exit `0` with a warning: "skipped, anchor claim already held".
- If reconciliation finds an existing matching anchor envelope, exit `0` and report the existing envelope ID.
- Network or driver failures exit according to the CLI error table.

`--all-pending` is included in v1 for operator sweep mode. Laravel scheduled jobs can call the same service later instead of inventing adapter-specific behavior.

### 3.9 Documentation

Update README and changelog with:

- Bundle format summary.
- CLI examples.
- Exit code table.
- JSON output schema.
- Trust model for bundle verification versus live chain verification.
- Reminder that v0.x APIs and bundle format are alpha.

## Follow-Up Note: attest-laravel

Do not forget the Laravel adapter after Chunk 3 core lands.

Update `fissible/attest-laravel` to consume the new core APIs and expose:

- Laravel storage-backed chain and bundle locations.
- Queue jobs for anchor submission and receipt upgrade.
- Artisan commands wrapping `anchor`, `upgrade`, `verify`, and bundle export/verify.
- Config for trusted keys, OTS calendars, Bitcoin Core, Esplora, and min-anchor policy.
- Scheduled verification/reporting hooks for operators.

This should be planned as the next adapter chunk after the core bundle/CLI interfaces are stable enough to avoid churn.

## Done Criteria

- Core bundle APIs covered by PHPUnit and PHPStan.
- CLI commands covered without public network dependencies.
- `vendor/bin/phpunit` and PHPStan pass locally and in CI.
- Bundle verification reuses the core `Verifier` state machine.
- README has enough examples for an alpha user to run a local chain verification and a bundle verification.

## Expansion Checklist

Before implementation starts, expand this outline into a Chunk-2-style executable plan with:

- File paths and class/interface names.
- Method signatures.
- Test cases and fixtures.
- Commit boundaries.
- Explicit size limits for bundles, members, manifests, and receipt payloads.
- Atomic write and failure semantics for every command that writes files.
