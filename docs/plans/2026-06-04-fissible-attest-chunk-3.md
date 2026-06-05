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

- Bundle format: ZIP container with a JSON manifest and uncompressed raw byte members.
- Bundle trust model: the bundle has no integrity layer of its own. Trust comes from signed envelopes, trusted keys, anchor receipts, and live header providers where policy requires them.
- Verification result storage: no "last verification result" is stored in `attest.bundle.v1`. Verification output is produced by commands and may be saved by operators, but it is not trusted input to `Verifier`.
- Anchor export scope: default export includes anchor envelopes whose declared target overlaps the requested range. `--include-all-anchors` means all anchor envelopes touching the requested range, including overlapping or ambiguous anchors; it does not mean every anchor envelope on the chain.

## Proposed Task Groups

### 3.1 Bundle Format

Define a versioned `attest.bundle.v1` ZIP format.

Required members:

- `manifest.json`
- `chain/<chain-id-safe>/records.jsonl`
- `anchors/<chain-id-safe>/anchors.jsonl`

Manifest fields:

- `format_version`: fixed string, `attest.bundle.v1`.
- `generated_at`: RFC 3339 UTC timestamp.
- `generator`: object with package name and version.
- `chain`: object with chain ID, requested `from_seq`, requested `to_seq`, and record count.
- `members`: object mapping member path to byte length and SHA-256 digest.
- `trusted_keys`: optional informational key metadata or key references, never private key material.
- `policy`: optional informational policy summary used when the bundle was exported.

Rules:

- ZIP entries must be stored uncompressed. Reject compressed entries to avoid zip-bomb behavior and keep raw byte accounting simple.
- Reject duplicate member names, absolute paths, `..` path segments, symlink entries, and unknown required-member replacements.
- Enforce per-member and total bundle size limits before parsing JSON or OpenTimestamps receipts.
- Member SHA-256 values are corruption checks only. They are not an authentication or tamper-resistance layer.
- Receipt bytes remain in canonical anchor envelopes as `base64:` fields; raw chain and anchor envelope bytes live in JSONL members.

Deferred from v1:

- Signed bundle manifests.
- Persisted "last verification result".
- Full-chain archive bundles.
- Compression.

### 3.2 Bundle Codec And Validator

Add bundle read/write APIs:

- `BundleExporter` to collect chain bytes, anchor envelopes, and metadata.
- `BundleReader` to validate structure and size limits.
- `BundleManifest` value object for manifest fields.
- Typed exceptions for unsupported version, malformed ZIP, missing member, duplicate member, oversize member, and manifest/member digest mismatch.

Validation rules:

- Accept `attest.bundle.v1` only.
- Decode raw envelope JSONL members only after member size and path checks pass.
- Compare manifest SHA-256 values with actual member bytes.
- Validate that chain record bytes decode to signed envelopes for the declared chain and requested range before passing them to `Verifier`.

Acceptance coverage:

- Bundle round-trip is byte-stable for raw envelope members.
- Missing required members fail with typed errors.
- Over-large bundles and receipt payloads are rejected before expensive parsing.
- Bundle verification produces the same result as live chain verification for equivalent inputs.
- Manifest hashes detect accidental corruption but are documented as non-security checks.

### 3.3 Bundle-Backed Store Adapter

Provide a verifier-compatible store adapter over bundle contents:

- Implements `RawChainStore`.
- Yields raw signed canonical bytes exactly as stored in the bundle.
- Exposes anchor envelopes included in the bundle.
- Does not allow append.

Trust model:

- The adapter does not make the bundle trustworthy.
- `Verifier` still proves chain integrity through canonical bytes, sequence links, signatures, trusted keys, anchor receipts, and header providers.
- If the bundle omits needed anchors or trusted keys, verification fails or reports the same warnings a live verification would.

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

- `0`: verified, or command completed successfully with no required work.
- `1`: integrity or anchor failure (`INVALID_CHAIN`, `INVALID_SIGNATURE`, `INVALID_ANCHOR`).
- `2`: policy failure (`ANCHOR_BELOW_MIN`, `PROVIDER_DISAGREEMENT`, `INTEGRITY_VERIFIED_UNTRUSTED`).
- `3`: invalid CLI arguments or configuration.
- `4`: provider/network unavailable while required by policy.

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
- Walks forward past `--to` through the end of the chain and collects anchor envelopes whose declared target overlaps `[from, to]`.
- By default, refuses ambiguous overlapping anchor coverage and reports the overlapping anchor IDs.
- With `--include-all-anchors`, includes every anchor envelope touching the requested range, including ambiguous overlaps.
- Emits a warning for pending anchors recommending `attest upgrade` before export when stronger receipts may be available.
- Allows explicit trusted-key metadata inclusion.
- Writes to a temporary file in the destination directory and then renames atomically.

The exporter should not claim the bundle is tamper-proof. It exports evidence that can be independently verified.

### 3.7 Bundle Verify Command

Verify a bundle using the same policy flags as live verification:

- No chain store required.
- Header providers are still live dependencies when `--min-anchor` requires active-chain confirmation.
- `attest bundle verify --min-anchor bitcoin_verified --bitcoin-core-rpc ...` reads chain bytes and receipts from the bundle, then calls the configured Bitcoin Core node for header verification.
- Header providers are optional only for thresholds that do not require them.
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
