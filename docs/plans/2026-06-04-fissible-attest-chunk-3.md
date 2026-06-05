# fissible/attest - Chunk 3 Plan Outline

> Bundle export/import plus CLI wiring for anchoring, upgrading, and verification policy.

**Goal:** Turn the Chunk 2 library primitives into operator-facing workflows: export portable proof bundles, verify them offline where possible, and expose core commands for anchoring, upgrading, and policy-driven verification.

**Scope:** `fissible/attest` core library first. Laravel integration is an explicit follow-up after the core APIs and CLI shapes settle.

## Product Shape

Chunk 3 should make these workflows concrete:

- Produce a portable proof bundle for a chain range.
- Verify a bundle without needing the original chain store.
- Verify a live chain store with `minAnchorOutcome` and provider-disagreement policy.
- Submit and upgrade anchors from CLI commands.
- Emit machine-readable verification results suitable for CI, cron, and Laravel jobs.

## Proposed Task Groups

### 3.1 Bundle Format

Define a versioned `attest.bundle.v1` format containing:

- Bundle metadata: version, generated timestamp, generator name/version.
- Chain identity and requested range.
- Raw signed canonical envelope bytes for the requested range.
- Anchor envelopes and receipts needed to prove that range.
- Trusted key metadata or key references, without embedding private material.
- Optional verifier policy summary and last verification result.

Open design points:

- JSON-only bundle versus ZIP with JSON manifest plus raw byte members.
- Whether receipt bytes remain base64 inside JSON or live as separate binary entries.
- How much key metadata to include without creating misleading trust assumptions.

### 3.2 Bundle Codec And Validator

Add bundle read/write APIs:

- `BundleWriter` or `BundleExporter` to collect chain bytes, anchors, and metadata.
- `BundleReader` or `BundleImporter` to validate structure and size limits.
- Strict version negotiation: accept v1 only, reject unknown major versions.
- Tamper checks for raw envelope bytes before handing them to `Verifier`.

Acceptance coverage:

- Bundle round-trip is byte-stable for raw envelope members.
- Missing required members fail with typed errors.
- Over-large bundles and receipt payloads are rejected before expensive parsing.
- Bundle verification produces the same result as live chain verification for equivalent inputs.

### 3.3 Bundle-Backed Store Adapter

Provide a verifier-compatible store adapter over bundle contents:

- Implements `RawChainStore`.
- Yields raw signed canonical bytes exactly as stored in the bundle.
- Exposes anchor envelopes included in the bundle.
- Does not allow append.

This keeps the existing `Verifier` state machine as the authority instead of creating a parallel bundle verifier.

### 3.4 CLI Skeleton

Add a small framework-free CLI entrypoint under `bin/attest`:

- Composer `bin` declaration.
- Command dispatch with clear exit codes.
- JSON output mode for automation.
- Human output mode for operators.

Commands to include in the first CLI slice:

- `attest verify`
- `attest bundle export`
- `attest bundle verify`
- `attest anchor`
- `attest upgrade`

### 3.5 Verify Command

Wire live chain verification:

- `--chain`
- `--from`
- `--to`
- `--trusted-key`
- `--trusted-key-file`
- `--min-anchor`
- `--allow-provider-disagreement`
- `--bitcoin-core-rpc`
- `--bitcoin-core-cookie`
- `--esplora-url`
- `--json`

Exit code sketch:

- `0`: verified
- `1`: verification failed by policy or integrity
- `2`: invalid CLI/configuration
- `3`: provider/network unavailable where policy requires it

### 3.6 Bundle Export Command

Export a live chain range to a bundle:

- Reads raw canonical bytes where available.
- Includes required anchor envelopes after the requested range.
- Allows explicit trusted-key metadata inclusion.
- Refuses ambiguous anchor coverage unless `--include-all-anchors` is specified.

### 3.7 Bundle Verify Command

Verify a bundle using the same policy flags as live verification:

- No chain store required.
- Header providers optional unless `--min-anchor` requires them.
- Output includes warnings for no providers, provider unknowns, ambiguous coverage, and untrusted signatures.

### 3.8 Anchor And Upgrade Commands

Expose the library anchoring services:

- `attest anchor --chain --from --to --driver opentimestamps`
- `attest upgrade --chain --anchor-id`
- PSR HTTP client wiring via optional Guzzle factory.
- Calendar URL and minimum calendar options.
- No network in tests; use mocked clients in command tests.

### 3.9 Documentation

Update README and changelog with:

- Bundle format summary.
- CLI examples.
- Exit code table.
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
