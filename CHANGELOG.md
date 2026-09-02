# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
## [1.4.0] - 2026-09-02

### Fixed
- Stop FileChainStore reads at torn lines and report corrupt records as UndecodableRecord
- Report undecodable stored records as INVALID_CHAIN at the broken sequence
- Validate verify --from/--to and emit structured output for runtime errors
- Reject unsupported envelope versions in EnvelopeCodec
- Reject overflowing OTS varuints instead of wrapping
- Surface malformed base64 in Binary as InvalidPayload
- Reclaim expired anchor claims before skipping a range
- Export the strongest receipt when an anchor has been upgraded
- Exit 4 when an upgrade sweep upgrades nothing and every anchor failed
- Report unreachable calendars from upgrade instead of treating them as unchanged
## [1.3.0] - 2026-08-19

### Added
- Declare in verification JSON that completeness is not asserted
- Print the completeness caveat in human verify output

### Fixed
- Name range scoping alongside bypass, and anchor the statement text
## [1.2.0] - 2026-08-06

### Ci
- Gate branch protection on one aggregator job
## [1.1.2] - 2026-06-15

### Ci
- Fix Symfony compatibility install
## [1.1.1] - 2026-06-13

### Fixed
- Allow Symfony 8 components
## [1.1.0] - 2026-06-13

### Added
- Ship storage contract test traits

### Ci
- Bump actions/checkout + actions/cache to v5 (Node 24)
## [1.0.0] - 2026-06-10

### Added
- Add optional fsync flag to FileChainStore
- Switch canonical binary wrapper to $binary and reserve the key
## [0.4.0-alpha] - 2026-06-05

### Added
- Classify detached anchor envelopes by signature trust
- Constants + entry-path safety helpers
- BundleManifest value object and JSON parser
- BundleExporter with exact-range proof envelopes and atomic write
- BundleReader with safe ZIP parsing and ratio guard
- BundleStore RawChainStore adapter
- Accept explicit detached anchor envelopes for bundle path
- Skeleton, JSON output schema v1, shared helpers
- Attest verify command with spec §13 exit codes
- Attest bundle:export
- Attest bundle:verify
- Attest anchor
- Attest upgrade

### Changed
- Robust size-cap test + derive payload cap from envelope cap
- Move classification to enum factory + add mixed-group test

### Fixed
- Binary payloads round-trip through JCS via canonical stand-in
- Enforce 64KB total signed-envelope cap at sign and decode
- Align with §6/§7.2/§11 — chainStats rename, static facade, slash rejection
## [0.2.0-alpha] - 2026-06-05

### Added
- Add RFC 6962 tree primitives
- Add Bitcoin header providers
- Add OpenTimestamps anchoring
- Add anchor verifier state machine
## [0.1.0-alpha] - 2026-05-25

### Added
- RFC 8785 JCS encoder with core test coverage
- PayloadValidator with type policy + 64KB cap
- Ed25519 KeyPair + SodiumSigner with verification helper
- Fingerprint helper over raw pubkey bytes
- EvidenceEnvelope + SignedEnvelope two-form canonical bytes
- EnvelopeCodec for byte-identical round-trip decode
- ChainStore interface + AppendContext + shared contract trait
- PathMapper for safe FileChainStore layout
- FileChainStore read methods with backward-chunk tail
- FileChainStore append with flock + atomic meta/index
- EvidenceChain friendly wrapper hiding callback shape

### Fixed
- Drop typed class constants (PHP 8.3+ feature; we target 8.2+)

### Ci
- PHP 8.2/8.3/8.4 matrix on Linux + macOS with PHPStan + PHPUnit

