# Changelog

## [Unreleased]

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
