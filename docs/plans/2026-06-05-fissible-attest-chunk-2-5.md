# fissible/attest — Chunk 2.5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three Chunk 1/2 alignment gaps that block bundle verification and v1.0: end-to-end `Binary` payload support through JCS, full signed-envelope size cap, and Ed25519 signature verification of detached anchor envelopes.

**Architecture:** Targeted, defensive fixes only — no new features. `PayloadValidator` returns the canonicalized payload (Binary → JSON stand-in array) so JCS never sees a PHP object. Envelope size cap moves to signing and decoding. `Verifier` classifies post-range anchor envelopes by signature trust before passing them to `AnchorSetResolver`.

**Tech Stack:** PHP 8.2+, paragonie/constant_time_encoding, libsodium (ext-sodium), PHPUnit 11.

**Out of scope:** Bundle format, CLI, spec-drift renames (`$stats` → `$chainStats`, static `Verifier::verifyChain()` facade). Those land in Chunk 3.

**Tag at completion:** `v0.3.0-alpha`.

---

## Assumed from Chunks 1-2

- `Fissible\Attest\Envelope\Binary` with `MAX_BYTES = 65536`, `::ofRaw`, `::ofBase64`, `::raw`, public `$base64` field.
- `Fissible\Attest\Envelope\PayloadValidator::ensure(array): array` — currently validates and returns the original payload unchanged.
- `Fissible\Attest\Envelope\InvalidPayload` exception.
- `Fissible\Attest\Canonical\JcsEncoder::encode(mixed): string` — rejects PHP objects with `JCS: unsupported type ...`.
- `Fissible\Attest\Envelope\EvidenceEnvelope` value object with `array $payload`.
- `Fissible\Attest\Envelope\SignedEnvelope::sign(EvidenceEnvelope, Signer): self`, `::signedCanonicalBytes()`, `::unsignedCanonicalBytes()`.
- `Fissible\Attest\Envelope\EnvelopeCodec::decodeSigned(string): SignedEnvelope`.
- `Fissible\Attest\Chain\EvidenceChain::record(string $type, array $payload, ...): SignedEnvelope` — currently calls `PayloadValidator::ensure($payload)` then passes the *original* `$payload` to `EvidenceEnvelope`.
- `Fissible\Attest\Verification\Verifier` with private `anchorEnvelopesFor(string $chainId, int $toSeq, array $rangeEnvelopes): array` — currently collects post-range anchor envelopes without signature verification.
- `Fissible\Attest\Verification\SignatureVerifier::verify(SignedEnvelope): SignatureVerificationResult` — returns trusted / untrusted / invalid / unsupported-algorithm classifications.
- `Fissible\Attest\Verification\AnchorSetResolver::resolve(iterable<SignedEnvelope>): list<ResolvedAnchor>` — parses payloads; does not verify signatures.
- `Fissible\Attest\Verification\Warning` value class with constants for `NO_RAW_BYTES`, `ANCHOR_COVERAGE_GAP`, `ANCHOR_COVERAGE_AMBIGUOUS`, `HEADER_PROVIDER_UNKNOWN`, `ANCHOR_OVER_RECOMPUTED_BYTES`, `PROVIDER_DISAGREEMENT_ALLOWED`.

If any of these symbols are missing or named differently, stop and escalate before extending Chunk 2.5.

---

## File Structure

**New:**
- `src/Verification/DetachedAnchorClassification.php` — enum: `TRUSTED`, `UNTRUSTED_VALID`, `INVALID`, `UNSUPPORTED_ALG`.
- `src/Verification/DetachedAnchorVerifier.php` — verifies signatures of post-range anchor envelopes and returns classified envelopes.
- `tests/Envelope/BinaryRoundTripTest.php` — end-to-end record-sign-decode-verify with a payload containing `Binary`.
- `tests/Envelope/SignedEnvelopeSizeCapTest.php` — sign-time and decode-time enforcement of the 64KB total.
- `tests/Verification/DetachedAnchorVerifierTest.php` — classification matrix.
- `tests/Verification/VerifierDetachedAnchorSigTest.php` — Verifier respects classification in anchor satisfaction.

**Modified:**
- `src/Envelope/PayloadValidator.php` — `ensure()` returns canonicalized payload (Binary → array stand-in); cap repurposed.
- `src/Chain/EvidenceChain.php` — `record()` uses the canonicalized return value.
- `src/Envelope/SignedEnvelope.php` — new `MAX_SIGNED_ENVELOPE_BYTES` const enforced in `sign()`.
- `src/Envelope/EnvelopeCodec.php` — `decodeSigned()` enforces the same cap before parsing JSON.
- `src/Verification/Warning.php` — new codes `DETACHED_ANCHOR_INVALID_SIGNATURE`, `DETACHED_ANCHOR_UNTRUSTED`.
- `src/Verification/Verifier.php` — `anchorEnvelopesFor()` classifies via `DetachedAnchorVerifier`; integrate classification into anchor satisfaction.
- `CHANGELOG.md`, `README.md` — document Binary canonical form, full-envelope cap, detached-anchor sig handling.

---

## Task 2.5.1: End-to-end Binary support through JCS

**Why:** `PayloadValidator::ensure()` accepts `Binary` for validation but returns the original payload unchanged. `EvidenceChain::record()` stores that original payload, and `JcsEncoder::encode()` rejects `Binary` objects with `JCS: unsupported type Fissible\Attest\Envelope\Binary`. Spec §5.3 lists `Binary` as an allowed canonical type. We fix this by having `PayloadValidator::ensure()` return the canonicalized payload (with `Binary` instances replaced by `['_attest_binary' => $base64]` arrays) and having `EvidenceChain::record()` use the returned value.

**Files:**
- Modify: `src/Envelope/PayloadValidator.php`
- Modify: `src/Chain/EvidenceChain.php`
- Create: `tests/Envelope/BinaryRoundTripTest.php`

- [ ] **Step 1: Write the failing integration test**

Create `tests/Envelope/BinaryRoundTripTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Canonical\JcsEncoder;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\Binary;
use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\PayloadValidator;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class BinaryRoundTripTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-binary-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_payload_validator_canonicalizes_binary_to_array_stand_in(): void
    {
        $payload = ['blob' => Binary::ofRaw('hi')];
        $canonical = PayloadValidator::ensure($payload);

        self::assertSame(
            ['blob' => ['_attest_binary' => base64_encode('hi')]],
            $canonical,
        );
    }

    public function test_jcs_encodes_canonicalized_binary_payload(): void
    {
        $payload = ['blob' => Binary::ofRaw('hi')];
        $canonical = PayloadValidator::ensure($payload);

        $encoded = JcsEncoder::encode($canonical);

        self::assertStringContainsString('"_attest_binary":"' . base64_encode('hi') . '"', $encoded);
    }

    public function test_record_with_binary_payload_signs_and_round_trips_to_storage(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'chain-with-binary', $signer);

        $signed = $chain->record('app.event', ['blob' => Binary::ofRaw("\x00\x01\x02hello")]);

        self::assertSame(
            ['blob' => ['_attest_binary' => base64_encode("\x00\x01\x02hello")]],
            $signed->envelope->payload,
        );

        // Round-trip through canonical bytes
        $reread = EnvelopeCodec::decodeSigned($signed->signedCanonicalBytes());
        self::assertSame($signed->signedCanonicalBytes(), $reread->signedCanonicalBytes());
        self::assertSame(
            ['blob' => ['_attest_binary' => base64_encode("\x00\x01\x02hello")]],
            $reread->envelope->payload,
        );
    }

    public function test_binary_oversize_still_fails_at_validation(): void
    {
        $this->expectException(\Fissible\Attest\Envelope\InvalidPayload::class);
        PayloadValidator::ensure(['blob' => Binary::ofRaw(str_repeat('x', Binary::MAX_BYTES + 1))]);
    }
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
vendor/bin/phpunit --filter BinaryRoundTripTest
```

Expected: `test_payload_validator_canonicalizes_binary_to_array_stand_in` and the round-trip test fail because `PayloadValidator::ensure()` returns the input unchanged.

- [ ] **Step 3: Update `PayloadValidator::ensure()` to return the canonical payload**

In `src/Envelope/PayloadValidator.php`, change the return value of `ensure()` from `$payload` to `self::toCanonical($payload)`. Make `toCanonical()` return an array for array inputs and ensure the top-level return type stays `array`.

Replace the body of `ensure()` with:

```php
public static function ensure(array $payload): array
{
    self::walk($payload, '');
    /** @var array<array-key, mixed> $canonical */
    $canonical = self::toCanonical($payload);
    $bytes = JcsEncoder::encode($canonical);
    if (strlen($bytes) > self::MAX_CANONICAL_BYTES) {
        throw new InvalidPayload(
            'Canonical payload exceeds ' . self::MAX_CANONICAL_BYTES . ' bytes (got ' . strlen($bytes) . ')'
        );
    }
    return $canonical;
}
```

Confirm `toCanonical()` already produces `['_attest_binary' => $base64]` for `Binary` instances (it does in current code at line 96-98).

- [ ] **Step 4: Update `EvidenceChain::record()` to use the canonical payload**

In `src/Chain/EvidenceChain.php`, replace the line `PayloadValidator::ensure($payload);` with:

```php
$canonicalPayload = PayloadValidator::ensure($payload);
```

Then inside the `append` callback, pass `$canonicalPayload` to `EvidenceEnvelope::__construct()`'s `payload:` argument instead of `$payload`. Update the `use` clause of the closure to capture `$canonicalPayload` instead of `$payload`.

The closure becomes:

```php
return $this->store->append($this->chainId, function (AppendContext $ctx) use (
    $type, $canonicalPayload, $subject, $correlation, $tenant
) {
    $env = new EvidenceEnvelope(
        id: (string) Ulid::generate(),
        chain: $ctx->chainId,
        seq: $ctx->sequence,
        ts: $ctx->timestampIso8601,
        type: $type,
        payload: $canonicalPayload,
        prevHash: $ctx->prevHash,
        keyId: $this->signer->keyId(),
        sigAlg: 'ed25519',
        subject: $subject,
        correlation: $correlation,
        tenant: $tenant,
    );
    return SignedEnvelope::sign($env, $this->signer);
});
```

- [ ] **Step 5: Run the new test and verify it passes**

```
vendor/bin/phpunit --filter BinaryRoundTripTest
```

Expected: all four tests pass.

- [ ] **Step 6: Run the full suite to confirm no regressions**

```
vendor/bin/phpunit
```

Expected: all 200+ existing tests still pass. If `PayloadValidatorTest` has an assertion that `ensure()` returns the original payload identity, update it to expect the canonical form (`Binary` becomes array stand-in; non-Binary payloads round-trip identically).

- [ ] **Step 7: Commit**

```
git add src/Envelope/PayloadValidator.php src/Chain/EvidenceChain.php tests/Envelope/BinaryRoundTripTest.php tests/Envelope/PayloadValidatorTest.php
git commit -m "fix(envelope): Binary payloads round-trip through JCS via canonical stand-in"
```

---

## Task 2.5.2: Full signed-envelope 64KB cap

**Why:** Spec §5.3 says "total canonical envelope size ≤ 64KB." Implementation caps canonical *payload* size only. Envelope overhead (timestamps, key_id, sig, prev_hash) routinely adds 400-600 bytes; payloads passing the validator can still produce envelopes well over the spec limit. The cap belongs at sign-time and decode-time so storage and verification reject oversize envelopes regardless of how they were produced.

**Files:**
- Modify: `src/Envelope/SignedEnvelope.php`
- Modify: `src/Envelope/EnvelopeCodec.php`
- Modify: `src/Envelope/PayloadValidator.php` (lower the payload cap to leave envelope overhead room)
- Create: `tests/Envelope/SignedEnvelopeSizeCapTest.php`

- [ ] **Step 1: Write the failing tests**

Create `tests/Envelope/SignedEnvelopeSizeCapTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\InvalidPayload;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class SignedEnvelopeSizeCapTest extends TestCase
{
    public function test_sign_rejects_envelope_over_full_cap(): void
    {
        // Build a payload that, when wrapped in envelope overhead and signed,
        // exceeds MAX_SIGNED_ENVELOPE_BYTES.
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');

        // 64512 chars + envelope frame > 65536 by construction.
        $payload = ['data' => str_repeat('a', SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES - 1024)];

        $env = new EvidenceEnvelope(
            id: '01H00000000000000000000000',
            chain: 'c',
            seq: 1,
            ts: '2026-06-05T00:00:00.000Z',
            type: 't',
            payload: $payload,
            prevHash: null,
            keyId: 'k1',
            sigAlg: 'ed25519',
        );

        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessageMatches('/signed canonical envelope exceeds/i');
        SignedEnvelope::sign($env, $signer);
    }

    public function test_sign_accepts_envelope_at_or_under_cap(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');

        // Small payload — should pass.
        $env = new EvidenceEnvelope(
            id: '01H00000000000000000000001',
            chain: 'c',
            seq: 1,
            ts: '2026-06-05T00:00:00.000Z',
            type: 't',
            payload: ['k' => 'v'],
            prevHash: null,
            keyId: 'k1',
            sigAlg: 'ed25519',
        );

        $signed = SignedEnvelope::sign($env, $signer);
        self::assertLessThanOrEqual(SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES, strlen($signed->signedCanonicalBytes()));
    }

    public function test_decode_rejects_signed_canonical_bytes_over_cap(): void
    {
        $oversized = '{' . str_repeat('"x":"' . str_repeat('a', 100) . '",', 1000) . '"end":1}';
        self::assertGreaterThan(SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES, strlen($oversized));

        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessageMatches('/signed canonical envelope exceeds/i');
        EnvelopeCodec::decodeSigned($oversized);
    }
}
```

- [ ] **Step 2: Run tests and verify they fail**

```
vendor/bin/phpunit --filter SignedEnvelopeSizeCapTest
```

Expected: `MAX_SIGNED_ENVELOPE_BYTES` is undefined; all three tests fail at parse time or with missing-constant error.

- [ ] **Step 3: Add the cap constant and enforcement to `SignedEnvelope::sign()`**

In `src/Envelope/SignedEnvelope.php`, add:

```php
public const MAX_SIGNED_ENVELOPE_BYTES = 65536;
```

Replace the body of `sign()` with:

```php
public static function sign(EvidenceEnvelope $envelope, Signer $signer): self
{
    if ($envelope->keyId !== $signer->keyId()) {
        throw new \LogicException(
            "Envelope key_id '{$envelope->keyId}' does not match signer key_id '{$signer->keyId()}'"
        );
    }
    $unsignedBytes = JcsEncoder::encode($envelope->toUnsignedArray());
    $sig = $signer->sign($unsignedBytes);
    $candidate = new self($envelope, $sig);
    $signedBytes = $candidate->signedCanonicalBytes();
    if (strlen($signedBytes) > self::MAX_SIGNED_ENVELOPE_BYTES) {
        throw new \Fissible\Attest\Envelope\InvalidPayload(
            'Signed canonical envelope exceeds ' . self::MAX_SIGNED_ENVELOPE_BYTES
            . ' bytes (got ' . strlen($signedBytes) . ')'
        );
    }
    return $candidate;
}
```

- [ ] **Step 4: Add the cap to `EnvelopeCodec::decodeSigned()`**

In `src/Envelope/EnvelopeCodec.php`, at the top of `decodeSigned()` before any JSON parsing:

```php
public static function decodeSigned(string $bytes): SignedEnvelope
{
    if (strlen($bytes) > SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES) {
        throw new InvalidPayload(
            'Signed canonical envelope exceeds ' . SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES
            . ' bytes (got ' . strlen($bytes) . ')'
        );
    }
    // ... rest of existing decode logic
}
```

Add `use Fissible\Attest\Envelope\SignedEnvelope;` and `use Fissible\Attest\Envelope\InvalidPayload;` at the top if not already present.

- [ ] **Step 5: Lower the payload-side cap to leave envelope overhead headroom**

In `src/Envelope/PayloadValidator.php`, change:

```php
public const MAX_CANONICAL_BYTES = 65536;
```

to:

```php
public const MAX_CANONICAL_BYTES = 61440;  // 60KB; leaves 4KB for envelope overhead under the 64KB signed cap
```

Update the docblock at the top of the class to reflect that the canonical *envelope* cap (enforced at sign-time) is 64KB and the payload-only cap is a sanity ceiling that leaves room for envelope frame.

- [ ] **Step 6: Run tests and verify they pass**

```
vendor/bin/phpunit --filter SignedEnvelopeSizeCapTest
vendor/bin/phpunit
```

Expected: new tests pass, existing 201+ tests still pass.

If a `PayloadValidator` test was previously asserting exactly 65536 as the payload cap, update it to 61440 with a comment referencing this task.

- [ ] **Step 7: Commit**

```
git add src/Envelope/SignedEnvelope.php src/Envelope/EnvelopeCodec.php src/Envelope/PayloadValidator.php tests/Envelope/SignedEnvelopeSizeCapTest.php tests/Envelope/PayloadValidatorTest.php
git commit -m "fix(envelope): enforce 64KB total signed-envelope cap at sign and decode"
```

---

## Task 2.5.3: Detached anchor envelope signature verification

**Why:** `Verifier::anchorEnvelopesFor()` collects post-range anchor envelopes (those at seq > `toSeq`) and passes them to `AnchorSetResolver` without any signature check. For full-chain verification this is latent (any tampered anchor envelope would also break chain integrity at its own seq when that range is verified). For Chunk 3 bundle verification, where `proof_envelopes/` are *detached* from chain continuity, signature validation is the only guarantee. Address it now in `Verifier` so the bundle work plugs in cleanly.

This task adds:
1. A `DetachedAnchorClassification` enum with four states (`TRUSTED`, `UNTRUSTED_VALID`, `INVALID`, `UNSUPPORTED_ALG`).
2. A `DetachedAnchorVerifier` class that runs each detached anchor envelope through `SignatureVerifier` and returns it with its classification.
3. `Verifier` wiring: detached envelopes classified before `AnchorSetResolver` sees them; invalid groups dropped with a warning; untrusted groups usable only when `requireTrustedKey=false`.

**Files:**
- Create: `src/Verification/DetachedAnchorClassification.php`
- Create: `src/Verification/DetachedAnchorVerifier.php`
- Modify: `src/Verification/Warning.php`
- Modify: `src/Verification/Verifier.php`
- Create: `tests/Verification/DetachedAnchorVerifierTest.php`
- Create: `tests/Verification/VerifierDetachedAnchorSigTest.php`

- [ ] **Step 1: Write the failing `DetachedAnchorVerifier` test**

Create `tests/Verification/DetachedAnchorVerifierTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\DetachedAnchorClassification;
use Fissible\Attest\Verification\DetachedAnchorVerifier;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use PHPUnit\Framework\TestCase;

final class DetachedAnchorVerifierTest extends TestCase
{
    public function test_trusted_signature_classifies_as_trusted(): void
    {
        [$signed, $kp] = $this->signedEnvelope(keyId: 'k1');
        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'k1')]),
        );

        $classified = $verifier->classify([$signed]);

        self::assertCount(1, $classified);
        self::assertSame(DetachedAnchorClassification::TRUSTED, $classified[0]->classification);
        self::assertSame($signed, $classified[0]->envelope);
    }

    public function test_valid_signature_but_no_trusted_key_classifies_as_untrusted_valid(): void
    {
        [$signed, $_] = $this->signedEnvelope(keyId: 'k1');
        // Different keypair in the trusted set.
        $other = KeyPair::generate();
        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($other->publicKey, keyId: 'k1')]),
        );

        $classified = $verifier->classify([$signed]);

        self::assertSame(DetachedAnchorClassification::UNTRUSTED_VALID, $classified[0]->classification);
    }

    public function test_tampered_payload_classifies_as_invalid(): void
    {
        [$signed, $kp] = $this->signedEnvelope(keyId: 'k1');
        // Forge a new envelope with the same signature but different payload.
        $tampered = new SignedEnvelope(
            envelope: new EvidenceEnvelope(
                id: $signed->envelope->id,
                chain: $signed->envelope->chain,
                seq: $signed->envelope->seq,
                ts: $signed->envelope->ts,
                type: $signed->envelope->type,
                payload: ['tampered' => true],
                prevHash: $signed->envelope->prevHash,
                keyId: $signed->envelope->keyId,
                sigAlg: $signed->envelope->sigAlg,
            ),
            sig: $signed->sig,
        );

        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'k1')]),
        );

        $classified = $verifier->classify([$tampered]);
        self::assertSame(DetachedAnchorClassification::INVALID, $classified[0]->classification);
    }

    public function test_unsupported_algorithm_classifies_as_unsupported_alg(): void
    {
        [$signed, $kp] = $this->signedEnvelope(keyId: 'k1', sigAlg: 'rsa-pss');
        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'k1')]),
        );

        $classified = $verifier->classify([$signed]);
        self::assertSame(DetachedAnchorClassification::UNSUPPORTED_ALG, $classified[0]->classification);
    }

    /** @return array{0: SignedEnvelope, 1: KeyPair} */
    private function signedEnvelope(string $keyId, string $sigAlg = 'ed25519'): array
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: $keyId);
        $env = new EvidenceEnvelope(
            id: '01H00000000000000000000000',
            chain: 'c',
            seq: 1,
            ts: '2026-06-05T00:00:00.000Z',
            type: 'attest.anchor.submitted',
            payload: ['anchor_id' => str_repeat('a', 64)],
            prevHash: null,
            keyId: $keyId,
            sigAlg: $sigAlg,
        );
        // For unsupported-alg tests we still sign with ed25519 to get a real-looking sig.
        $signedEnv = SignedEnvelope::sign(
            new EvidenceEnvelope(
                id: $env->id, chain: $env->chain, seq: $env->seq, ts: $env->ts,
                type: $env->type, payload: $env->payload, prevHash: $env->prevHash,
                keyId: $env->keyId, sigAlg: 'ed25519',
            ),
            $signer,
        );
        if ($sigAlg !== 'ed25519') {
            $signedEnv = new SignedEnvelope(
                envelope: new EvidenceEnvelope(
                    id: $env->id, chain: $env->chain, seq: $env->seq, ts: $env->ts,
                    type: $env->type, payload: $env->payload, prevHash: $env->prevHash,
                    keyId: $env->keyId, sigAlg: $sigAlg,
                ),
                sig: $signedEnv->sig,
            );
        }
        return [$signedEnv, $kp];
    }
}
```

- [ ] **Step 2: Run the test and verify it fails**

```
vendor/bin/phpunit --filter DetachedAnchorVerifierTest
```

Expected: PHP fatal errors because `DetachedAnchorVerifier` and `DetachedAnchorClassification` do not exist.

- [ ] **Step 3: Add the classification enum**

Create `src/Verification/DetachedAnchorClassification.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

enum DetachedAnchorClassification: string
{
    case TRUSTED = 'trusted';
    case UNTRUSTED_VALID = 'untrusted_valid';
    case INVALID = 'invalid';
    case UNSUPPORTED_ALG = 'unsupported_alg';
}
```

- [ ] **Step 4: Add the `DetachedAnchorVerifier`**

Create `src/Verification/DetachedAnchorVerifier.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Envelope\SignedEnvelope;

final class DetachedAnchorVerifier
{
    public function __construct(private readonly SignatureVerifier $signatures)
    {
    }

    /**
     * @param iterable<SignedEnvelope> $envelopes
     * @return list<ClassifiedDetachedAnchor>
     */
    public function classify(iterable $envelopes): array
    {
        $out = [];
        foreach ($envelopes as $signed) {
            $result = $this->signatures->verify($signed);
            $classification = match (true) {
                $result->unsupportedAlgorithm => DetachedAnchorClassification::UNSUPPORTED_ALG,
                $result->invalid              => DetachedAnchorClassification::INVALID,
                $result->hasTrustedMatch()    => DetachedAnchorClassification::TRUSTED,
                default                        => DetachedAnchorClassification::UNTRUSTED_VALID,
            };
            $out[] = new ClassifiedDetachedAnchor($signed, $classification, $result);
        }
        return $out;
    }
}
```

Also create `src/Verification/ClassifiedDetachedAnchor.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Envelope\SignedEnvelope;

final readonly class ClassifiedDetachedAnchor
{
    public function __construct(
        public SignedEnvelope $envelope,
        public DetachedAnchorClassification $classification,
        public SignatureVerificationResult $signatureResult,
    ) {
    }
}
```

If `SignatureVerificationResult` does not expose `unsupportedAlgorithm` or `invalid` as public properties, check its current shape — `Verifier.php` already reads `$signatureResult->invalid` and `$signatureResult->hasTrustedMatch()`, and the `SignatureVerifier` factory methods are `unsupportedAlgorithm()`, `untrusted()`, `invalid()`, `trusted()`. Confirm the `$unsupportedAlgorithm` field exists or rename to whatever flag distinguishes the unsupported case. Adjust the match arms to whatever existing API exposes (e.g., `$result instanceof UnsupportedAlgorithmResult` or a `->kind` enum field).

- [ ] **Step 5: Run `DetachedAnchorVerifierTest` and verify it passes**

```
vendor/bin/phpunit --filter DetachedAnchorVerifierTest
```

Expected: all four classification tests pass.

- [ ] **Step 6: Add warning codes for the integration**

In `src/Verification/Warning.php`, add two new constants near the existing ones:

```php
public const DETACHED_ANCHOR_INVALID_SIGNATURE = 'detached_anchor_invalid_signature';
public const DETACHED_ANCHOR_UNTRUSTED = 'detached_anchor_untrusted';
```

- [ ] **Step 7: Write the failing Verifier integration test**

Create `tests/Verification/VerifierDetachedAnchorSigTest.php` with three scenarios:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use Fissible\Attest\Verification\Warning;
use PHPUnit\Framework\TestCase;

final class VerifierDetachedAnchorSigTest extends TestCase
{
    /**
     * Detached anchor envelope signed by an untrusted key + chain in range
     * signed by trusted key: verifier yields ANCHOR_BELOW_MIN (because the
     * detached anchor cannot be used to satisfy min-anchor under
     * requireTrustedKey=true), and the result carries
     * Warning::DETACHED_ANCHOR_UNTRUSTED.
     */
    public function test_untrusted_detached_anchor_is_rejected_for_min_anchor_satisfaction(): void
    {
        // Detailed scenario setup: build a chain with seqs 1-5 signed by
        // trustedKp; append an anchor envelope at seq 6 signed by untrustedKp
        // whose payload claims to anchor [1,5]. Verify [1,5] with
        // minAnchorOutcome = LOCAL_ONLY and only trustedKp trusted.
        //
        // Expected outcome: ANCHOR_BELOW_MIN, warning DETACHED_ANCHOR_UNTRUSTED.
        self::markTestIncomplete('Implemented in step 9 below.');
    }

    public function test_invalid_detached_anchor_signature_drops_group_with_warning(): void
    {
        self::markTestIncomplete('Implemented in step 9 below.');
    }

    public function test_trusted_detached_anchor_satisfies_min_anchor(): void
    {
        self::markTestIncomplete('Implemented in step 9 below.');
    }
}
```

- [ ] **Step 8: Wire the verifier**

In `src/Verification/Verifier.php`:

a. Add a private `DetachedAnchorVerifier $detachedAnchorVerifier` field, lazily constructed in the constructor: `$this->detachedAnchorVerifier = new DetachedAnchorVerifier($signatures);`.

b. Modify `anchorEnvelopesFor()` to return a `list<ClassifiedDetachedAnchor>` instead of `list<SignedEnvelope>`. Existing in-range envelopes (already signature-verified in the main loop) are wrapped with `DetachedAnchorClassification::TRUSTED` or `UNTRUSTED_VALID` based on the matching `SignatureVerificationResult` from the loop. Post-range envelopes are classified by `$this->detachedAnchorVerifier->classify()`.

c. In `verifyAnchorPolicy()` and `verifyAnchorTiling()`, where the resolved anchor groups are walked, additionally check the classification of the *strongest receipt* for the group. Apply rules:
- If any envelope in the group is `INVALID` or `UNSUPPORTED_ALG`: skip the group entirely, append `Warning::DETACHED_ANCHOR_INVALID_SIGNATURE` once per group with the `anchor_id` in context.
- If all valid envelopes in the group are `UNTRUSTED_VALID` and policy `requireTrustedKey === true`: do not allow this group to satisfy `minAnchorOutcome`. Append `Warning::DETACHED_ANCHOR_UNTRUSTED` once per group. The group can still be used for "below-min" reporting (so the operator sees its presence) but cannot promote the result to `VERIFIED`.
- Otherwise (at least one `TRUSTED`, or all `UNTRUSTED_VALID` with `requireTrustedKey=false`): use the group as today.

Concretely: change `anchorEnvelopesFor()`'s return type and threading. The simplest in-place change is to introduce a helper that walks `$resolved` and filters by classification before the main `verifyAnchorPolicy()` / `verifyAnchorTiling()` paths execute.

```php
/**
 * @param list<ClassifiedDetachedAnchor> $classifiedEnvelopes
 * @return list<ResolvedAnchor>
 */
private function resolveTrustedAnchorGroups(array $classifiedEnvelopes, array &$warnings, VerificationPolicy $policy): array
{
    // Index classifications by envelope_id for downstream group filtering.
    $classByEnvelopeId = [];
    foreach ($classifiedEnvelopes as $classified) {
        $classByEnvelopeId[$classified->envelope->envelope->id] = $classified->classification;
    }

    $signedEnvelopes = array_map(
        static fn (ClassifiedDetachedAnchor $c): SignedEnvelope => $c->envelope,
        $classifiedEnvelopes,
    );

    $resolved = (new AnchorSetResolver())->resolve($signedEnvelopes);

    $filtered = [];
    foreach ($resolved as $group) {
        $classifications = [];
        foreach ($group->envelopeIds as $envId) {
            $classifications[] = $classByEnvelopeId[$envId] ?? DetachedAnchorClassification::INVALID;
        }
        $hasInvalid = in_array(DetachedAnchorClassification::INVALID, $classifications, true)
            || in_array(DetachedAnchorClassification::UNSUPPORTED_ALG, $classifications, true);
        if ($hasInvalid) {
            $warnings[] = new Warning(
                Warning::DETACHED_ANCHOR_INVALID_SIGNATURE,
                'Anchor group dropped because at least one envelope failed signature verification.',
                ['anchor_id' => $group->anchorId],
            );
            continue;
        }
        $allUntrusted = array_reduce(
            $classifications,
            static fn (bool $acc, DetachedAnchorClassification $c): bool
                => $acc && $c === DetachedAnchorClassification::UNTRUSTED_VALID,
            true,
        );
        if ($allUntrusted && $policy->requireTrustedKey) {
            $warnings[] = new Warning(
                Warning::DETACHED_ANCHOR_UNTRUSTED,
                'Anchor group cannot satisfy minAnchorOutcome because no envelope matched a trusted key.',
                ['anchor_id' => $group->anchorId],
            );
            continue;
        }
        $filtered[] = $group;
    }

    return $filtered;
}
```

Replace the call to `(new AnchorSetResolver())->resolve(...)` inside `verifyAnchorPolicy()` and `verifyAnchorTiling()` with this filtered resolver. The `anchorEnvelopesFor()` method changes to return `list<ClassifiedDetachedAnchor>`:

```php
/**
 * @param list<SignatureVerificationResult> $rangeSignatureResults
 * @param list<SignedEnvelope> $rangeEnvelopes
 * @return list<ClassifiedDetachedAnchor>
 */
private function anchorEnvelopesFor(
    string $chainId,
    int $toSeq,
    array $rangeEnvelopes,
    array $rangeSignatureResults,
): array {
    $out = [];
    // In-range anchor envelopes were already signature-checked by the main loop.
    // Reuse those classifications.
    foreach ($rangeEnvelopes as $i => $signed) {
        if (! str_starts_with($signed->envelope->type, 'attest.anchor.')) {
            continue;
        }
        $result = $rangeSignatureResults[$i] ?? null;
        $classification = match (true) {
            $result === null                                => DetachedAnchorClassification::INVALID,
            $result->unsupportedAlgorithm ?? false           => DetachedAnchorClassification::UNSUPPORTED_ALG,
            $result->invalid                                 => DetachedAnchorClassification::INVALID,
            $result->hasTrustedMatch()                       => DetachedAnchorClassification::TRUSTED,
            default                                          => DetachedAnchorClassification::UNTRUSTED_VALID,
        };
        $out[] = new ClassifiedDetachedAnchor($signed, $classification, $result);
    }
    // Post-range anchor envelopes — classify now.
    $postRange = [];
    foreach ($this->store->readRange($chainId, $toSeq + 1) as $signed) {
        if (str_starts_with($signed->envelope->type, 'attest.anchor.')) {
            $postRange[] = $signed;
        }
    }
    $out = [...$out, ...$this->detachedAnchorVerifier->classify($postRange)];
    return $out;
}
```

Update the call site in `verifyChain()` to pass `$signatureResults` to `anchorEnvelopesFor()`.

- [ ] **Step 9: Flesh out the integration tests**

In `tests/Verification/VerifierDetachedAnchorSigTest.php`, replace the `markTestIncomplete()` calls with real scenarios. Helper for setup (chain with N envelopes plus a post-range anchor envelope signed by an arbitrary keypair):

```php
private function buildChainWithDetachedAnchor(
    string $tmpDir,
    KeyPair $chainSignerKp,
    string $chainSignerKeyId,
    KeyPair $anchorSignerKp,
    string $anchorSignerKeyId,
    string $chainId = 'test-chain',
    int $chainLen = 3,
): void {
    $store = new FileChainStore($tmpDir);
    $signer = new SodiumSigner($chainSignerKp, keyId: $chainSignerKeyId);
    $chain = EvidenceChain::open($store, $chainId, $signer);
    for ($i = 1; $i <= $chainLen; $i++) {
        $chain->record('app.event', ['n' => $i]);
    }
    // Append a detached anchor envelope using a different signer.
    $anchorSigner = new SodiumSigner($anchorSignerKp, keyId: $anchorSignerKeyId);
    $anchorChain = EvidenceChain::open($store, $chainId, $anchorSigner);
    $anchorChain->record('attest.anchor.submitted', [
        'anchor_id' => bin2hex(random_bytes(32)),
        'target_chain' => $chainId,
        'from_seq' => 1,
        'to_seq' => $chainLen,
        'merkle_algorithm' => 'sha256-rfc6962',
        'root' => bin2hex(random_bytes(32)),
        'driver' => 'opentimestamps',
        'state' => 'pending',
        'receipt_bytes' => 'base64:',
        'anchored_at' => gmdate('c'),
    ]);
}
```

Wire each test to the appropriate trust set and policy. Each test asserts (a) outcome and (b) the presence of the expected `Warning` code in `$result->warnings`.

- [ ] **Step 10: Run the full suite**

```
vendor/bin/phpunit
```

Expected: all existing tests still pass, three new `VerifierDetachedAnchorSigTest` cases pass, `DetachedAnchorVerifierTest` passes.

- [ ] **Step 11: Commit**

```
git add src/Verification/DetachedAnchorClassification.php src/Verification/DetachedAnchorVerifier.php src/Verification/ClassifiedDetachedAnchor.php src/Verification/Warning.php src/Verification/Verifier.php tests/Verification/DetachedAnchorVerifierTest.php tests/Verification/VerifierDetachedAnchorSigTest.php
git commit -m "feat(verification): classify detached anchor envelopes by signature trust"
```

---

## Task 2.5.4: Update docs and tag

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `VERSION`

- [ ] **Step 1: Add a `0.3.0-alpha` section to `CHANGELOG.md`**

Insert under `## [Unreleased]`:

```markdown
## [0.3.0-alpha] — 2026-MM-DD

### Fixed
- `Binary` payloads now round-trip through JCS via canonical `_attest_binary` stand-in arrays — `PayloadValidator::ensure()` returns the canonical form and `EvidenceChain::record()` stores it.
- Spec §5.3 cap now enforced on total signed canonical envelope size (64KB) at `SignedEnvelope::sign()` and `EnvelopeCodec::decodeSigned()`. Payload-only cap lowered to 60KB to leave envelope-frame room.
- Detached (post-range) anchor envelopes are signature-verified by `Verifier` before contributing to `--min-anchor` satisfaction. Invalid signatures drop the group with a `DETACHED_ANCHOR_INVALID_SIGNATURE` warning; valid-but-untrusted signatures cannot satisfy `minAnchorOutcome` under `requireTrustedKey=true` and add `DETACHED_ANCHOR_UNTRUSTED`.

### Added
- `Fissible\Attest\Verification\DetachedAnchorClassification` enum.
- `Fissible\Attest\Verification\DetachedAnchorVerifier` — classifies envelopes by signature trust.
- `Fissible\Attest\Verification\ClassifiedDetachedAnchor` value object.
- `Warning::DETACHED_ANCHOR_INVALID_SIGNATURE`, `Warning::DETACHED_ANCHOR_UNTRUSTED`.
- `SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES = 65536`.
```

- [ ] **Step 2: Add a short "Binary payloads" section to `README.md`**

Under the Verifier Example, add:

```markdown
## Payload Types

Beyond JSON-native types, payloads may carry opaque binary blobs via `Fissible\Attest\Envelope\Binary`:

```php
use Fissible\Attest\Envelope\Binary;

$chain->record('cms.attachment.added', [
    'name' => 'spec.pdf',
    'sha256' => 'abc...',
    'blob' => Binary::ofRaw(file_get_contents('/tmp/spec.pdf')),
]);
```

Binary blobs are stored in canonical form as `{"_attest_binary": "<base64>"}` and round-trip stably. Each blob is capped at 64KB raw; larger artifacts must be stored externally and referenced by URL + sha256.

The total signed canonical envelope size is capped at 64KB. Payloads approaching that size will be rejected at `record()` time.
```

- [ ] **Step 3: Update `VERSION`**

Replace contents with `0.3.0-alpha`.

- [ ] **Step 4: Commit**

```
git add CHANGELOG.md README.md VERSION
git commit -m "docs: changelog for v0.3.0-alpha"
```

- [ ] **Step 5: Run release script**

```
bash release.sh
```

Per fissible org standards: this tags `v0.3.0-alpha`, pushes, and lets the CI release workflow create the GitHub release.

---

## Done Criteria

- `vendor/bin/phpunit` passes locally (all existing tests + new ones).
- `vendor/bin/phpstan analyse --no-progress` clean.
- `Binary::ofRaw(...)` no longer fails when used in a `record()` call.
- Signing an envelope whose canonical form exceeds 64KB raises `InvalidPayload`.
- A chain whose detached anchor envelope has a forged signature does not satisfy `--min-anchor`, even with `requireTrustedKey=false` (because INVALID is non-recoverable; only `UNTRUSTED_VALID` is policy-controllable).
- Bundle work in Chunk 3 can rely on detached anchor signature verification being part of `Verifier`'s contract.
