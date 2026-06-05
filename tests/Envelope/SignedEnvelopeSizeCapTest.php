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

        // Envelope overhead (id, chain, seq, ts, type, key_id, sig_alg, sig, JSON syntax)
        // is ~280 bytes, so a payload string of MAX - 280 chars produces an envelope
        // exactly 1 byte over the 64KB cap.
        $payload = ['data' => str_repeat('a', SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES - 280)];

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
