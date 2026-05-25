<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class EnvelopeCodecTest extends TestCase
{
    public function test_round_trip_decode_then_re_encode_is_byte_identical(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H1', chain: 'tenant:5', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 'cms.entry.published', payload: ['entry_id' => 42, 'actor' => 7],
            prevHash: null, keyId: 'k1', sigAlg: 'ed25519',
        );
        $signed = SignedEnvelope::sign($env, $signer);
        $originalBytes = $signed->signedCanonicalBytes();

        $decoded = EnvelopeCodec::decodeSigned($originalBytes);
        $this->assertSame($originalBytes, $decoded->signedCanonicalBytes());
    }

    public function test_round_trip_preserves_signature_verification(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H1', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: ['x' => 1], prevHash: null,
            keyId: 'k1', sigAlg: 'ed25519',
        );
        $signed = SignedEnvelope::sign($env, $signer);
        $bytes = $signed->signedCanonicalBytes();

        $decoded = EnvelopeCodec::decodeSigned($bytes);
        $unsignedBytes = $decoded->unsignedCanonicalBytes();

        $this->assertTrue(
            sodium_crypto_sign_verify_detached($decoded->sig, $unsignedBytes, $kp->publicKey)
        );
    }

    public function test_round_trip_preserves_optional_fields(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H1', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: [], prevHash: 'sha256:abc', keyId: 'k1', sigAlg: 'ed25519',
            subject: 'entry:42', correlation: 'req_abc', tenant: 'tenant:5',
        );
        $signed = SignedEnvelope::sign($env, $signer);
        $bytes = $signed->signedCanonicalBytes();

        $decoded = EnvelopeCodec::decodeSigned($bytes);
        $this->assertSame('entry:42', $decoded->envelope->subject);
        $this->assertSame('req_abc', $decoded->envelope->correlation);
        $this->assertSame('tenant:5', $decoded->envelope->tenant);
        $this->assertSame('sha256:abc', $decoded->envelope->prevHash);
    }

    public function test_decode_rejects_malformed_json(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EnvelopeCodec::decodeSigned('not-json');
    }

    public function test_decode_rejects_missing_required_field(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('missing field');
        EnvelopeCodec::decodeSigned('{"v":1}');
    }

    public function test_decode_rejects_non_object_root(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        EnvelopeCodec::decodeSigned('"a string"');
    }

    public function test_decode_rejects_sig_without_base64_prefix(): void
    {
        $bad = '{"v":1,"id":"x","chain":"c","seq":1,"ts":"t","type":"t","payload":[],"prev_hash":null,"key_id":"k","sig_alg":"ed25519","sig":"no-prefix"}';
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('base64');
        EnvelopeCodec::decodeSigned($bad);
    }
}
