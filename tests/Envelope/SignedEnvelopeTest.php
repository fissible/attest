<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SignatureVerification;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class SignedEnvelopeTest extends TestCase
{
    public function test_signing_produces_envelope_with_sig_field(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: ['x' => 1], prevHash: null,
            keyId: 'k1', sigAlg: 'ed25519',
        );

        $signed = SignedEnvelope::sign($env, $signer);

        $this->assertNotEmpty($signed->sig);
        $this->assertSame(SODIUM_CRYPTO_SIGN_BYTES, strlen($signed->sig));
        $this->assertSame($env, $signed->envelope);
    }

    public function test_signed_canonical_bytes_includes_sig(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: ['x' => 1], prevHash: null,
            keyId: 'k1', sigAlg: 'ed25519',
        );
        $signed = SignedEnvelope::sign($env, $signer);

        $this->assertStringContainsString('"sig":', $signed->signedCanonicalBytes());
    }

    public function test_unsigned_canonical_bytes_does_not_include_sig(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: [], prevHash: null,
            keyId: 'k1', sigAlg: 'ed25519',
        );
        $signed = SignedEnvelope::sign($env, $signer);

        $this->assertStringNotContainsString('"sig":', $signed->unsignedCanonicalBytes());
    }

    public function test_self_hash_is_sha256_of_signed_canonical_bytes(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: ['x' => 1], prevHash: null,
            keyId: 'k1', sigAlg: 'ed25519',
        );
        $signed = SignedEnvelope::sign($env, $signer);

        $expected = bin2hex(hash('sha256', $signed->signedCanonicalBytes(), binary: true));
        $this->assertSame($expected, $signed->selfHash());
    }

    public function test_sig_verifies_against_unsigned_canonical_bytes(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: ['x' => 1], prevHash: null,
            keyId: 'k1', sigAlg: 'ed25519',
        );
        $signed = SignedEnvelope::sign($env, $signer);

        $this->assertTrue(SignatureVerification::verify(
            $signed->unsignedCanonicalBytes(),
            $signed->sig,
            $kp->publicKey,
        ));
    }

    public function test_keyid_mismatch_between_envelope_and_signer_throws(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, 'k1');
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: [], prevHash: null,
            keyId: 'mismatched-key', sigAlg: 'ed25519',
        );

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('key_id');
        SignedEnvelope::sign($env, $signer);
    }
}
