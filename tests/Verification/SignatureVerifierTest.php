<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\Fingerprint;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\KeyMatch;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use PHPUnit\Framework\TestCase;

final class SignatureVerifierTest extends TestCase
{
    public function test_valid_trusted_signature_matches_by_key_id(): void
    {
        $keyPair = KeyPair::generate();
        $signed = $this->signedEnvelope($keyPair, keyId: 'station-prod');

        $result = (new SignatureVerifier([
            new TrustedKey($keyPair->publicKey, keyId: 'station-prod'),
        ]))->verify($signed);

        $this->assertFalse($result->invalid);
        $this->assertTrue($result->hasTrustedMatch());
        $this->assertCount(1, $result->matches);
        $this->assertSame(KeyMatch::MATCHED_BY_KEY_ID, $result->matches[0]->matchedBy);
        $this->assertSame(Fingerprint::of($keyPair->publicKey), $result->matches[0]->key->fingerprint);
    }

    public function test_valid_trusted_signature_can_match_by_fingerprint_key_id(): void
    {
        $keyPair = KeyPair::generate();
        $fingerprint = Fingerprint::of($keyPair->publicKey);
        $signed = $this->signedEnvelope($keyPair, keyId: $fingerprint);

        $result = (new SignatureVerifier([
            new TrustedKey($keyPair->publicKey),
        ]))->verify($signed);

        $this->assertFalse($result->invalid);
        $this->assertTrue($result->hasTrustedMatch());
        $this->assertSame(KeyMatch::MATCHED_BY_FINGERPRINT, $result->matches[0]->matchedBy);
    }

    public function test_valid_but_untrusted_signature_yields_no_key_match_not_invalid(): void
    {
        $signed = $this->signedEnvelope(KeyPair::generate(), keyId: 'untrusted-key');

        $result = (new SignatureVerifier([
            new TrustedKey(KeyPair::generate()->publicKey, keyId: 'station-prod'),
        ]))->verify($signed);

        $this->assertFalse($result->invalid);
        $this->assertFalse($result->hasTrustedMatch());
        $this->assertSame([], $result->matches);
        $this->assertStringContainsString('No trusted key', (string) $result->reason);
    }

    public function test_tampered_payload_fails_signature_verification_when_key_is_known(): void
    {
        $keyPair = KeyPair::generate();
        $signed = $this->signedEnvelope($keyPair, keyId: 'station-prod');
        $tampered = new SignedEnvelope(
            new EvidenceEnvelope(
                id: $signed->envelope->id,
                chain: $signed->envelope->chain,
                seq: $signed->envelope->seq,
                ts: $signed->envelope->ts,
                type: $signed->envelope->type,
                payload: ['amount' => 43],
                prevHash: $signed->envelope->prevHash,
                keyId: $signed->envelope->keyId,
                sigAlg: $signed->envelope->sigAlg,
            ),
            $signed->sig,
        );

        $result = (new SignatureVerifier([
            new TrustedKey($keyPair->publicKey, keyId: 'station-prod'),
        ]))->verify($tampered);

        $this->assertTrue($result->invalid);
        $this->assertFalse($result->unsupportedAlgorithm);
        $this->assertFalse($result->hasTrustedMatch());
        $this->assertStringContainsString('did not verify', (string) $result->reason);
    }

    public function test_unknown_signature_algorithm_fails_explicitly(): void
    {
        $keyPair = KeyPair::generate();
        $signed = $this->signedEnvelope($keyPair, keyId: 'station-prod', sigAlg: 'ed448');

        $result = (new SignatureVerifier([
            new TrustedKey($keyPair->publicKey, keyId: 'station-prod'),
        ]))->verify($signed);

        $this->assertTrue($result->invalid);
        $this->assertTrue($result->unsupportedAlgorithm);
        $this->assertSame('Unsupported signature algorithm: ed448', $result->reason);
    }

    public function test_trusted_key_rejects_invalid_public_key(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TrustedKey('not a raw Ed25519 public key');
    }

    private function signedEnvelope(KeyPair $keyPair, string $keyId, string $sigAlg = 'ed25519'): SignedEnvelope
    {
        $envelope = new EvidenceEnvelope(
            id: '01HV4F0M5J0X7P1W9JQ9M3Y8ZC',
            chain: 'tenant:5',
            seq: 1,
            ts: '2026-05-25T14:32:11Z',
            type: 'billing.invoice.paid',
            payload: ['amount' => 42],
            prevHash: null,
            keyId: $keyId,
            sigAlg: $sigAlg,
        );

        return SignedEnvelope::sign($envelope, new SodiumSigner($keyPair, $keyId));
    }
}
