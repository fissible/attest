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
        $kp = KeyPair::generate();
        $signed = $this->signedEnvelope($kp, 'my-key');

        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'my-key')]),
        );

        $classified = $verifier->classify([$signed]);

        $this->assertCount(1, $classified);
        $this->assertSame(DetachedAnchorClassification::TRUSTED, $classified[0]->classification);
    }

    public function test_valid_signature_but_no_trusted_key_classifies_as_untrusted_valid(): void
    {
        $kp = KeyPair::generate();
        $otherKp = KeyPair::generate();
        $signed = $this->signedEnvelope($kp, 'unknown-key');

        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($otherKp->publicKey, keyId: 'other-key')]),
        );

        $classified = $verifier->classify([$signed]);

        $this->assertCount(1, $classified);
        $this->assertSame(DetachedAnchorClassification::UNTRUSTED_VALID, $classified[0]->classification);
    }

    public function test_tampered_payload_classifies_as_invalid(): void
    {
        $kp = KeyPair::generate();
        $signed = $this->signedEnvelope($kp, 'my-key');
        // Same sig, different payload — cryptographic verification will fail
        $tampered = new SignedEnvelope(
            new EvidenceEnvelope(
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
            $signed->sig,
        );

        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'my-key')]),
        );

        $classified = $verifier->classify([$tampered]);

        $this->assertCount(1, $classified);
        $this->assertSame(DetachedAnchorClassification::INVALID, $classified[0]->classification);
    }

    public function test_unsupported_algorithm_classifies_as_unsupported_alg(): void
    {
        $kp = KeyPair::generate();
        // Sign with ed25519 (only supported alg), then replace sig_alg with an unsupported value
        $realSigned = $this->signedEnvelope($kp, 'my-key');
        $unsupported = new SignedEnvelope(
            new EvidenceEnvelope(
                id: $realSigned->envelope->id,
                chain: $realSigned->envelope->chain,
                seq: $realSigned->envelope->seq,
                ts: $realSigned->envelope->ts,
                type: $realSigned->envelope->type,
                payload: $realSigned->envelope->payload,
                prevHash: $realSigned->envelope->prevHash,
                keyId: $realSigned->envelope->keyId,
                sigAlg: 'rsa-pss',
            ),
            $realSigned->sig,
        );

        $verifier = new DetachedAnchorVerifier(
            new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'my-key')]),
        );

        $classified = $verifier->classify([$unsupported]);

        $this->assertCount(1, $classified);
        $this->assertSame(DetachedAnchorClassification::UNSUPPORTED_ALG, $classified[0]->classification);
    }

    private function signedEnvelope(KeyPair $kp, string $keyId): SignedEnvelope
    {
        $envelope = new EvidenceEnvelope(
            id: '01HV4F0M5J0X7P1W9JQ9M3Y8ZC',
            chain: 'tenant:99',
            seq: 1,
            ts: '2026-06-05T10:00:00Z',
            type: 'attest.anchor.submitted',
            payload: ['anchor_id' => 'test-anchor'],
            prevHash: null,
            keyId: $keyId,
            sigAlg: 'ed25519',
        );

        return SignedEnvelope::sign($envelope, new SodiumSigner($kp, $keyId));
    }
}
