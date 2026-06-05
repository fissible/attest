<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\InvalidAnchorEnvelope;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class AnchorEnvelopeTest extends TestCase
{
    private const ROOT = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function test_submitted_payload_round_trips_to_receipt(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: new AnchorTarget('tenant:5', 100, 149, MerkleTree::ALGORITHM, self::ROOT),
            state: ProofState::PENDING,
            receiptBytes: "raw\0ots",
            createdAtIso8601: '2026-05-25T14:30:00Z',
        );

        $payload = AnchorEnvelope::submittedPayload($receipt);
        $parsed = AnchorEnvelope::fromPayload($payload);

        $this->assertSame($receipt->anchorId, $parsed->anchorId);
        $this->assertSame($receipt->driverName, $parsed->driverName);
        $this->assertSame($receipt->receiptBytes, $parsed->receiptBytes);
        $this->assertSame(ProofState::PENDING, $parsed->state);
        $this->assertSame('2026-05-25T14:30:00Z', $parsed->createdAtIso8601);
    }

    public function test_upgraded_payload_round_trips_to_receipt(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: new AnchorTarget('tenant:5', 100, 149, MerkleTree::ALGORITHM, self::ROOT),
            state: ProofState::UPGRADED,
            receiptBytes: 'upgraded-ots',
            createdAtIso8601: '2026-05-26T03:15:00Z',
        );

        $payload = AnchorEnvelope::upgradedPayload($receipt, '01HX');
        $parsed = AnchorEnvelope::fromPayload($payload);

        $this->assertSame('01HX', $payload['supersedes_envelope_id']);
        $this->assertSame($receipt->anchorId, $parsed->anchorId);
        $this->assertSame(ProofState::UPGRADED, $parsed->state);
        $this->assertSame('2026-05-26T03:15:00Z', $parsed->createdAtIso8601);
    }

    public function test_mismatched_anchor_id_is_rejected(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: new AnchorTarget('tenant:5', 100, 149, MerkleTree::ALGORITHM, self::ROOT),
            state: ProofState::PENDING,
            receiptBytes: 'ots',
            createdAtIso8601: '2026-05-25T14:30:00Z',
        );
        $payload = AnchorEnvelope::submittedPayload($receipt);
        $payload['anchor_id'] = AnchorId::deriveFromParts('other', 100, 149, 'opentimestamps', self::ROOT);

        $this->expectException(InvalidAnchorEnvelope::class);
        $this->expectExceptionMessage('anchorId');

        AnchorEnvelope::fromPayload($payload);
    }

    public function test_missing_receipt_bytes_are_rejected(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: new AnchorTarget('tenant:5', 100, 149, MerkleTree::ALGORITHM, self::ROOT),
            state: ProofState::PENDING,
            receiptBytes: 'ots',
            createdAtIso8601: '2026-05-25T14:30:00Z',
        );
        $payload = AnchorEnvelope::submittedPayload($receipt);
        unset($payload['receipt_bytes']);

        $this->expectException(InvalidAnchorEnvelope::class);
        $this->expectExceptionMessage('receipt_bytes');

        AnchorEnvelope::fromPayload($payload);
    }

    public function test_verified_state_is_rejected(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: new AnchorTarget('tenant:5', 100, 149, MerkleTree::ALGORITHM, self::ROOT),
            state: ProofState::PENDING,
            receiptBytes: 'ots',
            createdAtIso8601: '2026-05-25T14:30:00Z',
        );
        $payload = AnchorEnvelope::submittedPayload($receipt);
        $payload['state'] = 'verified';

        $this->expectException(InvalidAnchorEnvelope::class);
        $this->expectExceptionMessage('state');

        AnchorEnvelope::fromPayload($payload);
    }

    public function test_parse_from_signed_anchor_envelope(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: new AnchorTarget('tenant:5', 100, 149, MerkleTree::ALGORITHM, self::ROOT),
            state: ProofState::PENDING,
            receiptBytes: 'ots',
            createdAtIso8601: '2026-05-25T14:30:00Z',
        );
        $signer = new SodiumSigner(KeyPair::generate(), 'k1');
        $env = new EvidenceEnvelope(
            id: '01H',
            chain: 'tenant:5',
            seq: 150,
            ts: '2026-05-25T14:31:00Z',
            type: AnchorEnvelope::SUBMITTED_TYPE,
            payload: AnchorEnvelope::submittedPayload($receipt),
            prevHash: null,
            keyId: 'k1',
            sigAlg: 'ed25519',
        );

        $parsed = AnchorEnvelope::fromSignedEnvelope(SignedEnvelope::sign($env, $signer));

        $this->assertSame($receipt->anchorId, $parsed->anchorId);
    }
}

