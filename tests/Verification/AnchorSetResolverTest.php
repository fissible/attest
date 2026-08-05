<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\AnchorSetResolver;
use PHPUnit\Framework\TestCase;

final class AnchorSetResolverTest extends TestCase
{
    private SodiumSigner $signer;

    protected function setUp(): void
    {
        $this->signer = new SodiumSigner(KeyPair::generate(), 'app-prod');
    }

    public function test_groups_anchor_envelopes_and_picks_strongest_state(): void
    {
        $target = $this->target();
        $pending = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: $target,
            state: ProofState::PENDING,
            receiptBytes: 'pending',
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );
        $upgraded = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: $target,
            state: ProofState::UPGRADED,
            receiptBytes: 'upgraded',
            createdAtIso8601: '2026-05-25T01:00:00.000Z',
        );

        $resolved = (new AnchorSetResolver())->resolve([
            $this->signedAnchor(1, AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($pending)),
            $this->signedAnchor(2, AnchorEnvelope::UPGRADED_TYPE, AnchorEnvelope::upgradedPayload($upgraded)),
        ]);

        $this->assertCount(1, $resolved);
        $this->assertTrue($resolved[0]->valid);
        $this->assertNotNull($resolved[0]->receipt);
        $this->assertSame(ProofState::UPGRADED, $resolved[0]->receipt->state);
        $this->assertCount(2, $resolved[0]->envelopeIds);
    }

    public function test_same_anchor_id_with_conflicting_binding_is_invalid(): void
    {
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: $this->target(),
            state: ProofState::PENDING,
            receiptBytes: 'pending',
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );
        $badPayload = AnchorEnvelope::submittedPayload($receipt);
        $badPayload['root'] = str_repeat('b', 64);

        $resolved = (new AnchorSetResolver())->resolve([
            $this->signedAnchor(1, AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt)),
            $this->signedAnchor(2, AnchorEnvelope::SUBMITTED_TYPE, $badPayload),
        ]);

        $this->assertCount(1, $resolved);
        $this->assertFalse($resolved[0]->valid);
        $this->assertSame($receipt->anchorId, $resolved[0]->anchorId);
        $this->assertStringContainsString('Invalid anchor envelope', (string) $resolved[0]->message);
    }

    private function target(): AnchorTarget
    {
        return new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: 2,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: str_repeat('a', 64),
        );
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function signedAnchor(int $seq, string $type, array $payload): SignedEnvelope
    {
        return SignedEnvelope::sign(
            new EvidenceEnvelope(
                id: '01HV4F0M5J0X7P1W9JQ9M3Y8Z' . $seq,
                chain: 'tenant:5',
                seq: $seq,
                ts: '2026-05-25T14:32:11.000Z',
                type: $type,
                payload: $payload,
                prevHash: null,
                keyId: $this->signer->keyId(),
                sigAlg: 'ed25519',
            ),
            $this->signer,
        );
    }
}
