<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Merkle\MerkleTree;
use PHPUnit\Framework\TestCase;

final class AnchorReceiptTest extends TestCase
{
    private const ROOT = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function test_anchor_target_rejects_invalid_ranges(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('fromSeq');

        new AnchorTarget('chain', 0, 1, MerkleTree::ALGORITHM, self::ROOT);
    }

    public function test_anchor_target_rejects_uppercase_root_hex(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('lower-case');

        new AnchorTarget('chain', 1, 1, MerkleTree::ALGORITHM, strtoupper(self::ROOT));
    }

    public function test_receipt_derives_anchor_id(): void
    {
        $target = new AnchorTarget('chain', 1, 5, MerkleTree::ALGORITHM, self::ROOT);
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: $target,
            state: ProofState::PENDING,
            receiptBytes: 'raw-ots-bytes',
            createdAtIso8601: '2026-05-25T00:00:00Z',
        );

        $this->assertSame(AnchorId::derive($target, 'opentimestamps'), $receipt->anchorId);
    }

    public function test_receipt_rejects_mismatched_anchor_id(): void
    {
        $target = new AnchorTarget('chain', 1, 5, MerkleTree::ALGORITHM, self::ROOT);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('anchorId');

        new AnchorReceipt(
            driverName: 'opentimestamps',
            target: $target,
            state: ProofState::PENDING,
            receiptBytes: 'raw-ots-bytes',
            createdAtIso8601: '2026-05-25T00:00:00Z',
            anchorId: str_repeat('0', 64),
        );
    }

    public function test_proof_state_strength_order(): void
    {
        $this->assertLessThan(ProofState::PENDING->strength(), ProofState::SUBMITTED->strength());
        $this->assertLessThan(ProofState::UPGRADED->strength(), ProofState::PENDING->strength());
    }

    public function test_anchor_outcome_threshold_order(): void
    {
        $this->assertTrue(AnchorOutcome::BITCOIN_VERIFIED->meets(AnchorOutcome::PENDING));
        $this->assertFalse(AnchorOutcome::PENDING->meets(AnchorOutcome::BITCOIN_VERIFIED));
        $this->assertFalse(AnchorOutcome::INVALID->isRanked());
    }
}

