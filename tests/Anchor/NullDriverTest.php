<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Merkle\MerkleTree;
use PHPUnit\Framework\TestCase;

final class NullDriverTest extends TestCase
{
    public function test_anchor_returns_local_only_submitted_receipt(): void
    {
        $target = new AnchorTarget('chain', 1, 1, MerkleTree::ALGORITHM, str_repeat('a', 64));
        $driver = new NullDriver();

        $receipt = $driver->anchor($target);

        $this->assertSame(NullDriver::NAME, $receipt->driverName);
        $this->assertSame(ProofState::SUBMITTED, $receipt->state);
        $this->assertSame('', $receipt->receiptBytes);
        $this->assertTrue($driver->supports($receipt));
        $this->assertSame($receipt, $driver->upgrade($receipt));
    }
}

