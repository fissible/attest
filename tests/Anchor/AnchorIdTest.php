<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Canonical\JcsEncoder;
use Fissible\Attest\Merkle\MerkleTree;
use PHPUnit\Framework\TestCase;

final class AnchorIdTest extends TestCase
{
    private const ROOT = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    public function test_derives_sha256_over_canonical_tuple(): void
    {
        $target = new AnchorTarget('tenant:5', 1, 10, MerkleTree::ALGORITHM, self::ROOT);

        $expected = bin2hex(hash(
            'sha256',
            JcsEncoder::encode(['attest-anchor-v1', 'tenant:5', 1, 10, 'opentimestamps', self::ROOT]),
            binary: true,
        ));

        $this->assertSame($expected, AnchorId::derive($target, 'opentimestamps'));
    }

    public function test_delimiter_trick_chain_ids_do_not_collide(): void
    {
        $first = AnchorId::deriveFromParts('tenant:5|1', 2, 3, 'driver', self::ROOT);
        $second = AnchorId::deriveFromParts('tenant:5', 1, 2, '3|driver', self::ROOT);

        $this->assertNotSame($first, $second);
    }

    public function test_changing_any_tuple_component_changes_id(): void
    {
        $base = AnchorId::deriveFromParts('c', 1, 2, 'd', self::ROOT);

        $this->assertNotSame($base, AnchorId::deriveFromParts('C', 1, 2, 'd', self::ROOT));
        $this->assertNotSame($base, AnchorId::deriveFromParts('c', 2, 2, 'd', self::ROOT));
        $this->assertNotSame($base, AnchorId::deriveFromParts('c', 1, 3, 'd', self::ROOT));
        $this->assertNotSame($base, AnchorId::deriveFromParts('c', 1, 2, 'D', self::ROOT));
        $this->assertNotSame($base, AnchorId::deriveFromParts(
            'c',
            1,
            2,
            'd',
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ));
    }

    public function test_empty_driver_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('driver');

        AnchorId::deriveFromParts('c', 1, 1, '', self::ROOT);
    }

    public function test_invalid_range_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('toSeq');

        AnchorId::deriveFromParts('c', 2, 1, 'driver', self::ROOT);
    }

    public function test_invalid_root_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('rootHex');

        AnchorId::deriveFromParts('c', 1, 1, 'driver', strtoupper(self::ROOT));
    }
}
