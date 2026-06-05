<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Merkle;

use Fissible\Attest\Merkle\InclusionProof;
use Fissible\Attest\Merkle\MerkleTree;
use PHPUnit\Framework\TestCase;

final class MerkleTreeTest extends TestCase
{
    public function test_empty_tree_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('at least one leaf');

        MerkleTree::rootHex([]);
    }

    public function test_fixture_roots_are_stable(): void
    {
        $vectors = json_decode(
            (string) file_get_contents(__DIR__ . '/vectors/sha256-rfc6962.json'),
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        $this->assertIsArray($vectors);
        $this->assertSame(MerkleTree::ALGORITHM, $vectors['algorithm']);
        $this->assertSame('leaf-{i}', $vectors['leaf_template']);
        $this->assertIsArray($vectors['roots']);

        foreach ($vectors['roots'] as $count => $expectedRoot) {
            $leaves = [];
            for ($i = 0; $i < (int) $count; $i++) {
                $leaves[] = 'leaf-' . $i;
            }
            $this->assertSame($expectedRoot, MerkleTree::rootHex($leaves), 'count ' . $count);
        }
    }

    public function test_mutating_input_changes_root(): void
    {
        $original = MerkleTree::rootHex(['a', 'b', 'c']);
        $mutated = MerkleTree::rootHex(['a', 'B', 'c']);

        $this->assertNotSame($original, $mutated);
    }

    public function test_odd_leaf_is_promoted_not_duplicated(): void
    {
        $a = MerkleTree::leafHash('a');
        $b = MerkleTree::leafHash('b');
        $c = MerkleTree::leafHash('c');

        $promoted = bin2hex(MerkleTree::nodeHash(MerkleTree::nodeHash($a, $b), $c));
        $duplicated = bin2hex(MerkleTree::nodeHash(MerkleTree::nodeHash($a, $b), MerkleTree::nodeHash($c, $c)));

        $this->assertSame($promoted, MerkleTree::rootHex(['a', 'b', 'c']));
        $this->assertNotSame($duplicated, MerkleTree::rootHex(['a', 'b', 'c']));
    }

    public function test_inclusion_proof_validates_hash_lengths(): void
    {
        $proof = new InclusionProof(
            leafIndex: 0,
            treeSize: 1,
            leafHash: str_repeat("\x00", 32),
            path: [],
        );

        $this->assertSame(str_repeat('00', 32), $proof->leafHashHex());
    }
}

