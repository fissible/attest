<?php
declare(strict_types=1);

namespace Fissible\Attest\Merkle;

final readonly class InclusionProof
{
    /**
     * @param list<string> $path binary sibling hashes, leaf-to-root order
     */
    public function __construct(
        public int $leafIndex,
        public int $treeSize,
        public string $leafHash,
        public array $path,
    ) {
        if ($leafIndex < 0) {
            throw new \InvalidArgumentException('leafIndex must be >= 0');
        }
        if ($treeSize < 1) {
            throw new \InvalidArgumentException('treeSize must be >= 1');
        }
        if ($leafIndex >= $treeSize) {
            throw new \InvalidArgumentException('leafIndex must be less than treeSize');
        }
        self::assertBinarySha256($leafHash, 'leafHash');
        foreach ($path as $siblingHash) {
            self::assertBinarySha256($siblingHash, 'path entry');
        }
    }

    public function leafHashHex(): string
    {
        return bin2hex($this->leafHash);
    }

    /**
     * @return list<string>
     */
    public function pathHex(): array
    {
        return array_map(static fn (string $hash): string => bin2hex($hash), $this->path);
    }

    private static function assertBinarySha256(string $hash, string $label): void
    {
        if (strlen($hash) !== 32) {
            throw new \InvalidArgumentException("$label must be a 32-byte binary SHA-256 hash");
        }
    }
}

