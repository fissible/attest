<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Merkle\MerkleTree;

/**
 * @experimental
 */
final readonly class AnchorTarget
{
    public function __construct(
        public string $chainId,
        public int $fromSeq,
        public int $toSeq,
        public string $merkleAlgorithm,
        public string $rootHex,
    ) {
        if ($chainId === '') {
            throw new \InvalidArgumentException('chainId must not be empty');
        }
        if ($fromSeq < 1) {
            throw new \InvalidArgumentException('fromSeq must be >= 1');
        }
        if ($toSeq < $fromSeq) {
            throw new \InvalidArgumentException('toSeq must be >= fromSeq');
        }
        if ($merkleAlgorithm !== MerkleTree::ALGORITHM) {
            throw new \InvalidArgumentException('Unsupported merkle algorithm: ' . $merkleAlgorithm);
        }
        if (! preg_match('/\A[0-9a-f]{64}\z/', $rootHex)) {
            throw new \InvalidArgumentException('rootHex must be a lower-case 64-character hex SHA-256 digest');
        }
    }
}

