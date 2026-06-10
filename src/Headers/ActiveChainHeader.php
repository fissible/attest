<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

/**
 * @experimental
 */
final readonly class ActiveChainHeader
{
    public function __construct(
        public string $blockHash,
        public int $height,
        public int $confirmations,
        public string $merkleRoot,
        public int $timeUnixSec,
    ) {
        if (! preg_match('/\A[0-9a-f]{64}\z/', $blockHash)) {
            throw new \InvalidArgumentException('blockHash must be a lower-case 64-character hex digest');
        }
        if ($height < 0) {
            throw new \InvalidArgumentException('height must be >= 0');
        }
        if ($confirmations < 1) {
            throw new \InvalidArgumentException('confirmations must be >= 1');
        }
        if (! preg_match('/\A[0-9a-f]{64}\z/', $merkleRoot)) {
            throw new \InvalidArgumentException('merkleRoot must be a lower-case 64-character hex digest');
        }
        if ($timeUnixSec < 0) {
            throw new \InvalidArgumentException('timeUnixSec must be >= 0');
        }
    }
}

