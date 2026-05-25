<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

final readonly class AppendContext
{
    public function __construct(
        public string $chainId,
        public int $sequence,           // 1-indexed; first envelope is seq 1
        public ?string $prevHash,       // null for genesis envelope (seq 1)
        public string $timestampIso8601, // genesis: now; subsequent: max(now, tail.ts + 1ms)
    ) {
        if ($sequence < 1) {
            throw new \InvalidArgumentException('sequence must be >= 1');
        }
    }
}
