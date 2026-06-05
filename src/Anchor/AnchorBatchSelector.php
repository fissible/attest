<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Chain\ChainStore;

final readonly class AnchorBatchSelector
{
    public function __construct(public int $maxBatchSize = 500)
    {
        if ($maxBatchSize < 1) {
            throw new \InvalidArgumentException('maxBatchSize must be >= 1');
        }
    }

    /**
     * @return array{from_seq:int,to_seq:int}|null
     */
    public function select(ChainStore $store, string $chainId, int $fromSeq = 1, ?int $toSeq = null): ?array
    {
        if ($fromSeq < 1) {
            throw new \InvalidArgumentException('fromSeq must be >= 1');
        }

        $tail = $store->tail($chainId);
        if ($tail === null) {
            return null;
        }

        $selectedToSeq = min($tail->envelope->seq, $fromSeq + $this->maxBatchSize - 1);
        if ($toSeq !== null) {
            if ($toSeq < $fromSeq) {
                throw new \InvalidArgumentException('toSeq must be >= fromSeq');
            }
            $selectedToSeq = min($selectedToSeq, $toSeq);
        }

        if ($selectedToSeq < $fromSeq) {
            return null;
        }

        return ['from_seq' => $fromSeq, 'to_seq' => $selectedToSeq];
    }
}

