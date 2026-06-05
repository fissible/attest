<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

final readonly class AnchorReceipt
{
    public string $anchorId;

    public function __construct(
        public string $driverName,
        public AnchorTarget $target,
        public ProofState $state,
        public string $receiptBytes,
        public string $createdAtIso8601,
        ?string $anchorId = null,
    ) {
        if ($driverName === '') {
            throw new \InvalidArgumentException('driverName must not be empty');
        }
        if ($createdAtIso8601 === '') {
            throw new \InvalidArgumentException('createdAtIso8601 must not be empty');
        }

        $derived = AnchorId::derive($target, $driverName);
        if ($anchorId !== null && $anchorId !== $derived) {
            throw new \InvalidArgumentException('anchorId does not match receipt target and driver');
        }
        $this->anchorId = $derived;
    }
}

