<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;

final readonly class ResolvedAnchor
{
    /**
     * @param list<string> $envelopeIds
     * @param list<AnchorReceipt> $receipts
     */
    private function __construct(
        public string $anchorId,
        public bool $valid,
        public ?AnchorReceipt $receipt,
        public array $envelopeIds,
        public array $receipts,
        public ?string $message = null,
    ) {
    }

    /**
     * @param list<string> $envelopeIds
     * @param list<AnchorReceipt> $receipts
     */
    public static function valid(string $anchorId, AnchorReceipt $receipt, array $envelopeIds, array $receipts): self
    {
        return new self($anchorId, true, $receipt, $envelopeIds, $receipts);
    }

    /**
     * @param list<string> $envelopeIds
     * @param list<AnchorReceipt> $receipts
     */
    public static function invalid(string $anchorId, string $message, array $envelopeIds, array $receipts = []): self
    {
        return new self($anchorId, false, null, $envelopeIds, $receipts, $message);
    }

    public function matchesTarget(AnchorTarget $target, ?string $driverName = null): bool
    {
        if (! $this->valid || $this->receipt === null) {
            return false;
        }

        return $this->receipt->target->chainId === $target->chainId
            && $this->receipt->target->fromSeq === $target->fromSeq
            && $this->receipt->target->toSeq === $target->toSeq
            && $this->receipt->target->merkleAlgorithm === $target->merkleAlgorithm
            && $this->receipt->target->rootHex === $target->rootHex
            && ($driverName === null || $this->receipt->driverName === $driverName);
    }

    public function matchesRange(AnchorTarget $target): bool
    {
        if (! $this->valid || $this->receipt === null) {
            return false;
        }

        return $this->receipt->target->chainId === $target->chainId
            && $this->receipt->target->fromSeq === $target->fromSeq
            && $this->receipt->target->toSeq === $target->toSeq
            && $this->receipt->target->merkleAlgorithm === $target->merkleAlgorithm;
    }
}
