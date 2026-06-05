<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorReceipt;

final readonly class AnchorVerification
{
    /**
     * @param list<Warning> $warnings
     */
    public function __construct(
        public AnchorReceipt $receipt,
        public AnchorOutcome $outcome,
        public array $warnings = [],
        public ?string $message = null,
        public ?string $providerName = null,
        public ?AnchorOutcome $strongestPassingOutcome = null,
        /** @var array<string, mixed> */
        public array $context = [],
    ) {
    }

    public static function invalid(AnchorReceipt $receipt, string $message): self
    {
        return new self($receipt, AnchorOutcome::INVALID, message: $message);
    }

    /**
     * @param list<Warning> $warnings
     * @param array<string, mixed> $context
     */
    public static function providerDisagreement(
        AnchorReceipt $receipt,
        string $message,
        ?AnchorOutcome $strongestPassingOutcome,
        array $warnings = [],
        array $context = [],
    ): self {
        return new self(
            receipt: $receipt,
            outcome: AnchorOutcome::PROVIDER_DISAGREEMENT,
            warnings: $warnings,
            message: $message,
            strongestPassingOutcome: $strongestPassingOutcome,
            context: $context,
        );
    }
}
