<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

final readonly class VerificationResult
{
    /**
     * @param list<Warning> $warnings
     * @param list<SignatureVerificationResult> $signatureResults
     */
    public function __construct(
        public VerificationOutcome $outcome,
        public ChainStats $stats,
        public array $warnings = [],
        public ?int $brokenAtSeq = null,
        public ?string $message = null,
        public array $signatureResults = [],
        public ?AnchorVerification $anchorVerification = null,
    ) {
    }

    public function isVerified(): bool
    {
        return $this->outcome === VerificationOutcome::VERIFIED;
    }
}
