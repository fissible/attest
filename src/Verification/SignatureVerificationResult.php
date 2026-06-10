<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

/**
 * @api
 */
final readonly class SignatureVerificationResult
{
    /**
     * @param list<KeyMatch> $matches
     */
    private function __construct(
        public bool $invalid,
        public bool $unsupportedAlgorithm,
        public ?string $reason,
        public array $matches,
    ) {
    }

    /**
     * @param list<KeyMatch> $matches
     */
    public static function trusted(array $matches): self
    {
        if ($matches === []) {
            throw new \InvalidArgumentException('Trusted signature result requires at least one key match');
        }

        return new self(
            invalid: false,
            unsupportedAlgorithm: false,
            reason: null,
            matches: $matches,
        );
    }

    public static function untrusted(string $reason): self
    {
        return new self(
            invalid: false,
            unsupportedAlgorithm: false,
            reason: $reason,
            matches: [],
        );
    }

    public static function invalid(string $reason): self
    {
        return new self(
            invalid: true,
            unsupportedAlgorithm: false,
            reason: $reason,
            matches: [],
        );
    }

    public static function unsupportedAlgorithm(string $sigAlg): self
    {
        return new self(
            invalid: true,
            unsupportedAlgorithm: true,
            reason: "Unsupported signature algorithm: $sigAlg",
            matches: [],
        );
    }

    public function hasTrustedMatch(): bool
    {
        return $this->matches !== [];
    }
}
