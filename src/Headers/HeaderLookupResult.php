<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

final readonly class HeaderLookupResult
{
    private function __construct(
        public string $providerName,
        public TrustLevel $trustLevel,
        public HeaderLookupStatus $status,
        public ?ActiveChainHeader $header = null,
        public ?string $diagnostic = null,
    ) {
        if ($providerName === '') {
            throw new \InvalidArgumentException('providerName must not be empty');
        }
        if ($status === HeaderLookupStatus::ACTIVE && $header === null) {
            throw new \InvalidArgumentException('ACTIVE header lookup result requires a header');
        }
        if ($status !== HeaderLookupStatus::ACTIVE && $header !== null) {
            throw new \InvalidArgumentException('non-ACTIVE header lookup result must not carry a header');
        }
    }

    public static function active(string $providerName, TrustLevel $trustLevel, ActiveChainHeader $header): self
    {
        return new self($providerName, $trustLevel, HeaderLookupStatus::ACTIVE, header: $header);
    }

    public static function notFoundOrBehind(string $providerName, TrustLevel $trustLevel, ?string $diagnostic = null): self
    {
        return new self(
            $providerName,
            $trustLevel,
            HeaderLookupStatus::NOT_FOUND_OR_BEHIND,
            diagnostic: self::sanitizeDiagnostic($diagnostic),
        );
    }

    public static function providerError(string $providerName, TrustLevel $trustLevel, string $diagnostic): self
    {
        return new self(
            $providerName,
            $trustLevel,
            HeaderLookupStatus::PROVIDER_ERROR,
            diagnostic: self::sanitizeDiagnostic($diagnostic),
        );
    }

    public function isActive(): bool
    {
        return $this->status === HeaderLookupStatus::ACTIVE;
    }

    private static function sanitizeDiagnostic(?string $diagnostic): ?string
    {
        if ($diagnostic === null) {
            return null;
        }

        $diagnostic = preg_replace(
            '/(https?:\/\/)([^:@\/\s]+):([^@\/\s]+)@/i',
            '$1***:***@',
            $diagnostic,
        ) ?? $diagnostic;
        $diagnostic = preg_replace('/\b(Basic|Bearer)\s+[A-Za-z0-9._~+\/=-]+/i', '$1 ***', $diagnostic)
            ?? $diagnostic;

        return $diagnostic;
    }
}

