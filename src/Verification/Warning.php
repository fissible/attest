<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

final readonly class Warning
{
    public const ANCHOR_OVER_RECOMPUTED_BYTES = 'anchor_over_recomputed_bytes';
    public const NO_RAW_BYTES = 'no_raw_bytes';
    public const HEADER_PROVIDER_UNKNOWN = 'header_provider_unknown';
    public const PROVIDER_DISAGREEMENT_ALLOWED = 'provider_disagreement_allowed';
    public const ANCHOR_COVERAGE_GAP = 'anchor_coverage_gap';
    public const ANCHOR_COVERAGE_AMBIGUOUS = 'anchor_coverage_ambiguous';
    public const DETACHED_ANCHOR_INVALID_SIGNATURE = 'detached_anchor_invalid_signature';
    public const DETACHED_ANCHOR_UNTRUSTED = 'detached_anchor_untrusted';

    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public string $code,
        public string $message,
        public array $context = [],
    ) {
        if ($code === '') {
            throw new \InvalidArgumentException('warning code must not be empty');
        }
        if ($message === '') {
            throw new \InvalidArgumentException('warning message must not be empty');
        }
    }
}
