<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorOutcome;

final readonly class VerificationPolicy
{
    public function __construct(
        public ?AnchorOutcome $minAnchorOutcome = null,
        public bool $allowProviderDisagreement = false,
        public bool $requireTrustedKey = true,
    ) {
    }
}
