<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

/**
 * @api
 */
enum VerificationOutcome: string
{
    case VERIFIED = 'verified';
    case INTEGRITY_VERIFIED_UNTRUSTED = 'integrity_verified_untrusted';
    case INVALID_CHAIN = 'invalid_chain';
    case INVALID_SIGNATURE = 'invalid_signature';
    case INVALID_ANCHOR = 'invalid_anchor';
    case PROVIDER_DISAGREEMENT = 'provider_disagreement';
    case ANCHOR_BELOW_MIN = 'anchor_below_min';
}
