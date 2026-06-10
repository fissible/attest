<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

/**
 * @experimental
 */
enum DetachedAnchorClassification: string
{
    case TRUSTED = 'trusted';
    case UNTRUSTED_VALID = 'untrusted_valid';
    case INVALID = 'invalid';
    case UNSUPPORTED_ALG = 'unsupported_alg';

    public static function fromSignatureResult(SignatureVerificationResult $result): self
    {
        if ($result->unsupportedAlgorithm) {
            return self::UNSUPPORTED_ALG;
        }
        if ($result->invalid) {
            return self::INVALID;
        }
        if ($result->hasTrustedMatch()) {
            return self::TRUSTED;
        }
        return self::UNTRUSTED_VALID;
    }
}
