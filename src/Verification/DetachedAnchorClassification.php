<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

enum DetachedAnchorClassification: string
{
    case TRUSTED = 'trusted';
    case UNTRUSTED_VALID = 'untrusted_valid';
    case INVALID = 'invalid';
    case UNSUPPORTED_ALG = 'unsupported_alg';
}
