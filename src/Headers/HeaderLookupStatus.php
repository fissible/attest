<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

enum HeaderLookupStatus: string
{
    case ACTIVE = 'active';
    case NOT_FOUND_OR_BEHIND = 'not_found_or_behind';
    case PROVIDER_ERROR = 'provider_error';
}

