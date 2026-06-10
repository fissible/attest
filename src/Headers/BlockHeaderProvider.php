<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

/**
 * @experimental
 */
interface BlockHeaderProvider
{
    public function name(): string;

    public function trustLevel(): TrustLevel;

    public function getActiveChainHeaderByHeight(int $height): HeaderLookupResult;
}

