<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

final class ChainLockUnavailable extends \RuntimeException
{
    public function __construct(string $chainId)
    {
        parent::__construct("Could not acquire append lock for chain: $chainId");
    }
}
