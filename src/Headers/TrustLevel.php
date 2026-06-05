<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

enum TrustLevel: string
{
    case LOCAL = 'local';
    case REMOTE = 'remote';

    public function strength(): int
    {
        return match ($this) {
            self::REMOTE => 0,
            self::LOCAL => 1,
        };
    }
}

