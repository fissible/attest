<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

enum ProofState: string
{
    case SUBMITTED = 'submitted';
    case PENDING = 'pending';
    case UPGRADED = 'upgraded';

    public function strength(): int
    {
        return match ($this) {
            self::SUBMITTED => 0,
            self::PENDING => 1,
            self::UPGRADED => 2,
        };
    }
}

