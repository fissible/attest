<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

use Fissible\Attest\Verification\Warning;

/**
 * @experimental
 */
final readonly class CalendarUpgradeAttempt
{
    /**
     * @param list<Warning> $warnings
     */
    public function __construct(
        public int $attempted,
        public int $unreachable,
        public array $warnings,
    ) {
    }

    public function allUnreachable(): bool
    {
        return $this->attempted > 0 && $this->unreachable === $this->attempted;
    }
}
