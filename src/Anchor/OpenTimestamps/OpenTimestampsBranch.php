<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

/**
 * @experimental
 */
final readonly class OpenTimestampsBranch
{
    public function __construct(
        public OpenTimestampsOperation $operation,
        public OpenTimestampsTimestamp $timestamp,
    ) {
    }
}

