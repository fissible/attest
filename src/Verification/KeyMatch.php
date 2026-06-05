<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

final readonly class KeyMatch
{
    public const MATCHED_BY_KEY_ID = 'key_id';
    public const MATCHED_BY_FINGERPRINT = 'fingerprint';

    public function __construct(
        public TrustedKey $key,
        public string $matchedBy,
    ) {
        if (! in_array($matchedBy, [self::MATCHED_BY_KEY_ID, self::MATCHED_BY_FINGERPRINT], true)) {
            throw new \InvalidArgumentException('matchedBy must be key_id or fingerprint');
        }
    }
}
