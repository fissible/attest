<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Signing\Fingerprint;

final readonly class TrustedKey
{
    public string $fingerprint;

    public function __construct(
        public string $publicKey,
        public ?string $keyId = null,
        public ?string $label = null,
    ) {
        if ($keyId === '') {
            throw new \InvalidArgumentException('keyId must not be empty');
        }
        if ($label === '') {
            throw new \InvalidArgumentException('label must not be empty');
        }

        $this->fingerprint = Fingerprint::of($publicKey);
    }
}
