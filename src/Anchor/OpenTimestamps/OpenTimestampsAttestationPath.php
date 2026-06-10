<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

/**
 * @experimental
 */
final readonly class OpenTimestampsAttestationPath
{
    public function __construct(
        public string $message,
        public OpenTimestampsAttestation $attestation,
    ) {
    }
}
