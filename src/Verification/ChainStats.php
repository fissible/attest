<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

/**
 * @api
 */
final readonly class ChainStats
{
    public function __construct(
        public string $chainId,
        public int $fromSeq,
        public ?int $toSeq,
        public int $envelopeCount,
        public int $trustedSignatureCount,
        public int $untrustedSignatureCount,
        public int $anchorEnvelopeCount,
    ) {
    }
}
