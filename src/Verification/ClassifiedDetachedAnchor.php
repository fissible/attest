<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Envelope\SignedEnvelope;

final readonly class ClassifiedDetachedAnchor
{
    public function __construct(
        public SignedEnvelope $envelope,
        public DetachedAnchorClassification $classification,
        public SignatureVerificationResult $signatureResult,
    ) {
    }
}
