<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Envelope\SignedEnvelope;

/**
 * @experimental
 */
final class DetachedAnchorVerifier
{
    public function __construct(private readonly SignatureVerifier $signatures)
    {
    }

    /**
     * @param iterable<SignedEnvelope> $envelopes
     * @return list<ClassifiedDetachedAnchor>
     */
    public function classify(iterable $envelopes): array
    {
        $out = [];
        foreach ($envelopes as $signed) {
            $result = $this->signatures->verify($signed);
            $classification = DetachedAnchorClassification::fromSignatureResult($result);
            $out[] = new ClassifiedDetachedAnchor($signed, $classification, $result);
        }
        return $out;
    }
}
