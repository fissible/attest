<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Envelope\SignedEnvelope;

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
            $classification = $this->classifyResult($result);
            $out[] = new ClassifiedDetachedAnchor($signed, $classification, $result);
        }
        return $out;
    }

    public function classifyResult(SignatureVerificationResult $result): DetachedAnchorClassification
    {
        if ($result->unsupportedAlgorithm) {
            return DetachedAnchorClassification::UNSUPPORTED_ALG;
        }
        if ($result->invalid) {
            return DetachedAnchorClassification::INVALID;
        }
        if ($result->hasTrustedMatch()) {
            return DetachedAnchorClassification::TRUSTED;
        }
        return DetachedAnchorClassification::UNTRUSTED_VALID;
    }
}
