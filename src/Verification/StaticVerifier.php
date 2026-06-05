<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorDriver;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Headers\BlockHeaderProvider;
use Fissible\Attest\Headers\HeaderProviderSet;

/**
 * Spec §6 facade: a one-shot static entry that mirrors the documented API.
 * Operationally it just wires Verifier from the named arguments.
 */
final class StaticVerifier
{
    /**
     * @param iterable<TrustedKey> $trustedKeys
     * @param iterable<AnchorDriver> $anchorDrivers
     * @param iterable<BlockHeaderProvider> $headerProviders
     * @param iterable<SignedEnvelope> $detachedAnchorEnvelopes
     */
    public static function verifyChain(
        ChainStore $store,
        string $chainId,
        iterable $trustedKeys,
        int $fromSeq = 1,
        ?int $toSeq = null,
        iterable $anchorDrivers = [],
        iterable $headerProviders = [],
        ?AnchorOutcome $minAnchorOutcome = null,
        bool $allowProviderDisagreement = false,
        bool $requireTrustedKey = true,
        iterable $detachedAnchorEnvelopes = [],
    ): VerificationResult {
        $headers = is_array($headerProviders)
            ? new HeaderProviderSet(...$headerProviders)
            : new HeaderProviderSet(...iterator_to_array($headerProviders, false));

        $verifier = new Verifier(
            store: $store,
            signatures: new SignatureVerifier($trustedKeys),
            policy: new VerificationPolicy(
                minAnchorOutcome: $minAnchorOutcome,
                allowProviderDisagreement: $allowProviderDisagreement,
                requireTrustedKey: $requireTrustedKey,
            ),
            anchorDrivers: $anchorDrivers,
            headers: $headers,
            detachedAnchorEnvelopes: $detachedAnchorEnvelopes,
        );

        return $verifier->verifyChain($chainId, $fromSeq, $toSeq);
    }
}
