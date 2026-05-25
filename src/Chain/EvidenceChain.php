<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\PayloadValidator;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\Signer;
use Symfony\Component\Uid\Ulid;

/**
 * Friendly wrapper that hides the ChainStore callback shape.
 * Use this in application code; reach for ChainStore directly only when
 * you need full control over the build-and-sign callback.
 */
final readonly class EvidenceChain
{
    public function __construct(
        private ChainStore $store,
        public string $chainId,
        private Signer $signer,
    ) {
    }

    public static function open(ChainStore $store, string $chainId, Signer $signer): self
    {
        return new self($store, $chainId, $signer);
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    public function record(
        string $type,
        array $payload,
        ?string $subject = null,
        ?string $correlation = null,
        ?string $tenant = null,
    ): SignedEnvelope {
        PayloadValidator::ensure($payload);

        return $this->store->append($this->chainId, function (AppendContext $ctx) use (
            $type, $payload, $subject, $correlation, $tenant
        ) {
            $env = new EvidenceEnvelope(
                id: (string) Ulid::generate(),
                chain: $ctx->chainId,
                seq: $ctx->sequence,
                ts: $ctx->timestampIso8601,
                type: $type,
                payload: $payload,
                prevHash: $ctx->prevHash,
                keyId: $this->signer->keyId(),
                sigAlg: 'ed25519',
                subject: $subject,
                correlation: $correlation,
                tenant: $tenant,
            );
            return SignedEnvelope::sign($env, $this->signer);
        });
    }
}
