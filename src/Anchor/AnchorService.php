<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\Signer;
use Fissible\Attest\Verification\Warning;

/**
 * @experimental
 */
final class AnchorService
{
    /** @var list<Warning> */
    private array $warnings = [];

    public function __construct(
        private readonly ChainStore $store,
        private readonly AnchorClaimStore $claimStore,
        private readonly Signer $signer,
        private readonly AnchorBatchSelector $batchSelector = new AnchorBatchSelector(),
        private readonly ?string $claimedBy = null,
        private readonly int $claimTtlSeconds = 3600,
    ) {
        if ($claimTtlSeconds < 0) {
            throw new \InvalidArgumentException('claimTtlSeconds must be >= 0');
        }
    }

    public function anchorNext(
        string $chainId,
        AnchorDriver $driver,
        int $fromSeq = 1,
        ?int $toSeq = null,
    ): ?SignedEnvelope {
        $selection = $this->batchSelector->select($this->store, $chainId, $fromSeq, $toSeq);
        if ($selection === null) {
            return null;
        }

        return $this->anchorRange($chainId, $selection['from_seq'], $selection['to_seq'], $driver);
    }

    public function anchorRange(string $chainId, int $fromSeq, int $toSeq, AnchorDriver $driver): ?SignedEnvelope
    {
        $this->warnings = [];

        $bytes = $this->canonicalEnvelopeBytes($chainId, $fromSeq, $toSeq);
        $expectedCount = $toSeq - $fromSeq + 1;
        if (count($bytes) !== $expectedCount) {
            throw new \RuntimeException(sprintf(
                'Could not read complete anchor range %s[%d,%d]; expected %d envelopes, got %d',
                $chainId,
                $fromSeq,
                $toSeq,
                $expectedCount,
                count($bytes),
            ));
        }

        $target = new AnchorTarget(
            chainId: $chainId,
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex($bytes),
        );
        $anchorId = AnchorId::derive($target, $driver->name());

        if (! $this->claimStore->claim($anchorId, $this->newClaim($chainId, $fromSeq, $toSeq, $driver))) {
            $existing = $this->reconcileExistingAnchor($anchorId, $target);
            if ($existing !== null) {
                return $existing;
            }
            // No envelope backs the held claim. If the claim is older than the
            // TTL, its worker died between claim() and the append; reclaim it
            // and retry exactly once with a fresh claim. A live claim is left
            // to its owner.
            if (! $this->reclaimIfExpired($anchorId)) {
                return null;
            }
            if (! $this->claimStore->claim($anchorId, $this->newClaim($chainId, $fromSeq, $toSeq, $driver))) {
                return null;
            }
        }

        try {
            $receipt = $driver->anchor($target);
            if ($receipt->anchorId !== $anchorId) {
                throw new \RuntimeException('Anchor driver returned receipt for a different target or driver');
            }

            $envelope = $this->appendReceiptEnvelope($receipt);
            $this->claimStore->complete($anchorId, $envelope->envelope->id);

            return $envelope;
        } catch (\Throwable $e) {
            $this->claimStore->release($anchorId);
            throw $e;
        }
    }

    /**
     * @return list<Warning>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /**
     * @return list<string>
     */
    private function canonicalEnvelopeBytes(string $chainId, int $fromSeq, int $toSeq): array
    {
        if ($this->store instanceof RawChainStore) {
            return array_values(iterator_to_array($this->store->readRawRange($chainId, $fromSeq, $toSeq), false));
        }

        $this->warnings[] = new Warning(
            Warning::ANCHOR_OVER_RECOMPUTED_BYTES,
            'Anchor commits to recomputed canonical envelope bytes because raw stored bytes are unavailable.',
            ['chain_id' => $chainId, 'from_seq' => $fromSeq, 'to_seq' => $toSeq],
        );

        $bytes = [];
        foreach ($this->store->readRange($chainId, $fromSeq, $toSeq) as $envelope) {
            $bytes[] = $envelope->signedCanonicalBytes();
        }

        return $bytes;
    }

    private function appendReceiptEnvelope(AnchorReceipt $receipt): SignedEnvelope
    {
        $type = $receipt->state === ProofState::UPGRADED
            ? AnchorEnvelope::UPGRADED_TYPE
            : AnchorEnvelope::SUBMITTED_TYPE;
        $payload = $receipt->state === ProofState::UPGRADED
            ? AnchorEnvelope::upgradedPayload($receipt)
            : AnchorEnvelope::submittedPayload($receipt);

        return EvidenceChain::open($this->store, $receipt->target->chainId, $this->signer)
            ->record($type, $payload);
    }

    private function newClaim(string $chainId, int $fromSeq, int $toSeq, AnchorDriver $driver): AnchorClaim
    {
        return new AnchorClaim(
            chainId: $chainId,
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            driver: $driver->name(),
            claimedBy: $this->claimedBy(),
            claimedAtIso8601: $this->nowIso8601(),
        );
    }

    private function reclaimIfExpired(string $anchorId): bool
    {
        foreach ($this->claimStore->reclaimExpired($this->claimTtlSeconds) as $expiredAnchorId => $expiredClaim) {
            if ($expiredAnchorId === $anchorId) {
                $this->claimStore->release($anchorId);

                return true;
            }
        }

        return false;
    }

    private function reconcileExistingAnchor(string $anchorId, AnchorTarget $target): ?SignedEnvelope
    {
        foreach ($this->store->readRange($target->chainId, $target->toSeq + 1) as $envelope) {
            if (! str_starts_with($envelope->envelope->type, 'attest.anchor.')) {
                continue;
            }
            if (($envelope->envelope->payload['anchor_id'] ?? null) !== $anchorId) {
                continue;
            }

            try {
                $this->claimStore->complete($anchorId, $envelope->envelope->id);
            } catch (\RuntimeException) {
                // A completed claim may already point at an equivalent prior anchor envelope.
            }

            return $envelope;
        }

        return null;
    }

    private function claimedBy(): string
    {
        if ($this->claimedBy !== null) {
            return $this->claimedBy;
        }

        return (gethostname() ?: 'host') . ':' . getmypid() . ':' . bin2hex(random_bytes(8));
    }

    private function nowIso8601(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z');
    }
}
