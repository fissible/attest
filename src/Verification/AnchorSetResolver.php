<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\InvalidAnchorEnvelope;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Envelope\SignedEnvelope;

final class AnchorSetResolver
{
    /**
     * @param iterable<SignedEnvelope> $envelopes
     * @return list<ResolvedAnchor>
     */
    public function resolve(iterable $envelopes): array
    {
        $groups = [];

        foreach ($envelopes as $signed) {
            if (! str_starts_with($signed->envelope->type, 'attest.anchor.')) {
                continue;
            }

            $anchorId = $this->anchorIdFromPayload($signed);
            $groups[$anchorId] ??= [
                'envelope_ids' => [],
                'receipts' => [],
                'errors' => [],
            ];
            $groups[$anchorId]['envelope_ids'][] = $signed->envelope->id;

            try {
                $groups[$anchorId]['receipts'][] = AnchorEnvelope::fromSignedEnvelope($signed);
            } catch (InvalidAnchorEnvelope $e) {
                $groups[$anchorId]['errors'][] = $e->getMessage();
            }
        }

        $resolved = [];
        foreach ($groups as $anchorId => $group) {
            /** @var list<string> $errors */
            $errors = $group['errors'];
            /** @var list<AnchorReceipt> $receipts */
            $receipts = $group['receipts'];
            /** @var list<string> $envelopeIds */
            $envelopeIds = $group['envelope_ids'];

            if ($errors !== []) {
                $resolved[] = ResolvedAnchor::invalid(
                    $anchorId,
                    'Invalid anchor envelope: ' . implode('; ', $errors),
                    $envelopeIds,
                    $receipts,
                );
                continue;
            }

            if ($receipts === []) {
                $resolved[] = ResolvedAnchor::invalid($anchorId, 'Anchor group contains no valid receipts', $envelopeIds);
                continue;
            }

            if (! $this->bindingsAgree($receipts)) {
                $resolved[] = ResolvedAnchor::invalid($anchorId, 'Anchor binding fields conflict within anchor_id group', $envelopeIds, $receipts);
                continue;
            }

            $resolved[] = ResolvedAnchor::valid($anchorId, $this->strongestReceipt($receipts), $envelopeIds, $receipts);
        }

        usort($resolved, static function (ResolvedAnchor $a, ResolvedAnchor $b): int {
            $aFrom = $a->receipt?->target->fromSeq ?? PHP_INT_MAX;
            $bFrom = $b->receipt?->target->fromSeq ?? PHP_INT_MAX;
            if ($aFrom !== $bFrom) {
                return $aFrom <=> $bFrom;
            }

            return strcmp($a->anchorId, $b->anchorId);
        });

        return $resolved;
    }

    private function anchorIdFromPayload(SignedEnvelope $signed): string
    {
        $anchorId = $signed->envelope->payload['anchor_id'] ?? null;
        if (is_string($anchorId) && $anchorId !== '') {
            return $anchorId;
        }

        return 'invalid:' . $signed->envelope->id;
    }

    /**
     * @param list<AnchorReceipt> $receipts
     */
    private function bindingsAgree(array $receipts): bool
    {
        $first = $this->bindingKey($receipts[0]);
        foreach ($receipts as $receipt) {
            if ($this->bindingKey($receipt) !== $first) {
                return false;
            }
        }

        return true;
    }

    private function bindingKey(AnchorReceipt $receipt): string
    {
        return implode("\0", [
            $receipt->target->chainId,
            (string) $receipt->target->fromSeq,
            (string) $receipt->target->toSeq,
            $receipt->target->merkleAlgorithm,
            $receipt->target->rootHex,
            $receipt->driverName,
        ]);
    }

    /**
     * @param list<AnchorReceipt> $receipts
     */
    private function strongestReceipt(array $receipts): AnchorReceipt
    {
        usort($receipts, fn (AnchorReceipt $a, AnchorReceipt $b): int => $this->stateRank($b->state) <=> $this->stateRank($a->state));

        return $receipts[0];
    }

    private function stateRank(ProofState $state): int
    {
        return match ($state) {
            ProofState::SUBMITTED => 0,
            ProofState::PENDING => 1,
            ProofState::UPGRADED => 2,
        };
    }
}
