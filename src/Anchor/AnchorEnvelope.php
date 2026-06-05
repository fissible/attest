<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Envelope\SignedEnvelope;
use ParagonIE\ConstantTime\Base64;

final class AnchorEnvelope
{
    public const SUBMITTED_TYPE = 'attest.anchor.submitted';
    public const UPGRADED_TYPE = 'attest.anchor.upgraded';

    /**
     * @return array<string, mixed>
     */
    public static function submittedPayload(AnchorReceipt $receipt): array
    {
        if ($receipt->state === ProofState::UPGRADED) {
            throw new InvalidAnchorEnvelope('submitted anchor payload cannot carry upgraded state');
        }

        return self::payload($receipt, 'anchored_at', $receipt->createdAtIso8601);
    }

    /**
     * @return array<string, mixed>
     */
    public static function upgradedPayload(AnchorReceipt $receipt, ?string $supersedesEnvelopeId = null): array
    {
        if ($receipt->state !== ProofState::UPGRADED) {
            throw new InvalidAnchorEnvelope('upgraded anchor payload requires upgraded state');
        }

        $payload = self::payload($receipt, 'upgraded_at', $receipt->createdAtIso8601);
        if ($supersedesEnvelopeId !== null) {
            $payload['supersedes_envelope_id'] = $supersedesEnvelopeId;
        }

        return $payload;
    }

    public static function fromSignedEnvelope(SignedEnvelope $signed): AnchorReceipt
    {
        $type = $signed->envelope->type;
        if ($type !== self::SUBMITTED_TYPE && $type !== self::UPGRADED_TYPE) {
            throw new InvalidAnchorEnvelope('Envelope is not an anchor envelope');
        }

        return self::fromPayload($signed->envelope->payload);
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    public static function fromPayload(array $payload): AnchorReceipt
    {
        $anchorId = self::requiredString($payload, 'anchor_id');
        $target = new AnchorTarget(
            chainId: self::requiredString($payload, 'target_chain'),
            fromSeq: self::requiredInt($payload, 'from_seq'),
            toSeq: self::requiredInt($payload, 'to_seq'),
            merkleAlgorithm: self::requiredString($payload, 'merkle_algorithm'),
            rootHex: self::requiredString($payload, 'root'),
        );

        $stateRaw = self::requiredString($payload, 'state');
        $state = ProofState::tryFrom($stateRaw);
        if ($state === null) {
            throw new InvalidAnchorEnvelope('Invalid anchor state: ' . $stateRaw);
        }

        $receiptBytes = self::receiptBytes($payload);
        $createdAt = self::timestamp($payload, $state);

        try {
            return new AnchorReceipt(
                driverName: self::requiredString($payload, 'driver'),
                target: $target,
                state: $state,
                receiptBytes: $receiptBytes,
                createdAtIso8601: $createdAt,
                anchorId: $anchorId,
            );
        } catch (\InvalidArgumentException $e) {
            throw new InvalidAnchorEnvelope($e->getMessage(), previous: $e);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function payload(AnchorReceipt $receipt, string $timestampField, string $timestamp): array
    {
        return [
            'anchor_id' => $receipt->anchorId,
            'target_chain' => $receipt->target->chainId,
            'from_seq' => $receipt->target->fromSeq,
            'to_seq' => $receipt->target->toSeq,
            'merkle_algorithm' => $receipt->target->merkleAlgorithm,
            'root' => $receipt->target->rootHex,
            'driver' => $receipt->driverName,
            'state' => $receipt->state->value,
            'receipt_bytes' => 'base64:' . Base64::encode($receipt->receiptBytes),
            $timestampField => $timestamp,
        ];
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    private static function requiredString(array $payload, string $field): string
    {
        if (! array_key_exists($field, $payload) || ! is_string($payload[$field])) {
            throw new InvalidAnchorEnvelope("Anchor payload missing string field: $field");
        }
        return $payload[$field];
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    private static function requiredInt(array $payload, string $field): int
    {
        if (! array_key_exists($field, $payload) || ! is_int($payload[$field])) {
            throw new InvalidAnchorEnvelope("Anchor payload missing integer field: $field");
        }
        return $payload[$field];
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    private static function receiptBytes(array $payload): string
    {
        $encoded = self::requiredString($payload, 'receipt_bytes');
        if (! str_starts_with($encoded, 'base64:')) {
            throw new InvalidAnchorEnvelope("Anchor payload field 'receipt_bytes' must be base64-prefixed");
        }

        return Base64::decode(substr($encoded, 7), strictPadding: true);
    }

    /**
     * @param array<array-key, mixed> $payload
     */
    private static function timestamp(array $payload, ProofState $state): string
    {
        if ($state === ProofState::UPGRADED && isset($payload['upgraded_at'])) {
            return self::requiredString($payload, 'upgraded_at');
        }
        if (isset($payload['anchored_at'])) {
            return self::requiredString($payload, 'anchored_at');
        }
        if (isset($payload['upgraded_at'])) {
            return self::requiredString($payload, 'upgraded_at');
        }

        throw new InvalidAnchorEnvelope("Anchor payload missing timestamp field: anchored_at or upgraded_at");
    }
}

