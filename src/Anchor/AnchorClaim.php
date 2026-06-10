<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

/**
 * @experimental
 */
final readonly class AnchorClaim
{
    public function __construct(
        public string $chainId,
        public int $fromSeq,
        public int $toSeq,
        public string $driver,
        public string $claimedBy,
        public string $claimedAtIso8601,
        public ?string $completedAtIso8601 = null,
        public ?string $completedEnvelopeId = null,
    ) {
        if ($chainId === '') {
            throw new \InvalidArgumentException('chainId must not be empty');
        }
        if ($fromSeq < 1) {
            throw new \InvalidArgumentException('fromSeq must be >= 1');
        }
        if ($toSeq < $fromSeq) {
            throw new \InvalidArgumentException('toSeq must be >= fromSeq');
        }
        if ($driver === '') {
            throw new \InvalidArgumentException('driver must not be empty');
        }
        if ($claimedBy === '') {
            throw new \InvalidArgumentException('claimedBy must not be empty');
        }
        if ($claimedAtIso8601 === '') {
            throw new \InvalidArgumentException('claimedAtIso8601 must not be empty');
        }
        if (($completedAtIso8601 === null) !== ($completedEnvelopeId === null)) {
            throw new \InvalidArgumentException('completedAtIso8601 and completedEnvelopeId must be set together');
        }
    }

    public function isCompleted(): bool
    {
        return $this->completedAtIso8601 !== null;
    }

    public function complete(string $envelopeId, string $completedAtIso8601): self
    {
        if ($envelopeId === '') {
            throw new \InvalidArgumentException('envelopeId must not be empty');
        }
        if ($completedAtIso8601 === '') {
            throw new \InvalidArgumentException('completedAtIso8601 must not be empty');
        }

        return new self(
            chainId: $this->chainId,
            fromSeq: $this->fromSeq,
            toSeq: $this->toSeq,
            driver: $this->driver,
            claimedBy: $this->claimedBy,
            claimedAtIso8601: $this->claimedAtIso8601,
            completedAtIso8601: $completedAtIso8601,
            completedEnvelopeId: $envelopeId,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(string $anchorId): array
    {
        self::assertAnchorId($anchorId);

        return [
            'anchor_id' => $anchorId,
            'chain_id' => $this->chainId,
            'from_seq' => $this->fromSeq,
            'to_seq' => $this->toSeq,
            'driver' => $this->driver,
            'claimed_by' => $this->claimedBy,
            'claimed_at' => $this->claimedAtIso8601,
            'completed_at' => $this->completedAtIso8601,
            'completed_envelope_id' => $this->completedEnvelopeId,
        ];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    public static function fromArray(array $data, ?string $expectedAnchorId = null): self
    {
        if ($expectedAnchorId !== null) {
            self::assertAnchorId($expectedAnchorId);
            if (($data['anchor_id'] ?? null) !== $expectedAnchorId) {
                throw new \InvalidArgumentException('Claim anchor_id does not match expected anchorId');
            }
        }

        $completedAt = self::nullableString($data, 'completed_at');
        $completedEnvelopeId = self::nullableString($data, 'completed_envelope_id');

        return new self(
            chainId: self::stringField($data, 'chain_id'),
            fromSeq: self::intField($data, 'from_seq'),
            toSeq: self::intField($data, 'to_seq'),
            driver: self::stringField($data, 'driver'),
            claimedBy: self::stringField($data, 'claimed_by'),
            claimedAtIso8601: self::stringField($data, 'claimed_at'),
            completedAtIso8601: $completedAt,
            completedEnvelopeId: $completedEnvelopeId,
        );
    }

    public static function assertAnchorId(string $anchorId): void
    {
        if (! preg_match('/\A[0-9a-f]{64}\z/', $anchorId)) {
            throw new \InvalidArgumentException('anchorId must be a lower-case 64-character hex digest');
        }
    }

    /**
     * @param array<array-key, mixed> $data
     */
    private static function stringField(array $data, string $field): string
    {
        if (! array_key_exists($field, $data) || ! is_string($data[$field])) {
            throw new \InvalidArgumentException("Claim missing string field: $field");
        }
        return $data[$field];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    private static function intField(array $data, string $field): int
    {
        if (! array_key_exists($field, $data) || ! is_int($data[$field])) {
            throw new \InvalidArgumentException("Claim missing integer field: $field");
        }
        return $data[$field];
    }

    /**
     * @param array<array-key, mixed> $data
     */
    private static function nullableString(array $data, string $field): ?string
    {
        if (! array_key_exists($field, $data) || $data[$field] === null) {
            return null;
        }
        if (! is_string($data[$field])) {
            throw new \InvalidArgumentException("Claim field must be string or null: $field");
        }
        return $data[$field];
    }
}

