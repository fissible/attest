<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

/**
 * @api
 */
final readonly class ChainSegmentMeta
{
    public function __construct(
        public string $chainId,
        public string $file,
        public int $fromSeq,
        public int $toSeq,
        public int $envelopeCount,
        public string $headHash,
    ) {
        if ($chainId === '') {
            throw new InvalidBundleManifest('chain_id must not be empty');
        }
        if ($fromSeq < 1) {
            throw new InvalidBundleManifest('from_seq must be >= 1');
        }
        if ($toSeq < $fromSeq) {
            throw new InvalidBundleManifest('to_seq must be >= from_seq');
        }
        if ($envelopeCount < 0) {
            throw new InvalidBundleManifest('envelope_count must be >= 0');
        }
        if (! preg_match('/\A[0-9a-f]{64}\z/', $headHash)) {
            throw new InvalidBundleManifest('head_hash must be a 64-char lower-case hex SHA-256');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'chain_id'       => $this->chainId,
            'file'           => $this->file,
            'from_seq'       => $this->fromSeq,
            'to_seq'         => $this->toSeq,
            'envelope_count' => $this->envelopeCount,
            'head_hash'      => $this->headHash,
        ];
    }

    /** @param array<string,mixed> $arr */
    public static function fromArray(array $arr): self
    {
        return new self(
            chainId:       self::str($arr, 'chain_id'),
            file:          self::str($arr, 'file'),
            fromSeq:       self::int($arr, 'from_seq'),
            toSeq:         self::int($arr, 'to_seq'),
            envelopeCount: self::int($arr, 'envelope_count'),
            headHash:      self::str($arr, 'head_hash'),
        );
    }

    /** @param array<string,mixed> $arr */
    private static function str(array $arr, string $k): string
    {
        if (! isset($arr[$k]) || ! is_string($arr[$k])) {
            throw new InvalidBundleManifest("ChainSegmentMeta missing string field: $k");
        }
        return $arr[$k];
    }

    /** @param array<string,mixed> $arr */
    private static function int(array $arr, string $k): int
    {
        if (! isset($arr[$k]) || ! is_int($arr[$k])) {
            throw new InvalidBundleManifest("ChainSegmentMeta missing int field: $k");
        }
        return $arr[$k];
    }
}
