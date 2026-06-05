<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final readonly class AnchorMeta
{
    public function __construct(
        public string $anchorId,
        public string $chainId,
        public int $fromSeq,
        public int $toSeq,
        public string $merkleAlgorithm,
        public string $root,
        public string $driver,
        public string $state,
        public string $receiptEnvelopeId,
        public ?string $receiptCacheFile = null,
    ) {
        if ($anchorId === '') {
            throw new InvalidBundleManifest('anchor_id must not be empty');
        }
        if ($chainId === '') {
            throw new InvalidBundleManifest('chain_id must not be empty');
        }
        if ($fromSeq < 1) {
            throw new InvalidBundleManifest('from_seq must be >= 1');
        }
        if ($toSeq < $fromSeq) {
            throw new InvalidBundleManifest('to_seq must be >= from_seq');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        $out = [
            'anchor_id'          => $this->anchorId,
            'chain_id'           => $this->chainId,
            'from_seq'           => $this->fromSeq,
            'to_seq'             => $this->toSeq,
            'merkle_algorithm'   => $this->merkleAlgorithm,
            'root'               => $this->root,
            'driver'             => $this->driver,
            'state'              => $this->state,
            'receipt_envelope_id' => $this->receiptEnvelopeId,
        ];
        if ($this->receiptCacheFile !== null) {
            $out['receipt_cache_file'] = $this->receiptCacheFile;
        }
        return $out;
    }

    /** @param array<string,mixed> $arr */
    public static function fromArray(array $arr): self
    {
        return new self(
            anchorId:         self::str($arr, 'anchor_id'),
            chainId:          self::str($arr, 'chain_id'),
            fromSeq:          self::int($arr, 'from_seq'),
            toSeq:            self::int($arr, 'to_seq'),
            merkleAlgorithm:  self::str($arr, 'merkle_algorithm'),
            root:             self::str($arr, 'root'),
            driver:           self::str($arr, 'driver'),
            state:            self::str($arr, 'state'),
            receiptEnvelopeId: self::str($arr, 'receipt_envelope_id'),
            receiptCacheFile: isset($arr['receipt_cache_file']) && is_string($arr['receipt_cache_file'])
                ? $arr['receipt_cache_file']
                : null,
        );
    }

    /** @param array<string,mixed> $arr */
    private static function str(array $arr, string $k): string
    {
        if (! isset($arr[$k]) || ! is_string($arr[$k])) {
            throw new InvalidBundleManifest("AnchorMeta missing string field: $k");
        }
        return $arr[$k];
    }

    /** @param array<string,mixed> $arr */
    private static function int(array $arr, string $k): int
    {
        if (! isset($arr[$k]) || ! is_int($arr[$k])) {
            throw new InvalidBundleManifest("AnchorMeta missing int field: $k");
        }
        return $arr[$k];
    }
}
