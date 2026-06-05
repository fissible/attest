<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final readonly class ClaimedKeyMeta
{
    public function __construct(
        public string $keyId,
        public string $sigAlg,
        public string $fingerprint,
        public string $file,
    ) {
        if ($keyId === '') {
            throw new InvalidBundleManifest('key_id must not be empty');
        }
        if ($sigAlg === '') {
            throw new InvalidBundleManifest('sig_alg must not be empty');
        }
        if ($fingerprint === '') {
            throw new InvalidBundleManifest('fingerprint must not be empty');
        }
        if ($file === '') {
            throw new InvalidBundleManifest('file must not be empty');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'key_id'      => $this->keyId,
            'sig_alg'     => $this->sigAlg,
            'fingerprint' => $this->fingerprint,
            'file'        => $this->file,
        ];
    }

    /** @param array<string,mixed> $arr */
    public static function fromArray(array $arr): self
    {
        return new self(
            keyId:       self::str($arr, 'key_id'),
            sigAlg:      self::str($arr, 'sig_alg'),
            fingerprint: self::str($arr, 'fingerprint'),
            file:        self::str($arr, 'file'),
        );
    }

    /** @param array<string,mixed> $arr */
    private static function str(array $arr, string $k): string
    {
        if (! isset($arr[$k]) || ! is_string($arr[$k])) {
            throw new InvalidBundleManifest("ClaimedKeyMeta missing string field: $k");
        }
        return $arr[$k];
    }
}
