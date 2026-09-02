<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

use ParagonIE\ConstantTime\Base64;

/**
 * Opaque binary blob carried in payloads. Always serialized as
 * {"$binary": "<base64>"} in canonical form. The "$binary" key is reserved:
 * PayloadValidator rejects user payloads that use it directly.
 *
 * Hard cap: 64KB raw. Larger blobs must be stored externally and referenced
 * by URL + sha256 in the payload.
 * @api
 */
final readonly class Binary
{
    public const MAX_BYTES = 65536;

    public function __construct(public string $base64)
    {
    }

    public static function ofRaw(string $bytes): self
    {
        if (strlen($bytes) > self::MAX_BYTES) {
            throw new InvalidPayload('Binary exceeds 64KB cap');
        }
        return new self(Base64::encode($bytes));
    }

    public static function ofBase64(string $base64): self
    {
        $raw = self::decode($base64);
        if (strlen($raw) > self::MAX_BYTES) {
            throw new InvalidPayload('Binary exceeds 64KB cap');
        }
        // The base64 string is stored verbatim in the canonical payload, so
        // only the encoding ofRaw() would produce is accepted.
        if (Base64::encode($raw) !== $base64) {
            throw new InvalidPayload('Binary base64 is not canonical');
        }
        return new self($base64);
    }

    public function raw(): string
    {
        return self::decode($this->base64);
    }

    private static function decode(string $base64): string
    {
        try {
            return Base64::decode($base64, strictPadding: true);
        } catch (\RangeException $e) {
            throw new InvalidPayload('Binary is not valid base64: ' . $e->getMessage(), previous: $e);
        }
    }
}
