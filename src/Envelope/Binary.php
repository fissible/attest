<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

use ParagonIE\ConstantTime\Base64;

/**
 * Opaque binary blob carried in payloads. Always serialized as
 * {"_attest_binary": "<base64>"} in canonical form.
 *
 * Hard cap: 64KB raw. Larger blobs must be stored externally and referenced
 * by URL + sha256 in the payload.
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
        $raw = Base64::decode($base64, strictPadding: true);
        if (strlen($raw) > self::MAX_BYTES) {
            throw new InvalidPayload('Binary exceeds 64KB cap');
        }
        return new self($base64);
    }

    public function raw(): string
    {
        return Base64::decode($this->base64, strictPadding: true);
    }
}
