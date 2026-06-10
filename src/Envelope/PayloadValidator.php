<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

use Fissible\Attest\Canonical\JcsEncoder;

/**
 * Enforces the wire-format type policy (spec §5.3):
 *   - allowed: string (UTF-8), int (JS-safe ±2^53-1), bool, null,
 *              list-of-allowed, assoc-array(string => allowed), Binary
 *   - rejected: float, DateTimeInterface, resource, invalid UTF-8, mixed-key arrays
 *   - canonical payload size cap: 60KB (sanity ceiling leaving ≥4KB for envelope
 *     frame overhead under the authoritative 64KB signed envelope cap enforced by
 *     SignedEnvelope::sign() and EnvelopeCodec::decodeSigned())
 * @api
 */
final class PayloadValidator
{
    public const JS_SAFE_MAX = 9007199254740991;   // 2^53 - 1
    public const JS_SAFE_MIN = -9007199254740991;
    public const MAX_CANONICAL_BYTES = SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES - 4096;  // 4KB headroom for envelope frame overhead

    /**
     * Validate a payload and return it unchanged (for fluent use).
     *
     * @param array<array-key, mixed> $payload
     * @return array<array-key, mixed>
     */
    public static function ensure(array $payload): array
    {
        self::walk($payload, '');
        /** @var array<array-key, mixed> $canonical */
        $canonical = self::toCanonical($payload);
        $bytes = JcsEncoder::encode($canonical);
        if (strlen($bytes) > self::MAX_CANONICAL_BYTES) {
            throw new InvalidPayload(
                'Canonical payload exceeds ' . self::MAX_CANONICAL_BYTES . ' bytes (got ' . strlen($bytes) . ')'
            );
        }
        return $canonical;
    }

    private static function walk(mixed $value, string $path): void
    {
        if ($value === null || is_bool($value) || $value instanceof Binary) {
            return;
        }
        if (is_int($value)) {
            if ($value > self::JS_SAFE_MAX || $value < self::JS_SAFE_MIN) {
                throw new InvalidPayload(
                    "Integer at path '$path' is outside JS-safe range ±(2^53-1); encode as string-decimal"
                );
            }
            return;
        }
        if (is_string($value)) {
            if (! mb_check_encoding($value, 'UTF-8')) {
                throw new InvalidPayload("Invalid UTF-8 string at path: $path");
            }
            return;
        }
        if (is_float($value)) {
            throw new InvalidPayload("Disallowed float at path: $path (encode as string-decimal)");
        }
        if ($value instanceof \DateTimeInterface) {
            throw new InvalidPayload(
                "DateTime object at path: $path (encode as ISO 8601 string)"
            );
        }
        if (is_resource($value)) {
            throw new InvalidPayload("Resource at path: $path");
        }
        if (is_array($value)) {
            if ($value === []) {
                return;
            }
            if (array_key_exists('$binary', $value)) {
                throw new InvalidPayload(
                    "Reserved key '\$binary' at path '$path' is reserved for the canonical binary sentinel; pass a Binary instance instead"
                );
            }
            $isList = array_is_list($value);
            $allStringKeys = ! $isList && array_reduce(
                array_keys($value),
                static fn(bool $acc, mixed $k) => $acc && is_string($k),
                true,
            );
            if (! $isList && ! $allStringKeys) {
                throw new InvalidPayload("Array at path '$path' has mixed keys");
            }
            foreach ($value as $k => $v) {
                $childPath = $path === '' ? (string) $k : "$path.$k";
                self::walk($v, $childPath);
            }
            return;
        }
        throw new InvalidPayload(
            "Unsupported type at path '$path': " . get_debug_type($value)
        );
    }

    /** Convert Binary wrappers into their canonical {"$binary": ...} form. */
    private static function toCanonical(mixed $value): mixed
    {
        if ($value instanceof Binary) {
            return ['$binary' => $value->base64];
        }
        if (is_array($value)) {
            return array_map(self::toCanonical(...), $value);
        }
        return $value;
    }
}
