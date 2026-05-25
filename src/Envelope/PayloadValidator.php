<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

use Fissible\Attest\Canonical\JcsEncoder;

/**
 * Enforces the wire-format type policy (spec §5.3):
 *   - allowed: string (UTF-8), int (JS-safe ±2^53-1), bool, null,
 *              list-of-allowed, assoc-array(string => allowed), Binary
 *   - rejected: float, DateTimeInterface, resource, invalid UTF-8, mixed-key arrays
 *   - canonical size cap: 64KB total
 */
final class PayloadValidator
{
    public const int JS_SAFE_MAX = 9007199254740991;   // 2^53 - 1
    public const int JS_SAFE_MIN = -9007199254740991;
    public const int MAX_CANONICAL_BYTES = 65536;

    /**
     * Validate a payload and return it unchanged (for fluent use).
     *
     * @param array<array-key, mixed> $payload
     * @return array<array-key, mixed>
     */
    public static function ensure(array $payload): array
    {
        self::walk($payload, '');
        $canonical = JcsEncoder::encode(self::toCanonical($payload));
        if (strlen($canonical) > self::MAX_CANONICAL_BYTES) {
            throw new InvalidPayload(
                'Canonical payload exceeds 64KB (got ' . strlen($canonical) . ' bytes)'
            );
        }
        return $payload;
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

    /** Convert Binary wrappers into their canonical {"_attest_binary": ...} form. */
    private static function toCanonical(mixed $value): mixed
    {
        if ($value instanceof Binary) {
            return ['_attest_binary' => $value->base64];
        }
        if (is_array($value)) {
            return array_map(self::toCanonical(...), $value);
        }
        return $value;
    }
}
