<?php
declare(strict_types=1);

namespace Fissible\Attest\Canonical;

/**
 * RFC 8785 (JCS) canonical JSON encoder.
 *
 * Constraints (intentionally a strict subset of the RFC):
 *  - Object keys sorted by UTF-16 code unit ordering.
 *  - Integers serialized without decimal point or exponent.
 *  - Floats explicitly rejected (attest payloads use string-decimal).
 *  - Strings escaped per RFC 8785 (subset of RFC 8259) — control chars as \uXXXX.
 *  - Invalid UTF-8 rejected.
 *
 * Not a general-purpose JSON library — narrowly scoped to attest's needs.
 */
final class JcsEncoder
{
    public static function encode(mixed $value): string
    {
        return self::encodeValue($value);
    }

    private static function encodeValue(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }
        if ($value === true) {
            return 'true';
        }
        if ($value === false) {
            return 'false';
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_float($value)) {
            throw new \InvalidArgumentException('JCS: floats are not allowed; use string-decimal');
        }
        if (is_string($value)) {
            return self::encodeString($value);
        }
        if (is_array($value)) {
            return array_is_list($value)
                ? self::encodeArray($value)
                : self::encodeObject($value);
        }
        throw new \InvalidArgumentException(
            'JCS: unsupported type ' . get_debug_type($value)
        );
    }

    /** @param list<mixed> $list */
    private static function encodeArray(array $list): string
    {
        $parts = array_map(self::encodeValue(...), $list);
        return '[' . implode(',', $parts) . ']';
    }

    /** @param array<string, mixed> $object */
    private static function encodeObject(array $object): string
    {
        $keys = array_keys($object);
        foreach ($keys as $k) {
            if (! is_string($k)) {
                throw new \InvalidArgumentException('JCS: object keys must be strings');
            }
        }
        // RFC 8785 §3.2.3: sort by UTF-16 code units. Convert keys to UTF-16BE
        // byte strings and strcmp them — for BMP chars this is equivalent to
        // Unicode code-point order; for surrogate-pair chars it diverges from
        // raw UTF-8 byte order.
        usort($keys, function (string $a, string $b): int {
            $aUtf16 = mb_convert_encoding($a, 'UTF-16BE', 'UTF-8');
            $bUtf16 = mb_convert_encoding($b, 'UTF-16BE', 'UTF-8');
            if ($aUtf16 === false || $bUtf16 === false) {
                throw new \InvalidArgumentException('JCS: object key is not valid UTF-8');
            }
            return strcmp($aUtf16, $bUtf16);
        });
        $parts = [];
        foreach ($keys as $k) {
            $parts[] = self::encodeString($k) . ':' . self::encodeValue($object[$k]);
        }
        return '{' . implode(',', $parts) . '}';
    }

    private static function encodeString(string $s): string
    {
        if (! mb_check_encoding($s, 'UTF-8')) {
            throw new \InvalidArgumentException('JCS: string is not valid UTF-8');
        }
        $out = '"';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            $o = ord($c);
            if ($c === '"') { $out .= '\\"'; continue; }
            if ($c === '\\') { $out .= '\\\\'; continue; }
            if ($c === "\b") { $out .= '\\b'; continue; }
            if ($c === "\f") { $out .= '\\f'; continue; }
            if ($c === "\n") { $out .= '\\n'; continue; }
            if ($c === "\r") { $out .= '\\r'; continue; }
            if ($c === "\t") { $out .= '\\t'; continue; }
            if ($o < 0x20) {
                $out .= sprintf('\\u%04x', $o);
                continue;
            }
            // Valid UTF-8 byte sequences pass through unchanged (RFC 8785 §3.2.2.2).
            $out .= $c;
        }
        return $out . '"';
    }
}
