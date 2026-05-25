<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Canonical;

use Fissible\Attest\Canonical\JcsEncoder;
use PHPUnit\Framework\TestCase;

final class JcsEncoderTest extends TestCase
{
    public function test_orders_object_keys_lexicographically_by_utf16_code_unit(): void
    {
        $input = ['z' => 1, 'a' => 2, 'm' => 3];
        $this->assertSame('{"a":2,"m":3,"z":1}', JcsEncoder::encode($input));
    }

    public function test_preserves_array_order(): void
    {
        $input = [3, 1, 2];
        $this->assertSame('[3,1,2]', JcsEncoder::encode($input));
    }

    public function test_nested_objects_have_keys_ordered_at_every_level(): void
    {
        $input = ['b' => ['z' => 1, 'a' => 2], 'a' => 1];
        $this->assertSame('{"a":1,"b":{"a":2,"z":1}}', JcsEncoder::encode($input));
    }

    public function test_serializes_integers_without_decimal_point(): void
    {
        $this->assertSame('{"n":42}', JcsEncoder::encode(['n' => 42]));
        $this->assertSame('{"n":-7}', JcsEncoder::encode(['n' => -7]));
        $this->assertSame('{"n":0}', JcsEncoder::encode(['n' => 0]));
    }

    public function test_rejects_floats(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('floats are not allowed');
        JcsEncoder::encode(['n' => 1.5]);
    }

    public function test_serializes_booleans_and_null(): void
    {
        $this->assertSame('{"a":false,"b":null,"c":true}', JcsEncoder::encode([
            'c' => true, 'a' => false, 'b' => null,
        ]));
    }

    public function test_escapes_string_per_rfc8785(): void
    {
        $this->assertSame('"hello"', JcsEncoder::encode('hello'));
        $this->assertSame('"with \\"quote\\""', JcsEncoder::encode('with "quote"'));
        $this->assertSame('"tab\\there"', JcsEncoder::encode("tab\there"));
        $this->assertSame('"newline\\nhere"', JcsEncoder::encode("newline\nhere"));
        $this->assertSame('"\\u0001"', JcsEncoder::encode("\x01"));
    }

    public function test_rejects_invalid_utf8(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        JcsEncoder::encode("\xC3\x28"); // invalid 2-byte sequence
    }

    public function test_key_ordering_uses_utf16_code_units(): void
    {
        // RFC 8785: sort by UTF-16 code units. For BMP chars this matches Unicode
        // code-point order; we test a mixed ASCII + 2-byte UTF-8 char ('é' = U+00E9).
        $input = ['é' => 1, 'a' => 2];
        $this->assertSame('{"a":2,"é":1}', JcsEncoder::encode($input));
    }
}
