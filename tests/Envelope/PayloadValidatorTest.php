<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Envelope\Binary;
use Fissible\Attest\Envelope\InvalidPayload;
use Fissible\Attest\Envelope\PayloadValidator;
use PHPUnit\Framework\TestCase;

final class PayloadValidatorTest extends TestCase
{
    public function test_accepts_basic_scalars(): void
    {
        $v = PayloadValidator::ensure(['s' => 'x', 'i' => 42, 'b' => true, 'n' => null]);
        $this->assertSame(['s' => 'x', 'i' => 42, 'b' => true, 'n' => null], $v);
    }

    public function test_accepts_nested_arrays_and_objects(): void
    {
        $input = ['outer' => ['list' => [1, 2, 3], 'map' => ['k' => 'v']]];
        $this->assertSame($input, PayloadValidator::ensure($input));
    }

    public function test_rejects_floats(): void
    {
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('float at path: n');
        PayloadValidator::ensure(['n' => 1.5]);
    }

    public function test_rejects_integers_outside_js_safe_range(): void
    {
        $this->expectException(InvalidPayload::class);
        PayloadValidator::ensure(['n' => PHP_INT_MAX]);
    }

    public function test_accepts_integers_at_js_safe_boundary(): void
    {
        $max = 9007199254740991;  // 2^53 - 1
        $min = -9007199254740991;
        PayloadValidator::ensure(['hi' => $max, 'lo' => $min]);
        $this->expectNotToPerformAssertions();
    }

    public function test_rejects_datetime_objects(): void
    {
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('DateTime');
        PayloadValidator::ensure(['t' => new \DateTimeImmutable()]);
    }

    public function test_rejects_resources(): void
    {
        $r = fopen('php://memory', 'r');
        $this->assertNotFalse($r);
        try {
            $this->expectException(InvalidPayload::class);
            PayloadValidator::ensure(['r' => $r]);
        } finally {
            fclose($r);
        }
    }

    public function test_rejects_invalid_utf8_strings(): void
    {
        $this->expectException(InvalidPayload::class);
        PayloadValidator::ensure(['s' => "\xC3\x28"]);
    }

    public function test_rejects_non_string_object_keys(): void
    {
        // Mixed int+string keys = neither pure list nor pure string-keyed map.
        $input = [0 => 'a', 'x' => 'b'];
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('mixed keys');
        PayloadValidator::ensure($input);
    }

    public function test_accepts_binary_wrapper(): void
    {
        $result = PayloadValidator::ensure(['b' => Binary::ofBase64('aGVsbG8=')]);
        $this->assertInstanceOf(Binary::class, $result['b']);
        $this->assertSame('aGVsbG8=', $result['b']->base64);
    }

    public function test_rejects_binary_over_size_cap(): void
    {
        $big = str_repeat('x', 65 * 1024); // 65KB
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('Binary exceeds 64KB');
        PayloadValidator::ensure(['b' => Binary::ofRaw($big)]);
    }

    public function test_total_canonical_size_cap(): void
    {
        $big = ['s' => str_repeat('x', 70 * 1024)];
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('exceeds 64KB');
        PayloadValidator::ensure($big);
    }
}
