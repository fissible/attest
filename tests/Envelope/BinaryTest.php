<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Envelope\Binary;
use Fissible\Attest\Envelope\InvalidPayload;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class BinaryTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedBase64(): iterable
    {
        yield 'invalid characters' => ['!!!not-base64'];
        yield 'trailing garbage' => ['aGk=x'];
        yield 'length 1 mod 4' => ['aGkx='];
    }

    #[DataProvider('malformedBase64')]
    public function test_of_base64_rejects_malformed_input_as_invalid_payload(string $b64): void
    {
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('not valid base64');
        Binary::ofBase64($b64);
    }

    #[DataProvider('malformedBase64')]
    public function test_raw_rejects_malformed_input_as_invalid_payload(string $b64): void
    {
        $binary = new Binary($b64);
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('not valid base64');
        $binary->raw();
    }

    public function test_of_base64_rejects_non_canonical_encoding(): void
    {
        // Decodes to "hi" but is not what Base64::encode("hi") produces ("aGk=").
        $this->expectException(InvalidPayload::class);
        $this->expectExceptionMessage('not canonical');
        Binary::ofBase64('aGk');
    }

    public function test_of_base64_round_trips_valid_input(): void
    {
        $binary = Binary::ofBase64(base64_encode("\x00\x01hi"));

        $this->assertSame("\x00\x01hi", $binary->raw());
    }
}
