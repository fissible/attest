<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor\OpenTimestamps;

use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsReadBuffer;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsWriteBuffer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Varuint decoding of untrusted receipt bytes must throw rather than wrap
 * when the encoded value does not fit in a 63-bit non-negative integer.
 */
final class OpenTimestampsVaruintTest extends TestCase
{
    protected function setUp(): void
    {
        // The read/write buffers are declared alongside the codec, not in
        // their own PSR-4 files; loading the codec makes them available.
        class_exists(OpenTimestampsCodec::class);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function overflowingVaruints(): iterable
    {
        // 10th byte lands at shift 63: previously wrapped to PHP_INT_MIN.
        yield 'ten bytes, low bit set' => [str_repeat("\x80", 9) . "\x01"];
        // 10th byte lands at shift 63: previously wrapped to 0 (a valid height).
        yield 'ten bytes, bit 1 set' => [str_repeat("\x80", 9) . "\x02"];
        // Eleven bytes can never fit.
        yield 'eleven bytes' => [str_repeat("\x80", 10) . "\x01"];
        // Non-minimal: a continuation byte followed by a zero terminator.
        yield 'non-minimal trailing zero' => ["\x80\x00"];
    }

    #[DataProvider('overflowingVaruints')]
    public function test_bitcoin_attestation_rejects_overflowing_height(string $payload): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('varuint');
        OpenTimestampsAttestation::fromPayload(OpenTimestampsAttestation::TAG_BITCOIN, $payload);
    }

    #[DataProvider('overflowingVaruints')]
    public function test_read_buffer_rejects_overflowing_varuint(string $bytes): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('varuint');
        (new OpenTimestampsReadBuffer($bytes))->readVaruint();
    }

    public function test_bitcoin_attestation_height_round_trips(): void
    {
        $encoded = OpenTimestampsAttestation::bitcoin(840000);
        $decoded = OpenTimestampsAttestation::fromPayload(OpenTimestampsAttestation::TAG_BITCOIN, $encoded->payload);

        $this->assertSame(840000, $decoded->height);
    }

    public function test_read_buffer_varuint_round_trips_large_values(): void
    {
        foreach ([0, 1, 127, 128, 840000, PHP_INT_MAX] as $value) {
            $writer = new OpenTimestampsWriteBuffer();
            $writer->writeVaruint($value);

            $this->assertSame($value, (new OpenTimestampsReadBuffer($writer->bytes()))->readVaruint(), "value $value");
        }
    }
}
