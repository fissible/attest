<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Signing;

use Fissible\Attest\Signing\Fingerprint;
use Fissible\Attest\Signing\KeyPair;
use PHPUnit\Framework\TestCase;

final class FingerprintTest extends TestCase
{
    public function test_fingerprint_is_64_hex_chars(): void
    {
        $kp = KeyPair::generate();
        $fp = Fingerprint::of($kp->publicKey);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $fp);
    }

    public function test_fingerprint_is_deterministic(): void
    {
        $kp = KeyPair::generate();
        $this->assertSame(Fingerprint::of($kp->publicKey), Fingerprint::of($kp->publicKey));
    }

    public function test_fingerprint_is_over_raw_bytes_not_base64(): void
    {
        // Per spec §12: fingerprint = sha256(raw 32-byte pubkey), never over base64 text.
        $raw = random_bytes(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
        $expected = bin2hex(hash('sha256', $raw, binary: true));
        $this->assertSame($expected, Fingerprint::of($raw));
    }

    public function test_rejects_wrong_size_input(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Fingerprint::of('not a real public key');
    }
}
