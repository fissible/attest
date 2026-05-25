<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Signing;

use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SignatureVerification;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class SodiumSignerTest extends TestCase
{
    public function test_generates_keypair_with_64_byte_secret_and_32_byte_public(): void
    {
        $kp = KeyPair::generate();
        $this->assertSame(SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, strlen($kp->secretKey));
        $this->assertSame(SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, strlen($kp->publicKey));
    }

    public function test_round_trip_sign_and_verify(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'test-key-1');

        $message = 'attest canonical bytes';
        $signature = $signer->sign($message);

        $this->assertSame(SODIUM_CRYPTO_SIGN_BYTES, strlen($signature));
        $this->assertTrue(SignatureVerification::verify($message, $signature, $kp->publicKey));
    }

    public function test_signature_fails_for_tampered_message(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'test-key-1');
        $sig = $signer->sign('original');
        $this->assertFalse(SignatureVerification::verify('tampered', $sig, $kp->publicKey));
    }

    public function test_signature_fails_for_wrong_public_key(): void
    {
        $kp1 = KeyPair::generate();
        $kp2 = KeyPair::generate();
        $sig = (new SodiumSigner($kp1, 'k1'))->sign('msg');
        $this->assertFalse(SignatureVerification::verify('msg', $sig, $kp2->publicKey));
    }

    public function test_keypair_from_seed_is_deterministic(): void
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $kp1 = KeyPair::fromSeed($seed);
        $kp2 = KeyPair::fromSeed($seed);
        $this->assertSame($kp1->publicKey, $kp2->publicKey);
        $this->assertSame($kp1->secretKey, $kp2->secretKey);
    }

    public function test_keypair_from_seed_rejects_wrong_length(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KeyPair::fromSeed('too short');
    }

    public function test_signer_exposes_key_id(): void
    {
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'station-prod-2026-01');
        $this->assertSame('station-prod-2026-01', $signer->keyId());
    }

    public function test_signer_rejects_empty_key_id(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SodiumSigner(KeyPair::generate(), '');
    }
}
