<?php
declare(strict_types=1);

namespace Fissible\Attest\Signing;

/**
 * Ed25519 key material. Secret key is 64 bytes (libsodium concatenates seed +
 * public key for signing efficiency). Public key is 32 bytes.
 */
final readonly class KeyPair
{
    /**
     * @param non-empty-string $secretKey
     * @param non-empty-string $publicKey
     */
    public function __construct(
        public string $secretKey,
        public string $publicKey,
    ) {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \InvalidArgumentException(
                'Secret key must be ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' bytes'
            );
        }
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \InvalidArgumentException(
                'Public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' bytes'
            );
        }
    }

    public static function generate(): self
    {
        $kp = sodium_crypto_sign_keypair();
        return new self(
            secretKey: sodium_crypto_sign_secretkey($kp),
            publicKey: sodium_crypto_sign_publickey($kp),
        );
    }

    public static function fromSeed(string $seed): self
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException(
                'Seed must be ' . SODIUM_CRYPTO_SIGN_SEEDBYTES . ' bytes'
            );
        }
        $kp = sodium_crypto_sign_seed_keypair($seed);
        return new self(
            secretKey: sodium_crypto_sign_secretkey($kp),
            publicKey: sodium_crypto_sign_publickey($kp),
        );
    }
}
