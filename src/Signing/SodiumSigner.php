<?php
declare(strict_types=1);

namespace Fissible\Attest\Signing;

final class SodiumSigner implements Signer
{
    public function __construct(
        private readonly KeyPair $keyPair,
        private readonly string $keyId,
    ) {
        if ($keyId === '') {
            throw new \InvalidArgumentException('keyId must not be empty');
        }
    }

    public function keyId(): string
    {
        return $this->keyId;
    }

    public function sign(string $message): string
    {
        return sodium_crypto_sign_detached($message, $this->keyPair->secretKey);
    }
}
