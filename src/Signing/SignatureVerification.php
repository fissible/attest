<?php
declare(strict_types=1);

namespace Fissible\Attest\Signing;

final class SignatureVerification
{
    public static function verify(string $message, string $signature, string $publicKey): bool
    {
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }
}
