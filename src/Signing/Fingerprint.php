<?php
declare(strict_types=1);

namespace Fissible\Attest\Signing;

final class Fingerprint
{
    /**
     * Compute the sha256 fingerprint of a raw 32-byte Ed25519 public key.
     * Returns 64 lowercase hex chars. Per spec §12: the hash is always over
     * the raw decoded bytes, never over base64 representations.
     */
    public static function of(string $rawPublicKey): string
    {
        if (strlen($rawPublicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new \InvalidArgumentException(
                'Public key must be ' . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . ' raw bytes'
            );
        }
        return bin2hex(hash('sha256', $rawPublicKey, binary: true));
    }
}
