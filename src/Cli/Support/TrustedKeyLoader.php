<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Verification\TrustedKey;
use ParagonIE\ConstantTime\Base64;

final class TrustedKeyLoader
{
    /**
     * @param list<string> $inline   each entry is "<key_id>=<base64-pubkey>"
     * @param list<string> $files    paths to .pub files containing base64 pubkeys
     * @return list<TrustedKey>
     */
    public static function load(array $inline, array $files): array
    {
        $keys = [];
        foreach ($inline as $entry) {
            if (! str_contains($entry, '=')) {
                throw new \InvalidArgumentException("Invalid --trusted-key entry: $entry (expected '<key_id>=<base64>')");
            }
            [$keyId, $b64] = explode('=', $entry, 2);
            $keys[] = new TrustedKey(self::decodePubkey($b64), keyId: $keyId);
        }
        foreach ($files as $path) {
            if (! is_file($path)) {
                throw new \InvalidArgumentException("Trusted-key file not found: $path");
            }
            $b64 = trim((string) file_get_contents($path));
            $keys[] = new TrustedKey(self::decodePubkey($b64));
        }
        return $keys;
    }

    private static function decodePubkey(string $b64): string
    {
        $raw = Base64::decode($b64, strictPadding: true);
        if (strlen($raw) !== 32) {
            throw new \InvalidArgumentException('Trusted public key must decode to 32 bytes');
        }
        return $raw;
    }
}
