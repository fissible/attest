<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Verification\TrustedKey;
use ParagonIE\ConstantTime\Base64;

/**
 * @internal
 */
final class TrustedKeyLoader
{
    /**
     * @param list<string> $inline   each entry is "<key_id>=<base64-pubkey>"
     * @param list<string> $files    each entry is "[<key_id>=]<path>" to a .pub file containing a base64 pubkey
     * @return list<TrustedKey>
     */
    public static function load(array $inline, array $files): array
    {
        $keys = [];
        foreach ($inline as $entry) {
            if (! str_contains($entry, '=')) {
                throw new \InvalidArgumentException("Invalid --trusted-key entry: $entry (expected '<key_id>=<base64-pubkey>'; to load a key from a .pub file use --trusted-key-file [<key_id>=]<path>)");
            }
            [$keyId, $b64] = explode('=', $entry, 2);
            $keys[] = new TrustedKey(self::decodePubkey($b64), keyId: $keyId);
        }
        foreach ($files as $entry) {
            [$keyId, $path] = self::parseFileEntry($entry);
            if (! is_file($path)) {
                throw new \InvalidArgumentException("Trusted-key file not found: $path");
            }
            $b64 = trim((string) file_get_contents($path));
            $keys[] = new TrustedKey(self::decodePubkey($b64), keyId: $keyId);
        }
        return $keys;
    }

    private static function decodePubkey(string $b64): string
    {
        try {
            $raw = Base64::decode($b64, strictPadding: true);
        } catch (\Throwable $e) {
            throw new \InvalidArgumentException('Trusted public key must be strict base64', previous: $e);
        }
        if (strlen($raw) !== 32) {
            throw new \InvalidArgumentException('Trusted public key must decode to 32 bytes');
        }
        return $raw;
    }

    /**
     * @return array{0:?string,1:string}
     */
    private static function parseFileEntry(string $entry): array
    {
        if (str_contains($entry, '=')) {
            [$keyId, $path] = explode('=', $entry, 2);
            $keyId = trim($keyId);
            $path = trim($path);

            if ($keyId === '') {
                throw new \InvalidArgumentException('Trusted-key file key_id must not be empty');
            }
            if ($path === '') {
                throw new \InvalidArgumentException('Trusted-key file path must not be empty');
            }

            return [$keyId, $path];
        }

        $path = trim($entry);
        if ($path === '') {
            throw new \InvalidArgumentException('Trusted-key file path must not be empty');
        }

        return [null, $path];
    }
}
