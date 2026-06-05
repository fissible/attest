<?php
declare(strict_types=1);

namespace Fissible\Attest\Merkle;

final class MerkleTree
{
    public const ALGORITHM = 'sha256-rfc6962';

    /**
     * @param iterable<string> $leaves signed canonical envelope bytes
     */
    public static function rootHex(iterable $leaves): string
    {
        return bin2hex(self::root($leaves));
    }

    /**
     * @param iterable<string> $leaves signed canonical envelope bytes
     */
    public static function root(iterable $leaves): string
    {
        $level = [];
        foreach ($leaves as $leaf) {
            if (! is_string($leaf)) {
                throw new \InvalidArgumentException('Merkle leaves must be strings');
            }
            $level[] = self::leafHash($leaf);
        }

        if ($level === []) {
            throw new \InvalidArgumentException('Merkle tree requires at least one leaf');
        }

        while (count($level) > 1) {
            $next = [];
            $count = count($level);
            for ($i = 0; $i < $count; $i += 2) {
                if ($i + 1 === $count) {
                    $next[] = $level[$i];
                    continue;
                }
                $next[] = self::nodeHash($level[$i], $level[$i + 1]);
            }
            $level = $next;
        }

        return $level[0];
    }

    public static function leafHashHex(string $bytes): string
    {
        return bin2hex(self::leafHash($bytes));
    }

    public static function leafHash(string $bytes): string
    {
        return hash('sha256', "\x00" . $bytes, binary: true);
    }

    public static function nodeHashHex(string $leftHash, string $rightHash): string
    {
        return bin2hex(self::nodeHash($leftHash, $rightHash));
    }

    public static function nodeHash(string $leftHash, string $rightHash): string
    {
        self::assertBinarySha256($leftHash, 'left hash');
        self::assertBinarySha256($rightHash, 'right hash');

        return hash('sha256', "\x01" . $leftHash . $rightHash, binary: true);
    }

    private static function assertBinarySha256(string $hash, string $label): void
    {
        if (strlen($hash) !== 32) {
            throw new \InvalidArgumentException("$label must be a 32-byte binary SHA-256 hash");
        }
    }
}

