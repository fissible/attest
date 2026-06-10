<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Canonical\JcsEncoder;

/**
 * @experimental
 */
final class AnchorId
{
    private const DOMAIN = 'attest-anchor-v1';

    public static function derive(AnchorTarget $target, string $driver): string
    {
        return self::deriveFromParts(
            chainId: $target->chainId,
            fromSeq: $target->fromSeq,
            toSeq: $target->toSeq,
            driver: $driver,
            rootHex: $target->rootHex,
        );
    }

    public static function deriveFromParts(
        string $chainId,
        int $fromSeq,
        int $toSeq,
        string $driver,
        string $rootHex,
    ): string {
        if ($chainId === '') {
            throw new \InvalidArgumentException('chainId must not be empty');
        }
        if ($fromSeq < 1) {
            throw new \InvalidArgumentException('fromSeq must be >= 1');
        }
        if ($toSeq < $fromSeq) {
            throw new \InvalidArgumentException('toSeq must be >= fromSeq');
        }
        if ($driver === '') {
            throw new \InvalidArgumentException('driver must not be empty');
        }
        if (! preg_match('/\A[0-9a-f]{64}\z/', $rootHex)) {
            throw new \InvalidArgumentException('rootHex must be a lower-case 64-character hex SHA-256 digest');
        }

        return bin2hex(hash(
            'sha256',
            JcsEncoder::encode([self::DOMAIN, $chainId, $fromSeq, $toSeq, $driver, $rootHex]),
            binary: true,
        ));
    }
}
