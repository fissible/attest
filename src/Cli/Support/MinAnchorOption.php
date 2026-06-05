<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Anchor\AnchorOutcome;

final class MinAnchorOption
{
    public static function parse(?string $raw): ?AnchorOutcome
    {
        if ($raw === null) {
            return null;
        }
        return match (strtolower(trim($raw))) {
            'local_only' => AnchorOutcome::LOCAL_ONLY,
            'pending' => AnchorOutcome::PENDING,
            'upgraded_no_headers' => AnchorOutcome::UPGRADED_NO_HEADERS,
            'remote_header_confirmed' => AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            'bitcoin_verified' => AnchorOutcome::BITCOIN_VERIFIED,
            default => throw new \InvalidArgumentException(
                "Invalid --min-anchor value: $raw (allowed: local_only, pending, upgraded_no_headers, remote_header_confirmed, bitcoin_verified)"
            ),
        };
    }
}
