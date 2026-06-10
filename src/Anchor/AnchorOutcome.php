<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

/**
 * @api
 */
enum AnchorOutcome: string
{
    case LOCAL_ONLY = 'local_only';
    case PENDING = 'pending';
    case UPGRADED_NO_HEADERS = 'upgraded_no_headers';
    case REMOTE_HEADER_CONFIRMED = 'remote_header_confirmed';
    case BITCOIN_VERIFIED = 'bitcoin_verified';
    case PROVIDER_DISAGREEMENT = 'provider_disagreement';
    case INVALID = 'invalid';

    public function isRanked(): bool
    {
        return match ($this) {
            self::LOCAL_ONLY,
            self::PENDING,
            self::UPGRADED_NO_HEADERS,
            self::REMOTE_HEADER_CONFIRMED,
            self::BITCOIN_VERIFIED => true,
            self::PROVIDER_DISAGREEMENT,
            self::INVALID => false,
        };
    }

    public function rank(): int
    {
        return match ($this) {
            self::LOCAL_ONLY => 0,
            self::PENDING => 1,
            self::UPGRADED_NO_HEADERS => 2,
            self::REMOTE_HEADER_CONFIRMED => 3,
            self::BITCOIN_VERIFIED => 4,
            self::PROVIDER_DISAGREEMENT,
            self::INVALID => throw new \LogicException($this->value . ' is not a ranked anchor outcome'),
        };
    }

    public function meets(self $minimum): bool
    {
        return $this->rank() >= $minimum->rank();
    }
}

