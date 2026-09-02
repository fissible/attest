<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

/**
 * @experimental
 */
final readonly class OpenTimestampsAttestation
{
    public const TAG_PENDING = "\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";
    public const TAG_BITCOIN = "\x05\x88\x96\x0d\x73\xd7\x19\x01";
    public const TAG_SIZE = 8;
    public const MAX_PAYLOAD_SIZE = 8192;
    public const MAX_PENDING_URI_SIZE = 1000;

    private function __construct(
        public string $tag,
        public string $payload,
        public ?string $uri = null,
        public ?int $height = null,
    ) {
        if (strlen($tag) !== self::TAG_SIZE) {
            throw new \InvalidArgumentException('attestation tag must be 8 bytes');
        }
        if (strlen($payload) > self::MAX_PAYLOAD_SIZE) {
            throw new \InvalidArgumentException('attestation payload exceeds max size');
        }
    }

    public static function pending(string $uri): self
    {
        self::assertPendingUri($uri);

        return new self(self::TAG_PENDING, $uri, uri: $uri);
    }

    public static function bitcoin(int $height): self
    {
        if ($height < 0) {
            throw new \InvalidArgumentException('Bitcoin attestation height must be >= 0');
        }

        return new self(self::TAG_BITCOIN, self::encodeVaruint($height), height: $height);
    }

    public static function unknown(string $tag, string $payload): self
    {
        if ($tag === self::TAG_PENDING || $tag === self::TAG_BITCOIN) {
            return self::fromPayload($tag, $payload);
        }

        return new self($tag, $payload);
    }

    public static function fromPayload(string $tag, string $payload): self
    {
        if ($tag === self::TAG_PENDING) {
            self::assertPendingUri($payload);
            return new self($tag, $payload, uri: $payload);
        }

        if ($tag === self::TAG_BITCOIN) {
            $offset = 0;
            $height = self::decodeVaruint($payload, $offset);
            if ($offset !== strlen($payload)) {
                throw new \InvalidArgumentException('Bitcoin attestation payload has trailing bytes');
            }
            return new self($tag, $payload, height: $height);
        }

        return new self($tag, $payload);
    }

    public function isPending(): bool
    {
        return $this->tag === self::TAG_PENDING;
    }

    public function isBitcoin(): bool
    {
        return $this->tag === self::TAG_BITCOIN;
    }

    public function isUnknown(): bool
    {
        return ! $this->isPending() && ! $this->isBitcoin();
    }

    public function compare(self $other): int
    {
        $tagComparison = strcmp($this->tag, $other->tag);
        if ($tagComparison !== 0) {
            return $tagComparison;
        }

        return strcmp($this->payload, $other->payload);
    }

    public function tagHex(): string
    {
        return bin2hex($this->tag);
    }

    private static function assertPendingUri(string $uri): void
    {
        if ($uri === '' || strlen($uri) > self::MAX_PENDING_URI_SIZE) {
            throw new \InvalidArgumentException('pending attestation URI length is invalid');
        }
        if (! preg_match('/\A[A-Za-z0-9.\-_\/:]+\z/', $uri)) {
            throw new \InvalidArgumentException('pending attestation URI contains invalid characters');
        }
    }

    private static function encodeVaruint(int $value): string
    {
        if ($value < 0) {
            throw new \InvalidArgumentException('varuint value must be >= 0');
        }
        if ($value === 0) {
            return "\x00";
        }

        $out = '';
        while ($value !== 0) {
            $byte = $value & 0x7f;
            $value >>= 7;
            if ($value !== 0) {
                $byte |= 0x80;
            }
            $out .= chr($byte);
        }

        return $out;
    }

    private static function decodeVaruint(string $bytes, int &$offset): int
    {
        $value = 0;
        $shift = 0;
        while (true) {
            if ($offset >= strlen($bytes)) {
                throw new \InvalidArgumentException('truncated varuint');
            }

            $byte = ord($bytes[$offset]);
            $offset++;
            // Nine 7-bit groups fill bits 0..62; a tenth group would shift
            // past the sign bit and wrap silently in PHP's signed arithmetic.
            if ($shift > 56) {
                throw new \InvalidArgumentException('varuint is too large');
            }
            if (($byte & 0x80) === 0) {
                if ($byte === 0 && $shift > 0) {
                    throw new \InvalidArgumentException('varuint is not minimally encoded');
                }
                return $value | ($byte << $shift);
            }
            $value |= ($byte & 0x7f) << $shift;
            $shift += 7;
        }
    }
}

