<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

/**
 * Thrown by a ChainStore / RawChainStore when a stored record inside the
 * requested range cannot be decoded into a SignedEnvelope (not JSON, missing
 * or type-mismatched field, malformed signature encoding, ...).
 *
 * $seq is the sequence the record occupies by position (the previous
 * decodable record's seq + 1), or null when the store cannot tell (tail()).
 * The Verifier turns this into INVALID_CHAIN at that sequence rather than
 * letting the underlying decode exception escape.
 * @api
 */
final class UndecodableRecord extends \RuntimeException
{
    public function __construct(
        public readonly string $chainId,
        public readonly ?int $seq,
        public readonly string $reason,
        ?\Throwable $previous = null,
    ) {
        parent::__construct(
            sprintf(
                'Stored record %s in chain %s could not be decoded: %s',
                $seq === null ? 'at tail' : "at sequence $seq",
                $chainId,
                $reason,
            ),
            previous: $previous,
        );
    }

    public static function wrap(string $chainId, ?int $seq, \Throwable $e): self
    {
        return new self($chainId, $seq, $e->getMessage(), $e);
    }
}
