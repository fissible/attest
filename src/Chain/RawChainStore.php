<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

/**
 * @api
 */
interface RawChainStore
{
    /**
     * Yields stored canonical envelope record bytes for [fromSeq, toSeq] in seq order.
     *
     * Each yielded string must equal SignedEnvelope::signedCanonicalBytes() for that
     * envelope and must not contain a trailing newline or any other framing byte.
     *
     * A stored record inside the requested range that cannot be decoded must
     * surface as UndecodableRecord (see ChainStore::readRange()); the Verifier
     * also tolerates raw bytes it cannot decode itself, but a store that knows
     * the record is broken should say so with the positional sequence.
     *
     * @return iterable<string>
     * @throws UndecodableRecord
     */
    public function readRawRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable;
}

