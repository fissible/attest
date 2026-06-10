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
     * @return iterable<string>
     */
    public function readRawRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable;
}

