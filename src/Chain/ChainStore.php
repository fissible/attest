<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

use Fissible\Attest\Envelope\SignedEnvelope;

/**
 * @api
 */
interface ChainStore
{
    /**
     * Atomically append a new envelope to the named chain.
     *
     * The store reads the current tail, builds an AppendContext from it,
     * invokes the callback with that context, validates that the returned
     * envelope's chain/seq/prev_hash/ts exactly match, and persists.
     *
     * @param callable(AppendContext): SignedEnvelope $buildAndSign
     * @throws ContextMismatch       if the callback returned an envelope inconsistent with the context
     * @throws ChainLockUnavailable  if the per-chain lock could not be acquired
     */
    public function append(string $chainId, callable $buildAndSign): SignedEnvelope;

    /**
     * @throws UndecodableRecord if the stored tail record cannot be decoded
     */
    public function tail(string $chainId): ?SignedEnvelope;

    /**
     * Yields decoded envelopes for [fromSeq, toSeq] in seq order.
     *
     * A stored record inside the requested range that cannot be decoded must
     * surface as UndecodableRecord (with the sequence it occupies by position),
     * never as the underlying JSON/type/base64 exception. Records outside the
     * range should not affect the read. The Verifier relies on this to report
     * INVALID_CHAIN at the broken sequence.
     *
     * @return iterable<SignedEnvelope>
     * @throws UndecodableRecord
     */
    public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable;

    /** @return iterable<string> chain IDs */
    public function listChains(): iterable;

    public function exists(string $chainId): bool;
}
