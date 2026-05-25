<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

use Fissible\Attest\Envelope\SignedEnvelope;

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

    public function tail(string $chainId): ?SignedEnvelope;

    /** @return iterable<SignedEnvelope> */
    public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable;

    /** @return iterable<string> chain IDs */
    public function listChains(): iterable;

    public function exists(string $chainId): bool;
}
