<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

/**
 * @experimental
 */
interface AnchorClaimStore
{
    /**
     * Atomically takes the claim for $anchorId. Returns false when another
     * worker already holds it. Side-effecting: a second call after a
     * release() may succeed.
     *
     * @phpstan-impure
     */
    public function claim(string $anchorId, AnchorClaim $details): bool;

    public function release(string $anchorId): void;

    public function complete(string $anchorId, string $envelopeId): void;

    /**
     * @return iterable<string, AnchorClaim> anchor_id => claim
     */
    public function reclaimExpired(int $ttlSeconds): iterable;
}

