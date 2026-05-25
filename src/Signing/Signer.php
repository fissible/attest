<?php
declare(strict_types=1);

namespace Fissible\Attest\Signing;

interface Signer
{
    public function keyId(): string;

    /** Returns a 64-byte Ed25519 signature. */
    public function sign(string $message): string;
}
