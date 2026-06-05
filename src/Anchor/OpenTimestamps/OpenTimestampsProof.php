<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

use Fissible\Attest\Anchor\ProofState;

final readonly class OpenTimestampsProof
{
    public function __construct(
        public string $fileDigest,
        public OpenTimestampsTimestamp $timestamp,
    ) {
        if (strlen($fileDigest) !== 32) {
            throw new \InvalidArgumentException('OpenTimestamps file digest must be 32 bytes');
        }
        if ($timestamp->message !== $fileDigest) {
            throw new \InvalidArgumentException('timestamp root message must equal file digest');
        }
    }

    public static function fromRootHex(string $rootHex): self
    {
        if (! preg_match('/\A[0-9a-f]{64}\z/', $rootHex)) {
            throw new \InvalidArgumentException('rootHex must be a lower-case 64-character hex SHA-256 digest');
        }

        $digest = hex2bin($rootHex);
        if ($digest === false) {
            throw new \InvalidArgumentException('rootHex is not valid hex');
        }

        return new self($digest, new OpenTimestampsTimestamp($digest));
    }

    public function fileDigestHex(): string
    {
        return bin2hex($this->fileDigest);
    }

    public function state(): ProofState
    {
        $hasPending = false;
        foreach ($this->timestamp->allAttestations() as $entry) {
            if ($entry->attestation->isBitcoin()) {
                return ProofState::UPGRADED;
            }
            if ($entry->attestation->isPending()) {
                $hasPending = true;
            }
        }

        return $hasPending ? ProofState::PENDING : ProofState::SUBMITTED;
    }

    public function assertFileDigestHex(string $expectedRootHex): void
    {
        if ($this->fileDigestHex() !== $expectedRootHex) {
            throw new \InvalidArgumentException('OpenTimestamps file digest does not match expected root');
        }
    }
}
