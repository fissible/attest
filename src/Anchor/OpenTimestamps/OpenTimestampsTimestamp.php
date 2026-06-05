<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

final readonly class OpenTimestampsTimestamp
{
    /**
     * @param list<OpenTimestampsAttestation> $attestations
     * @param list<OpenTimestampsBranch> $branches
     */
    public function __construct(
        public string $message,
        public array $attestations = [],
        public array $branches = [],
    ) {
        foreach ($attestations as $attestation) {
            if (! $attestation instanceof OpenTimestampsAttestation) {
                throw new \InvalidArgumentException('attestations must contain OpenTimestampsAttestation instances');
            }
        }
        foreach ($branches as $branch) {
            if (! $branch instanceof OpenTimestampsBranch) {
                throw new \InvalidArgumentException('branches must contain OpenTimestampsBranch instances');
            }
        }
    }

    public function withAttestation(OpenTimestampsAttestation $attestation): self
    {
        return new self($this->message, [...$this->attestations, $attestation], $this->branches);
    }

    public function withOperation(OpenTimestampsOperation $operation, self $timestamp): self
    {
        if ($operation->apply($this->message) !== $timestamp->message) {
            throw new \InvalidArgumentException('operation result must equal child timestamp message');
        }

        return new self($this->message, $this->attestations, [
            ...$this->branches,
            new OpenTimestampsBranch($operation, $timestamp),
        ]);
    }

    /**
     * @return list<OpenTimestampsAttestationPath>
     */
    public function allAttestations(): array
    {
        $entries = [];
        foreach ($this->attestations as $attestation) {
            $entries[] = new OpenTimestampsAttestationPath($this->message, $attestation);
        }
        foreach ($this->branches as $branch) {
            array_push($entries, ...$branch->timestamp->allAttestations());
        }

        return $entries;
    }

    public function isEmpty(): bool
    {
        return $this->attestations === [] && $this->branches === [];
    }
}

