<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

/**
 * Unsigned envelope value object (spec §5.1).
 *
 * The fields here are what get RFC 8785-canonicalized and signed by Ed25519.
 * The resulting signature is added in SignedEnvelope.
 */
final readonly class EvidenceEnvelope
{
    public int $v;

    /**
     * @param array<array-key, mixed> $payload
     */
    public function __construct(
        public string $id,
        public string $chain,
        public int $seq,
        public string $ts,
        public string $type,
        public array $payload,
        public ?string $prevHash,
        public string $keyId,
        public string $sigAlg,
        public ?string $subject = null,
        public ?string $correlation = null,
        public ?string $tenant = null,
    ) {
        $this->v = 1;
        if ($seq < 1) {
            throw new \InvalidArgumentException('seq must be >= 1');
        }
    }

    /**
     * Build the array form that is RFC 8785-canonicalized to produce the
     * unsigned canonical bytes. Authoring order here is purely semantic;
     * JCS sorts keys at encode time.
     *
     * @return array<string, mixed>
     */
    public function toUnsignedArray(): array
    {
        $arr = [
            'v' => $this->v,
            'id' => $this->id,
            'chain' => $this->chain,
            'seq' => $this->seq,
            'ts' => $this->ts,
            'type' => $this->type,
            'payload' => $this->payload,
            'prev_hash' => $this->prevHash,
            'key_id' => $this->keyId,
            'sig_alg' => $this->sigAlg,
        ];
        if ($this->subject !== null) {
            $arr['subject'] = $this->subject;
        }
        if ($this->correlation !== null) {
            $arr['correlation'] = $this->correlation;
        }
        if ($this->tenant !== null) {
            $arr['tenant'] = $this->tenant;
        }
        return $arr;
    }
}
