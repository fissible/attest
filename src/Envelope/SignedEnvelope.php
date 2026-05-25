<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

use Fissible\Attest\Canonical\JcsEncoder;
use Fissible\Attest\Signing\Signer;
use ParagonIE\ConstantTime\Base64;

/**
 * Signed envelope = unsigned envelope + Ed25519 signature.
 *
 * Two canonical byte forms (spec §5):
 *   - unsignedCanonicalBytes: the signed input to Ed25519
 *   - signedCanonicalBytes:   unsigned object + sig, used for self_hash /
 *                             prev_hash linking / storage
 */
final readonly class SignedEnvelope
{
    public function __construct(
        public EvidenceEnvelope $envelope,
        public string $sig,            // raw 64-byte signature
    ) {
    }

    public static function sign(EvidenceEnvelope $envelope, Signer $signer): self
    {
        if ($envelope->keyId !== $signer->keyId()) {
            throw new \LogicException(
                "Envelope key_id '{$envelope->keyId}' does not match signer key_id '{$signer->keyId()}'"
            );
        }
        $unsignedBytes = JcsEncoder::encode($envelope->toUnsignedArray());
        $sig = $signer->sign($unsignedBytes);
        return new self($envelope, $sig);
    }

    public function unsignedCanonicalBytes(): string
    {
        return JcsEncoder::encode($this->envelope->toUnsignedArray());
    }

    public function signedCanonicalBytes(): string
    {
        $arr = $this->envelope->toUnsignedArray();
        $arr['sig'] = 'base64:' . Base64::encode($this->sig);
        return JcsEncoder::encode($arr);
    }

    public function selfHash(): string
    {
        return bin2hex(hash('sha256', $this->signedCanonicalBytes(), binary: true));
    }
}
