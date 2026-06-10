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
 *
 * Spec §5.3: total signed canonical envelope size ≤ 64KB.
 * MAX_SIGNED_ENVELOPE_BYTES is the authoritative cap; it is enforced at
 * sign() time and at EnvelopeCodec::decodeSigned() entry. The payload-only
 * cap in PayloadValidator is a lower sanity ceiling that leaves room for
 * envelope-frame overhead (timestamps, key_id, sig, prev_hash, etc.).
 * @api
 */
final readonly class SignedEnvelope
{
    public const MAX_SIGNED_ENVELOPE_BYTES = 65536;

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
        $candidate = new self($envelope, $sig);
        $signedBytes = $candidate->signedCanonicalBytes();
        if (strlen($signedBytes) > self::MAX_SIGNED_ENVELOPE_BYTES) {
            throw new InvalidPayload(
                'Signed canonical envelope exceeds ' . self::MAX_SIGNED_ENVELOPE_BYTES
                . ' bytes (got ' . strlen($signedBytes) . ')'
            );
        }
        return $candidate;
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
