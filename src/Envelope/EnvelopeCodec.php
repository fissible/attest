<?php
declare(strict_types=1);

namespace Fissible\Attest\Envelope;

use ParagonIE\ConstantTime\Base64;

final class EnvelopeCodec
{
    public static function decodeSigned(string $signedCanonicalBytes): SignedEnvelope
    {
        try {
            $arr = json_decode($signedCanonicalBytes, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \InvalidArgumentException(
                'Envelope is not valid JSON: ' . $e->getMessage(),
                previous: $e,
            );
        }
        if (! is_array($arr)) {
            throw new \InvalidArgumentException('Envelope JSON root must be an object');
        }
        foreach (['v', 'id', 'chain', 'seq', 'ts', 'type', 'payload', 'key_id', 'sig_alg', 'sig'] as $required) {
            if (! array_key_exists($required, $arr)) {
                throw new \InvalidArgumentException("Envelope missing field: $required");
            }
        }
        $sigRaw = $arr['sig'];
        if (! is_string($sigRaw) || ! str_starts_with($sigRaw, 'base64:')) {
            throw new \InvalidArgumentException("Envelope 'sig' must be a base64-prefixed string");
        }
        $sig = Base64::decode(substr($sigRaw, 7), strictPadding: true);

        $envelope = new EvidenceEnvelope(
            id: $arr['id'],
            chain: $arr['chain'],
            seq: $arr['seq'],
            ts: $arr['ts'],
            type: $arr['type'],
            payload: $arr['payload'],
            prevHash: array_key_exists('prev_hash', $arr) ? $arr['prev_hash'] : null,
            keyId: $arr['key_id'],
            sigAlg: $arr['sig_alg'],
            subject: $arr['subject'] ?? null,
            correlation: $arr['correlation'] ?? null,
            tenant: $arr['tenant'] ?? null,
        );
        return new SignedEnvelope($envelope, $sig);
    }
}
