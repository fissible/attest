<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\SignatureVerification;

final class SignatureVerifier
{
    /** @var array<string, list<TrustedKey>> */
    private array $keysByKeyId = [];

    /** @var array<string, TrustedKey> */
    private array $keysByFingerprint = [];

    /**
     * @param iterable<TrustedKey> $trustedKeys
     */
    public function __construct(iterable $trustedKeys)
    {
        foreach ($trustedKeys as $key) {
            if ($key->keyId !== null) {
                $this->keysByKeyId[$key->keyId] ??= [];
                $this->keysByKeyId[$key->keyId][] = $key;
            }

            $this->keysByFingerprint[$key->fingerprint] = $key;
        }
    }

    public function verify(SignedEnvelope $signed): SignatureVerificationResult
    {
        if ($signed->envelope->sigAlg !== 'ed25519') {
            return SignatureVerificationResult::unsupportedAlgorithm($signed->envelope->sigAlg);
        }

        $candidateKeys = $this->candidateKeys($signed->envelope->keyId);
        if ($candidateKeys === []) {
            return SignatureVerificationResult::untrusted(
                "No trusted key matched key_id or fingerprint: {$signed->envelope->keyId}",
            );
        }

        $matches = [];
        foreach ($candidateKeys as $candidate) {
            if (! SignatureVerification::verify($signed->unsignedCanonicalBytes(), $signed->sig, $candidate->key->publicKey)) {
                continue;
            }

            $matches[] = new KeyMatch($candidate->key, $candidate->matchedBy);
        }

        if ($matches !== []) {
            return SignatureVerificationResult::trusted($matches);
        }

        return SignatureVerificationResult::invalid(
            "Signature did not verify against trusted key_id or fingerprint: {$signed->envelope->keyId}",
        );
    }

    /**
     * @return list<object{key: TrustedKey, matchedBy: string}>
     */
    private function candidateKeys(string $keyId): array
    {
        $candidates = [];
        $seen = [];

        foreach ($this->keysByKeyId[$keyId] ?? [] as $key) {
            $seen[$this->candidateId($key)] = true;
            $candidates[] = (object) [
                'key' => $key,
                'matchedBy' => KeyMatch::MATCHED_BY_KEY_ID,
            ];
        }

        $fingerprintKey = $this->keysByFingerprint[$keyId] ?? null;
        if ($fingerprintKey !== null && ! isset($seen[$this->candidateId($fingerprintKey)])) {
            $candidates[] = (object) [
                'key' => $fingerprintKey,
                'matchedBy' => KeyMatch::MATCHED_BY_FINGERPRINT,
            ];
        }

        return $candidates;
    }

    private function candidateId(TrustedKey $key): string
    {
        return ($key->keyId ?? '') . "\0" . $key->fingerprint;
    }
}
