<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;

/**
 * Stable v1 JSON schema for `attest *` commands that produce a
 * VerificationResult. Field names are pinned; future versions may add
 * fields but must not change existing meanings without a format-version bump.
 * @internal
 */
final class JsonResultSchema
{
    public const FORMAT = 'attest.cli.result.v1';

    /** @return array<string,mixed> */
    public static function fromVerification(string $command, VerificationResult $result, int $exitCode): array
    {
        return [
            'format_version' => self::FORMAT,
            'command' => $command,
            'outcome' => $result->outcome->value,
            'verified' => $result->outcome->value === 'verified',
            'exit_code' => $exitCode,
            'message' => $result->message,
            'broken_at_seq' => $result->brokenAtSeq,
            'chain_stats' => [
                'chain_id' => $result->chainStats->chainId,
                'from_seq' => $result->chainStats->fromSeq,
                'to_seq' => $result->chainStats->toSeq,
                'envelope_count' => $result->chainStats->envelopeCount,
                'trusted_signatures' => $result->chainStats->trustedSignatureCount,
                'untrusted_signatures' => $result->chainStats->untrustedSignatureCount,
                'anchor_envelopes' => $result->chainStats->anchorEnvelopeCount,
            ],
            'completeness' => self::completeness(),
            'signature_summary' => self::signatureSummary($result),
            'anchor_verification' => self::anchorSummary($result),
            'warnings' => array_map(
                static fn ($w) => ['code' => $w->code, 'message' => $w->message, 'context' => $w->context],
                $result->warnings,
            ),
        ];
    }

    /**
     * What a passing verification does not establish.
     *
     * A chain attests the integrity of the entries written to it. It cannot attest that those entries are
     * every event that occurred, because anything that bypassed instrumentation never reached the chain to
     * be signed. Documentation states this; the JSON did not, and an automated consumer reading
     * `verified: true` has no other place to learn it.
     *
     * Constant rather than computed, deliberately: attest cannot detect a bypassed path, and a value that
     * varied with the outcome would imply it had looked.
     *
     * @return array{asserted:bool,statement:string}
     */
    private static function completeness(): array
    {
        return [
            'asserted' => false,
            'statement' => 'Attests the integrity of recorded entries, not that they are all events. '
                .'Anything that bypassed instrumentation is invisible to this record.',
        ];
    }

    /** @return array<string,mixed> */
    private static function signatureSummary(VerificationResult $result): array
    {
        $byKey = [];
        foreach ($result->signatureResults as $sr) {
            if (! $sr->hasTrustedMatch()) {
                continue;
            }
            foreach ($sr->matches as $m) {
                $id = $m->key->keyId ?? $m->key->fingerprint;
                $byKey[$id] ??= 0;
                $byKey[$id]++;
            }
        }
        return [
            'trusted_keys_matched' => $byKey,
        ];
    }

    /** @return array<string,mixed>|null */
    private static function anchorSummary(VerificationResult $result): ?array
    {
        $av = $result->anchorVerification;
        if ($av === null) {
            return null;
        }
        return [
            'outcome' => $av->outcome->value,
            'provider' => $av->providerName,
            'message' => $av->message,
            'context' => $av->context,
        ];
    }
}
