<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;

/**
 * Stable v1 JSON schema for `attest *` commands that produce a
 * VerificationResult. Field names are pinned; future versions may add
 * fields but must not change existing meanings without a format-version bump.
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
            'signature_summary' => self::signatureSummary($result),
            'anchor_verification' => self::anchorSummary($result),
            'warnings' => array_map(
                static fn ($w) => ['code' => $w->code, 'message' => $w->message, 'context' => $w->context],
                $result->warnings,
            ),
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
