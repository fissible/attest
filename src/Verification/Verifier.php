<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorDriver;
use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Merkle\MerkleTree;

final class Verifier
{
    /** @var array<string, AnchorDriver> */
    private array $anchorDrivers = [];

    /**
     * @param iterable<AnchorDriver> $anchorDrivers
     */
    public function __construct(
        private readonly ChainStore $store,
        private readonly SignatureVerifier $signatures,
        private readonly VerificationPolicy $policy = new VerificationPolicy(),
        iterable $anchorDrivers = [],
        private readonly HeaderProviderSet $headers = new HeaderProviderSet(),
    ) {
        foreach ($anchorDrivers as $driver) {
            $this->anchorDrivers[$driver->name()] = $driver;
        }
    }

    public function verifyChain(string $chainId, int $fromSeq = 1, ?int $toSeq = null): VerificationResult
    {
        if ($fromSeq < 1) {
            throw new \InvalidArgumentException('fromSeq must be >= 1');
        }
        if ($toSeq !== null && $toSeq < $fromSeq) {
            throw new \InvalidArgumentException('toSeq must be >= fromSeq');
        }

        $warnings = [];
        $previousHash = null;
        if ($fromSeq > 1) {
            $previousRecord = $this->readSingleRecord($chainId, $fromSeq - 1, $warnings);
            if ($previousRecord === null) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    0,
                    0,
                    0,
                    0,
                    $warnings,
                    [],
                    $fromSeq,
                    'Missing previous envelope at sequence ' . ($fromSeq - 1),
                );
            }
            if ($previousRecord->rawBytes !== null
                && $previousRecord->rawBytes !== $previousRecord->signed->signedCanonicalBytes()
            ) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    0,
                    0,
                    0,
                    0,
                    $warnings,
                    [],
                    $fromSeq - 1,
                    'Stored previous envelope bytes are not signed canonical bytes',
                );
            }

            $previousHash = $previousRecord->signed->selfHash();
        }

        $records = $this->readRecords($chainId, $fromSeq, $toSeq, $warnings);
        $expectedSeq = $fromSeq;
        $count = 0;
        $trustedSignatures = 0;
        $untrustedSignatures = 0;
        $anchorEnvelopes = 0;
        $signatureResults = [];
        $canonicalBytes = [];
        $rangeEnvelopes = [];

        foreach ($records as $record) {
            $signed = $record->signed;
            $seq = $signed->envelope->seq;

            if ($record->rawBytes !== null && $record->rawBytes !== $signed->signedCanonicalBytes()) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    $count,
                    $trustedSignatures,
                    $untrustedSignatures,
                    $anchorEnvelopes,
                    $warnings,
                    $signatureResults,
                    $seq,
                    'Stored envelope bytes are not signed canonical bytes',
                );
            }

            if ($signed->envelope->chain !== $chainId) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    $count,
                    $trustedSignatures,
                    $untrustedSignatures,
                    $anchorEnvelopes,
                    $warnings,
                    $signatureResults,
                    $seq,
                    "Envelope chain '{$signed->envelope->chain}' does not match requested chain '$chainId'",
                );
            }

            if ($seq !== $expectedSeq) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    $count,
                    $trustedSignatures,
                    $untrustedSignatures,
                    $anchorEnvelopes,
                    $warnings,
                    $signatureResults,
                    $expectedSeq,
                    "Expected sequence $expectedSeq, found $seq",
                );
            }

            if ($seq === 1 && $signed->envelope->prevHash !== null) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    $count,
                    $trustedSignatures,
                    $untrustedSignatures,
                    $anchorEnvelopes,
                    $warnings,
                    $signatureResults,
                    $seq,
                    'Genesis envelope must have prev_hash=null',
                );
            }

            if ($previousHash !== null && $signed->envelope->prevHash !== $previousHash) {
                return $this->invalidChain(
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    $count,
                    $trustedSignatures,
                    $untrustedSignatures,
                    $anchorEnvelopes,
                    $warnings,
                    $signatureResults,
                    $seq,
                    'Envelope prev_hash does not match previous self hash',
                );
            }

            $signatureResult = $this->signatures->verify($signed);
            $signatureResults[] = $signatureResult;
            if ($signatureResult->invalid) {
                return new VerificationResult(
                    outcome: VerificationOutcome::INVALID_SIGNATURE,
                    stats: new ChainStats(
                        chainId: $chainId,
                        fromSeq: $fromSeq,
                        toSeq: $toSeq,
                        envelopeCount: $count,
                        trustedSignatureCount: $trustedSignatures,
                        untrustedSignatureCount: $untrustedSignatures,
                        anchorEnvelopeCount: $anchorEnvelopes,
                    ),
                    warnings: $warnings,
                    brokenAtSeq: $seq,
                    message: $signatureResult->reason,
                    signatureResults: $signatureResults,
                );
            }

            if ($signatureResult->hasTrustedMatch()) {
                $trustedSignatures++;
            } else {
                $untrustedSignatures++;
            }

            $canonicalBytes[] = $signed->signedCanonicalBytes();
            $rangeEnvelopes[] = $signed;

            if (str_starts_with($signed->envelope->type, 'attest.anchor.')) {
                $anchorEnvelopes++;
            }

            $count++;
            $expectedSeq++;
            $previousHash = $signed->selfHash();
        }

        if ($count === 0) {
            return $this->invalidChain(
                $chainId,
                $fromSeq,
                $toSeq,
                $count,
                $trustedSignatures,
                $untrustedSignatures,
                $anchorEnvelopes,
                $warnings,
                $signatureResults,
                $fromSeq,
                'No envelopes found in requested range',
            );
        }

        if ($toSeq !== null && $expectedSeq <= $toSeq) {
            return $this->invalidChain(
                $chainId,
                $fromSeq,
                $toSeq,
                $count,
                $trustedSignatures,
                $untrustedSignatures,
                $anchorEnvelopes,
                $warnings,
                $signatureResults,
                $expectedSeq,
                "Missing envelope at sequence $expectedSeq",
            );
        }

        $stats = new ChainStats(
            chainId: $chainId,
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            envelopeCount: $count,
            trustedSignatureCount: $trustedSignatures,
            untrustedSignatureCount: $untrustedSignatures,
            anchorEnvelopeCount: $anchorEnvelopes,
        );

        $anchorVerification = null;
        if ($this->policy->minAnchorOutcome !== null) {
            $anchorResult = $this->verifyAnchorPolicy(
                $chainId,
                $fromSeq,
                $toSeq ?? ($fromSeq + $count - 1),
                $canonicalBytes,
                $rangeEnvelopes,
                $stats,
                $warnings,
                $signatureResults,
            );
            if ($anchorResult instanceof VerificationResult) {
                return $anchorResult;
            }
            $anchorVerification = $anchorResult;
            $warnings = [...$warnings, ...$anchorVerification->warnings];
        }

        if ($this->policy->requireTrustedKey && $untrustedSignatures > 0) {
            return new VerificationResult(
                outcome: VerificationOutcome::INTEGRITY_VERIFIED_UNTRUSTED,
                stats: $stats,
                warnings: $warnings,
                message: 'Chain structure is valid, but one or more signatures did not match a trusted key',
                signatureResults: $signatureResults,
                anchorVerification: $anchorVerification,
            );
        }

        return new VerificationResult(
            outcome: VerificationOutcome::VERIFIED,
            stats: $stats,
            warnings: $warnings,
            signatureResults: $signatureResults,
            anchorVerification: $anchorVerification,
        );
    }

    /**
     * @param list<Warning> $warnings
     * @return iterable<object{signed: SignedEnvelope, rawBytes: ?string}>
     */
    private function readRecords(string $chainId, int $fromSeq, ?int $toSeq, array &$warnings): iterable
    {
        if ($this->store instanceof RawChainStore) {
            foreach ($this->store->readRawRange($chainId, $fromSeq, $toSeq) as $rawBytes) {
                yield (object) [
                    'signed' => EnvelopeCodec::decodeSigned($rawBytes),
                    'rawBytes' => $rawBytes,
                ];
            }

            return;
        }

        $this->addNoRawBytesWarning($warnings, $chainId);

        foreach ($this->store->readRange($chainId, $fromSeq, $toSeq) as $signed) {
            yield (object) [
                'signed' => $signed,
                'rawBytes' => null,
            ];
        }
    }

    /**
     * @param list<Warning> $warnings
     * @return ?object{signed: SignedEnvelope, rawBytes: ?string}
     */
    private function readSingleRecord(string $chainId, int $seq, array &$warnings): ?object
    {
        foreach ($this->readRecords($chainId, $seq, $seq, $warnings) as $record) {
            return $record;
        }

        return null;
    }

    /**
     * @param list<Warning> $warnings
     */
    private function addNoRawBytesWarning(array &$warnings, string $chainId): void
    {
        foreach ($warnings as $warning) {
            if ($warning->code === Warning::NO_RAW_BYTES && ($warning->context['chain_id'] ?? null) === $chainId) {
                return;
            }
        }

        $warnings[] = new Warning(
            Warning::NO_RAW_BYTES,
            'Chain store does not expose raw signed envelope bytes; verifier used recomputed canonical bytes.',
            ['chain_id' => $chainId],
        );
    }

    /**
     * @param list<string> $canonicalBytes
     * @param list<SignedEnvelope> $rangeEnvelopes
     * @param list<Warning> $warnings
     * @param list<SignatureVerificationResult> $signatureResults
     */
    private function verifyAnchorPolicy(
        string $chainId,
        int $fromSeq,
        int $toSeq,
        array $canonicalBytes,
        array $rangeEnvelopes,
        ChainStats $stats,
        array $warnings,
        array $signatureResults,
    ): AnchorVerification|VerificationResult {
        $minimum = $this->policy->minAnchorOutcome;
        if ($minimum === null) {
            throw new \LogicException('Anchor policy verification requires minAnchorOutcome');
        }

        $target = new AnchorTarget(
            chainId: $chainId,
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex($canonicalBytes),
        );

        $resolved = (new AnchorSetResolver())->resolve($this->anchorEnvelopesFor($chainId, $toSeq, $rangeEnvelopes));
        $expectedAnchorIds = [];
        foreach (array_keys($this->anchorDrivers) as $driverName) {
            $expectedAnchorIds[] = AnchorId::derive($target, $driverName);
        }

        foreach ($resolved as $group) {
            if (! $group->valid && in_array($group->anchorId, $expectedAnchorIds, true)) {
                return new VerificationResult(
                    outcome: VerificationOutcome::INVALID_ANCHOR,
                    stats: $stats,
                    warnings: $warnings,
                    message: $group->message,
                    signatureResults: $signatureResults,
                );
            }
        }

        $sameRangeDifferentRoot = null;
        $belowMinimum = null;
        foreach ($resolved as $group) {
            if (! $group->valid || $group->receipt === null) {
                continue;
            }

            if ($group->matchesTarget($target)) {
                $driver = $this->anchorDrivers[$group->receipt->driverName] ?? null;
                if ($driver === null) {
                    return new VerificationResult(
                        outcome: VerificationOutcome::INVALID_ANCHOR,
                        stats: $stats,
                        warnings: $warnings,
                        message: 'No anchor driver configured for receipt driver: ' . $group->receipt->driverName,
                        signatureResults: $signatureResults,
                    );
                }

                $verification = $driver->verify($group->receipt, $this->headers);
                if ($verification->outcome === AnchorOutcome::INVALID) {
                    return new VerificationResult(
                        outcome: VerificationOutcome::INVALID_ANCHOR,
                        stats: $stats,
                        warnings: [...$warnings, ...$verification->warnings],
                        message: $verification->message,
                        signatureResults: $signatureResults,
                        anchorVerification: $verification,
                    );
                }

                if ($verification->outcome === AnchorOutcome::PROVIDER_DISAGREEMENT) {
                    if (! $this->policy->allowProviderDisagreement || $verification->strongestPassingOutcome === null) {
                        return new VerificationResult(
                            outcome: VerificationOutcome::PROVIDER_DISAGREEMENT,
                            stats: $stats,
                            warnings: [...$warnings, ...$verification->warnings],
                            message: $verification->message,
                            signatureResults: $signatureResults,
                            anchorVerification: $verification,
                        );
                    }

                    $verification = new AnchorVerification(
                        receipt: $verification->receipt,
                        outcome: $verification->strongestPassingOutcome,
                        warnings: [
                            ...$verification->warnings,
                            new Warning(
                                Warning::PROVIDER_DISAGREEMENT_ALLOWED,
                                'Provider disagreement was allowed by verification policy; using strongest passing provider outcome.',
                                $verification->context,
                            ),
                        ],
                        message: $verification->message,
                        providerName: $verification->providerName,
                        strongestPassingOutcome: $verification->strongestPassingOutcome,
                        context: $verification->context,
                    );
                }

                if (! $verification->outcome->isRanked()
                    || ! $verification->outcome->meets($minimum)
                ) {
                    if ($verification->outcome->isRanked()
                        && ($belowMinimum === null || $verification->outcome->rank() > $belowMinimum->outcome->rank())
                    ) {
                        $belowMinimum = $verification;
                    }

                    continue;
                }

                return $verification;
            }

            if ($group->matchesRange($target)) {
                $sameRangeDifferentRoot = $group;
            }
        }

        if ($sameRangeDifferentRoot instanceof ResolvedAnchor) {
            return new VerificationResult(
                outcome: VerificationOutcome::INVALID_ANCHOR,
                stats: $stats,
                warnings: $warnings,
                message: 'Anchor range exists but root does not match recomputed chain bytes',
                signatureResults: $signatureResults,
            );
        }

        $tilingResult = $this->verifyAnchorTiling(
            $target,
            $resolved,
            $canonicalBytes,
            $stats,
            $warnings,
            $signatureResults,
            $minimum,
        );
        if ($tilingResult instanceof VerificationResult || $tilingResult instanceof AnchorVerification) {
            return $tilingResult;
        }

        if ($belowMinimum instanceof AnchorVerification) {
            return new VerificationResult(
                outcome: VerificationOutcome::ANCHOR_BELOW_MIN,
                stats: $stats,
                warnings: [...$warnings, ...$belowMinimum->warnings],
                message: sprintf(
                    'Anchor outcome %s is below required minimum %s',
                    $belowMinimum->outcome->value,
                    $minimum->value,
                ),
                signatureResults: $signatureResults,
                anchorVerification: $belowMinimum,
            );
        }

        return new VerificationResult(
            outcome: VerificationOutcome::ANCHOR_BELOW_MIN,
            stats: $stats,
            warnings: $warnings,
            message: 'No exact anchor matched requested range and recomputed Merkle root',
            signatureResults: $signatureResults,
        );
    }

    /**
     * @param list<ResolvedAnchor> $resolved
     * @param list<string> $canonicalBytes
     * @param list<Warning> $warnings
     * @param list<SignatureVerificationResult> $signatureResults
     */
    private function verifyAnchorTiling(
        AnchorTarget $target,
        array $resolved,
        array $canonicalBytes,
        ChainStats $stats,
        array $warnings,
        array $signatureResults,
        AnchorOutcome $minimum,
    ): AnchorVerification|VerificationResult|null {
        $ranges = [];
        $verificationsByRange = [];
        $anchorIdsByRange = [];

        foreach ($resolved as $group) {
            if (! $group->valid || $group->receipt === null) {
                continue;
            }

            $receipt = $group->receipt;
            if ($receipt->target->chainId !== $target->chainId
                || $receipt->target->merkleAlgorithm !== $target->merkleAlgorithm
                || $receipt->target->fromSeq < $target->fromSeq
                || $receipt->target->toSeq > $target->toSeq
                || ($receipt->target->fromSeq === $target->fromSeq && $receipt->target->toSeq === $target->toSeq)
            ) {
                continue;
            }

            $expectedRoot = $this->rootForSubRange(
                $canonicalBytes,
                $target->fromSeq,
                $receipt->target->fromSeq,
                $receipt->target->toSeq,
            );
            if ($receipt->target->rootHex !== $expectedRoot) {
                return new VerificationResult(
                    outcome: VerificationOutcome::INVALID_ANCHOR,
                    stats: $stats,
                    warnings: $warnings,
                    message: 'Anchor range exists but root does not match recomputed chain bytes',
                    signatureResults: $signatureResults,
                );
            }

            $driver = $this->anchorDrivers[$receipt->driverName] ?? null;
            if ($driver === null) {
                return new VerificationResult(
                    outcome: VerificationOutcome::INVALID_ANCHOR,
                    stats: $stats,
                    warnings: $warnings,
                    message: 'No anchor driver configured for receipt driver: ' . $receipt->driverName,
                    signatureResults: $signatureResults,
                );
            }

            $verification = $driver->verify($receipt, $this->headers);
            if ($verification->outcome === AnchorOutcome::INVALID) {
                return new VerificationResult(
                    outcome: VerificationOutcome::INVALID_ANCHOR,
                    stats: $stats,
                    warnings: [...$warnings, ...$verification->warnings],
                    message: $verification->message,
                    signatureResults: $signatureResults,
                    anchorVerification: $verification,
                );
            }

            if ($verification->outcome === AnchorOutcome::PROVIDER_DISAGREEMENT) {
                if (! $this->policy->allowProviderDisagreement || $verification->strongestPassingOutcome === null) {
                    return new VerificationResult(
                        outcome: VerificationOutcome::PROVIDER_DISAGREEMENT,
                        stats: $stats,
                        warnings: [...$warnings, ...$verification->warnings],
                        message: $verification->message,
                        signatureResults: $signatureResults,
                        anchorVerification: $verification,
                    );
                }

                $verification = new AnchorVerification(
                    receipt: $verification->receipt,
                    outcome: $verification->strongestPassingOutcome,
                    warnings: [
                        ...$verification->warnings,
                        new Warning(
                            Warning::PROVIDER_DISAGREEMENT_ALLOWED,
                            'Provider disagreement was allowed by verification policy; using strongest passing provider outcome.',
                            $verification->context,
                        ),
                    ],
                    message: $verification->message,
                    providerName: $verification->providerName,
                    strongestPassingOutcome: $verification->strongestPassingOutcome,
                    context: $verification->context,
                );
            }

            if (! $verification->outcome->isRanked()) {
                continue;
            }

            $key = $receipt->target->fromSeq . ':' . $receipt->target->toSeq;
            $ranges[$key] = [
                'from' => $receipt->target->fromSeq,
                'to' => $receipt->target->toSeq,
            ];
            $anchorIdsByRange[$key] ??= [];
            $anchorIdsByRange[$key][] = $group->anchorId;

            if (! isset($verificationsByRange[$key])
                || $verification->outcome->rank() > $verificationsByRange[$key]->outcome->rank()
            ) {
                $verificationsByRange[$key] = $verification;
            }
        }

        if ($ranges === []) {
            return null;
        }

        uasort($ranges, static function (array $a, array $b): int {
            if ($a['from'] !== $b['from']) {
                return $a['from'] <=> $b['from'];
            }

            return $a['to'] <=> $b['to'];
        });

        $previous = null;
        $previousKey = null;
        foreach ($ranges as $key => $range) {
            if ($previous !== null && $range['from'] <= $previous['to']) {
                $overlappingAnchorIds = array_values(array_unique([
                    ...($anchorIdsByRange[$previousKey] ?? []),
                    ...($anchorIdsByRange[$key] ?? []),
                ]));

                return new VerificationResult(
                    outcome: VerificationOutcome::ANCHOR_BELOW_MIN,
                    stats: $stats,
                    warnings: [
                        ...$warnings,
                        new Warning(
                            Warning::ANCHOR_COVERAGE_AMBIGUOUS,
                            'Overlapping anchor ranges prevent deterministic contiguous coverage.',
                            ['anchor_ids' => $overlappingAnchorIds],
                        ),
                    ],
                    message: 'Anchor coverage is ambiguous because ranges overlap',
                    signatureResults: $signatureResults,
                );
            }
            $previous = $range;
            $previousKey = $key;
        }

        $current = $target->fromSeq;
        $lastVerification = null;
        foreach ($ranges as $key => $range) {
            if ($range['to'] < $current) {
                continue;
            }
            if ($range['from'] > $current) {
                return $this->anchorGapResult($target, $stats, $warnings, $signatureResults, $current);
            }

            $verification = $verificationsByRange[$key];
            if (! $verification->outcome->meets($minimum)) {
                return new VerificationResult(
                    outcome: VerificationOutcome::ANCHOR_BELOW_MIN,
                    stats: $stats,
                    warnings: [...$warnings, ...$verification->warnings],
                    message: sprintf(
                        'Anchor outcome %s is below required minimum %s',
                        $verification->outcome->value,
                        $minimum->value,
                    ),
                    signatureResults: $signatureResults,
                    anchorVerification: $verification,
                );
            }

            $lastVerification = $verification;
            $current = $range['to'] + 1;
            if ($current > $target->toSeq) {
                return $lastVerification;
            }
        }

        if ($current <= $target->toSeq) {
            return $this->anchorGapResult($target, $stats, $warnings, $signatureResults, $current);
        }

        return $lastVerification;
    }

    /**
     * @param list<string> $canonicalBytes
     */
    private function rootForSubRange(array $canonicalBytes, int $requestFromSeq, int $fromSeq, int $toSeq): string
    {
        $offset = $fromSeq - $requestFromSeq;
        $length = $toSeq - $fromSeq + 1;

        return MerkleTree::rootHex(array_slice($canonicalBytes, $offset, $length));
    }

    /**
     * @param list<Warning> $warnings
     * @param list<SignatureVerificationResult> $signatureResults
     */
    private function anchorGapResult(
        AnchorTarget $target,
        ChainStats $stats,
        array $warnings,
        array $signatureResults,
        int $uncoveredSeq,
    ): VerificationResult {
        return new VerificationResult(
            outcome: VerificationOutcome::ANCHOR_BELOW_MIN,
            stats: $stats,
            warnings: [
                ...$warnings,
                new Warning(
                    Warning::ANCHOR_COVERAGE_GAP,
                    'Anchor coverage does not form a contiguous tiling for the requested range.',
                    [
                        'target_chain' => $target->chainId,
                        'from_seq' => $target->fromSeq,
                        'to_seq' => $target->toSeq,
                        'uncovered_seq' => $uncoveredSeq,
                    ],
                ),
            ],
            message: "Anchor coverage gap at sequence $uncoveredSeq",
            signatureResults: $signatureResults,
        );
    }

    /**
     * @param list<SignedEnvelope> $rangeEnvelopes
     * @return list<SignedEnvelope>
     */
    private function anchorEnvelopesFor(string $chainId, int $toSeq, array $rangeEnvelopes): array
    {
        $anchors = array_values(array_filter(
            $rangeEnvelopes,
            static fn (SignedEnvelope $signed): bool => str_starts_with($signed->envelope->type, 'attest.anchor.'),
        ));

        foreach ($this->store->readRange($chainId, $toSeq + 1) as $signed) {
            if (str_starts_with($signed->envelope->type, 'attest.anchor.')) {
                $anchors[] = $signed;
            }
        }

        return $anchors;
    }

    /**
     * @param list<Warning> $warnings
     * @param list<SignatureVerificationResult> $signatureResults
     */
    private function invalidChain(
        string $chainId,
        int $fromSeq,
        ?int $toSeq,
        int $envelopeCount,
        int $trustedSignatureCount,
        int $untrustedSignatureCount,
        int $anchorEnvelopeCount,
        array $warnings,
        array $signatureResults,
        int $brokenAtSeq,
        string $message,
    ): VerificationResult {
        return new VerificationResult(
            outcome: VerificationOutcome::INVALID_CHAIN,
            stats: new ChainStats(
                chainId: $chainId,
                fromSeq: $fromSeq,
                toSeq: $toSeq,
                envelopeCount: $envelopeCount,
                trustedSignatureCount: $trustedSignatureCount,
                untrustedSignatureCount: $untrustedSignatureCount,
                anchorEnvelopeCount: $anchorEnvelopeCount,
            ),
            warnings: $warnings,
            brokenAtSeq: $brokenAtSeq,
            message: $message,
            signatureResults: $signatureResults,
        );
    }
}
