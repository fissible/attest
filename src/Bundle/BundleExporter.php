<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Signing\Fingerprint;
use Fissible\Attest\Verification\Warning;
use ParagonIE\ConstantTime\Base64;

/**
 * @api
 */
final class BundleExporter
{
    /** @var list<array{chainId:string, fromSeq:int, toSeq:int}> */
    private array $segments = [];

    /** @var list<array{pubkey:string, keyId:?string, sigAlg:string}> */
    private array $claimedKeys = [];

    /** @var list<Warning> */
    private array $warnings = [];

    private ?string $note = null;
    private ?string $issuerHint = null;

    public static function create(ChainStore $store): self
    {
        return new self($store);
    }

    private function __construct(private readonly ChainStore $store)
    {
    }

    public function forChainSegment(string $chainId, int $fromSeq, int $toSeq): self
    {
        if ($fromSeq < 1 || $toSeq < $fromSeq) {
            throw new BundleExportException('Invalid segment range');
        }
        $this->segments[] = ['chainId' => $chainId, 'fromSeq' => $fromSeq, 'toSeq' => $toSeq];
        return $this;
    }

    public function withClaimedKey(string $rawPubkeyBytes, ?string $keyId = null, string $sigAlg = 'ed25519'): self
    {
        if (strlen($rawPubkeyBytes) !== 32) {
            throw new BundleExportException('Ed25519 public key must be 32 bytes');
        }
        $this->claimedKeys[] = ['pubkey' => $rawPubkeyBytes, 'keyId' => $keyId, 'sigAlg' => $sigAlg];
        return $this;
    }

    public function withNote(string $note): self
    {
        $this->note = $note;
        return $this;
    }

    public function withIssuerHint(string $hint): self
    {
        $this->issuerHint = $hint;
        return $this;
    }

    public function writeTo(string $outPath): void
    {
        if ($this->segments === []) {
            throw new BundleExportException('No segments to export');
        }

        $chainMetas = [];
        $anchorMetas = [];
        $chainEntries = [];
        $proofEntries = [];
        $receiptEntries = [];

        foreach ($this->segments as $seg) {
            $entry = $this->collectSegment($seg['chainId'], $seg['fromSeq'], $seg['toSeq']);
            $chainEntries[$entry['chainEntryPath']] = $entry['chainBytes'];
            $proofEntries[$entry['proofEntryPath']] = $entry['proofBytes'];
            foreach ($entry['receiptEntries'] as $rPath => $rBytes) {
                $receiptEntries[$rPath] = $rBytes;
            }
            $chainMetas[] = new ChainSegmentMeta(
                chainId: $seg['chainId'],
                file: $entry['chainEntryPath'],
                fromSeq: $seg['fromSeq'],
                toSeq: $seg['toSeq'],
                envelopeCount: $entry['envelopeCount'],
                headHash: $entry['headHash'],
            );
            foreach ($entry['anchorMetas'] as $am) {
                $anchorMetas[] = $am;
            }
        }

        $claimedKeyMetas = [];
        $keyEntries = [];
        foreach ($this->claimedKeys as $ck) {
            $fingerprint = Fingerprint::of($ck['pubkey']);
            $entryPath = BundleConstants::KEYS_PREFIX . $fingerprint . '.pub';
            $keyEntries[$entryPath] = Base64::encode($ck['pubkey']);
            $claimedKeyMetas[] = new ClaimedKeyMeta(
                keyId: $ck['keyId'] !== null && $ck['keyId'] !== '' ? $ck['keyId'] : $fingerprint,
                sigAlg: $ck['sigAlg'],
                fingerprint: 'sha256:' . $fingerprint,
                file: $entryPath,
            );
        }

        $manifest = new BundleManifest(
            createdAt: gmdate('Y-m-d\TH:i:s\Z'),
            chains: $chainMetas,
            anchors: $anchorMetas,
            claimedKeys: $claimedKeyMetas,
            issuerHint: $this->issuerHint,
            note: $this->note,
        );

        $writer = BundleWriter::open($outPath);
        try {
            $writer->addEntry(BundleConstants::MANIFEST_ENTRY, $manifest->toJson());
            foreach ($chainEntries as $p => $b)   { $writer->addEntry($p, $b); }
            foreach ($proofEntries as $p => $b)   { $writer->addEntry($p, $b); }
            foreach ($receiptEntries as $p => $b) { $writer->addEntry($p, $b); }
            foreach ($keyEntries as $p => $b)     { $writer->addEntry($p, $b); }
            $writer->commit();
        } catch (\Throwable $e) {
            $writer->discard();
            throw $e;
        }
    }

    /** @return list<Warning> */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /**
     * @return array{
     *   chainEntryPath:string,
     *   chainBytes:string,
     *   proofEntryPath:string,
     *   proofBytes:string,
     *   receiptEntries:array<string,string>,
     *   envelopeCount:int,
     *   headHash:string,
     *   anchorMetas:list<AnchorMeta>,
     * }
     */
    private function collectSegment(string $chainId, int $fromSeq, int $toSeq): array
    {
        $chainHash = substr(hash('sha256', $chainId), 0, 32);
        $chainEntryPath = BundleConstants::CHAINS_PREFIX . $chainHash . '.jsonl';
        $proofEntryPath = BundleConstants::PROOF_ENVELOPES_PREFIX . $chainHash . '.jsonl';

        // Chain segment bytes
        $chainLines = [];
        $headHash = null;
        $count = 0;
        if ($this->store instanceof RawChainStore) {
            foreach ($this->store->readRawRange($chainId, $fromSeq, $toSeq) as $raw) {
                $chainLines[] = $raw;
                $count++;
            }
            // Recompute head_hash from the last raw line
            if ($chainLines !== []) {
                $headHash = bin2hex(hash('sha256', end($chainLines), binary: true));
            }
        } else {
            foreach ($this->store->readRange($chainId, $fromSeq, $toSeq) as $signed) {
                $chainLines[] = $signed->signedCanonicalBytes();
                $count++;
                $headHash = $signed->selfHash();
            }
        }
        if ($count !== ($toSeq - $fromSeq + 1)) {
            throw new BundleExportException(
                "Chain segment incomplete: expected " . ($toSeq - $fromSeq + 1) . ", got $count"
            );
        }

        // Single forward pass past toSeq:
        // - Collect exact-range proof envelopes
        // - Detect wider-only anchors if no exact match is found
        $proofLines = [];
        // Strongest receipt per anchor_id. Every exact-range envelope is kept
        // in proof_envelopes/ (the verifier needs the supersession history),
        // but the manifest and receipt cache describe only the winning proof.
        /** @var array<string, array{receipt: AnchorReceipt, envelopeId: string}> $winners */
        $winners = [];
        $exactCount = 0;
        $widerCount = 0;

        foreach ($this->store->readRange($chainId, $toSeq + 1) as $signed) {
            if (! str_starts_with($signed->envelope->type, 'attest.anchor.')) {
                continue;
            }
            try {
                $receipt = AnchorEnvelope::fromSignedEnvelope($signed);
            } catch (\Throwable) {
                continue;
            }
            $target = $receipt->target;
            if ($target->chainId !== $chainId) {
                continue;
            }

            $isExact = ($target->fromSeq === $fromSeq && $target->toSeq === $toSeq);
            $isWider = (! $isExact
                && $target->fromSeq <= $fromSeq
                && $target->toSeq >= $toSeq);

            if ($isExact) {
                $exactCount++;
                $proofLines[] = $signed->signedCanonicalBytes();

                // Later envelopes win ties so an equal-strength re-record supersedes.
                $current = $winners[$receipt->anchorId] ?? null;
                if ($current === null || $receipt->state->strength() >= $current['receipt']->state->strength()) {
                    $winners[$receipt->anchorId] = [
                        'receipt' => $receipt,
                        'envelopeId' => $signed->envelope->id,
                    ];
                }
            } elseif ($isWider) {
                $widerCount++;
            }
        }

        // If no exact match but at least one wider anchor exists, refuse export.
        if ($exactCount === 0 && $widerCount > 0) {
            throw new BundleExportException(
                "No proof envelope matches exact range [$fromSeq,$toSeq] for chain $chainId; "
                . 'wider anchors exist but subset inclusion proofs are not supported in v1. '
                . 'Export the full anchored range instead.',
            );
        }

        // Manifest entries and receipt cache (path => raw bytes) from the winners
        $anchorMetas = [];
        $receiptEntries = [];
        foreach ($winners as $anchorId => $winner) {
            $receipt = $winner['receipt'];
            $target = $receipt->target;
            $path = BundleConstants::RECEIPTS_PREFIX . $anchorId . '.ots';

            $anchorMetas[] = new AnchorMeta(
                anchorId: $anchorId,
                chainId: $target->chainId,
                fromSeq: $target->fromSeq,
                toSeq: $target->toSeq,
                merkleAlgorithm: $target->merkleAlgorithm,
                root: $target->rootHex,
                driver: $receipt->driverName,
                state: $receipt->state->value,
                receiptEnvelopeId: $winner['envelopeId'],
                receiptCacheFile: $path,
            );
            $receiptEntries[$path] = $receipt->receiptBytes;

            if ($receipt->state === ProofState::PENDING) {
                $this->warnings[] = new Warning(
                    'bundle_export_pending_anchor',
                    'Anchor is in PENDING state; consider running `attest upgrade` before export.',
                    ['anchor_id' => $anchorId],
                );
            }
        }

        return [
            'chainEntryPath' => $chainEntryPath,
            'chainBytes' => implode("\n", $chainLines) . ($chainLines === [] ? '' : "\n"),
            'proofEntryPath' => $proofEntryPath,
            'proofBytes' => implode("\n", $proofLines) . ($proofLines === [] ? '' : "\n"),
            'receiptEntries' => $receiptEntries,
            'envelopeCount' => $count,
            'headHash' => $headHash ?? str_repeat('0', 64),
            'anchorMetas' => $anchorMetas,
        ];
    }
}
