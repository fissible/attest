<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Bundle\BundleReader;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for issue #18: when a pending anchor has been upgraded,
 * the bundle manifest and receipt cache must describe the upgraded proof.
 */
final class BundleExporterUpgradedAnchorTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-bxu-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_upgraded_anchor_wins_over_its_pending_predecessor(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $signer = new SodiumSigner(KeyPair::generate(), keyId: 'k1');
        $chain = EvidenceChain::open($store, 'c', $signer);
        $chain->record('app.event', ['n' => 1]);
        $chain->record('app.event', ['n' => 2]);

        $pending = $this->otsReceipt($store, 'c', 1, 2, ProofState::PENDING);
        $upgraded = $this->otsReceipt($store, 'c', 1, 2, ProofState::UPGRADED);
        self::assertSame($pending->anchorId, $upgraded->anchorId);
        self::assertNotSame($pending->receiptBytes, $upgraded->receiptBytes);

        $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($pending));
        $chain->record(AnchorEnvelope::UPGRADED_TYPE, AnchorEnvelope::upgradedPayload($upgraded));

        $out = $this->tmpDir . '/c.attest.zip';
        $exporter = BundleExporter::create($store)->forChainSegment('c', 1, 2);
        $exporter->writeTo($out);

        $reader = BundleReader::open($out);
        $anchors = $reader->manifest()->anchors;
        self::assertCount(1, $anchors, 'one manifest entry per anchor_id');
        self::assertSame($upgraded->anchorId, $anchors[0]->anchorId);
        self::assertSame(ProofState::UPGRADED->value, $anchors[0]->state);

        self::assertSame($upgraded->receiptBytes, $reader->getReceiptCache($upgraded->anchorId));

        $proofEnvelopes = iterator_to_array($reader->readProofEnvelopes('c'), false);
        self::assertCount(2, $proofEnvelopes, 'supersession history is preserved in proof_envelopes');

        $codes = array_map(static fn ($w) => $w->code, $exporter->warnings());
        self::assertNotContains('bundle_export_pending_anchor', $codes);
    }

    public function test_pending_anchor_without_upgrade_still_warns(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $signer = new SodiumSigner(KeyPair::generate(), keyId: 'k1');
        $chain = EvidenceChain::open($store, 'c', $signer);
        $chain->record('app.event', ['n' => 1]);

        $pending = $this->otsReceipt($store, 'c', 1, 1, ProofState::PENDING);
        $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($pending));

        $out = $this->tmpDir . '/c.attest.zip';
        $exporter = BundleExporter::create($store)->forChainSegment('c', 1, 1);
        $exporter->writeTo($out);

        $reader = BundleReader::open($out);
        self::assertCount(1, $reader->manifest()->anchors);
        self::assertSame(ProofState::PENDING->value, $reader->manifest()->anchors[0]->state);
        self::assertSame($pending->receiptBytes, $reader->getReceiptCache($pending->anchorId));

        $codes = array_map(static fn ($w) => $w->code, $exporter->warnings());
        self::assertContains('bundle_export_pending_anchor', $codes);
    }

    private function otsReceipt(
        FileChainStore $store,
        string $chainId,
        int $fromSeq,
        int $toSeq,
        ProofState $state,
    ): AnchorReceipt {
        $rawBytes = iterator_to_array($store->readRawRange($chainId, $fromSeq, $toSeq), false);
        $target = new AnchorTarget(
            chainId: $chainId,
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex($rawBytes),
        );
        $rootBytes = hex2bin($target->rootHex);
        self::assertIsString($rootBytes);

        $timestamp = new OpenTimestampsTimestamp($rootBytes);
        $timestamp = $state === ProofState::PENDING
            ? $timestamp->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example'))
            : $timestamp->withAttestation(OpenTimestampsAttestation::bitcoin(840000));

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: $state,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-06-06T00:00:00.000Z',
        );
    }
}
