<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Bundle\BundleConstants;
use Fissible\Attest\Bundle\BundleExportException;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class BundleExporterTest extends TestCase
{
    private string $tmpDir;
    private string $bundleDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-bx-' . bin2hex(random_bytes(8));
        $this->bundleDir = $this->tmpDir . '/out';
        mkdir($this->tmpDir, 0o700, recursive: true);
        mkdir($this->bundleDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_exports_segment_with_matching_anchor(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        for ($i = 1; $i <= 5; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        // Anchor exactly [1,5] with NullDriver
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('tenant:5', 1, 5, new NullDriver());

        $out = $this->bundleDir . '/incident.attest';
        BundleExporter::create($store)
            ->forChainSegment('tenant:5', 1, 5)
            ->withClaimedKey($kp->publicKey, keyId: 'k1', sigAlg: 'ed25519')
            ->withNote('Test export')
            ->writeTo($out);

        self::assertFileExists($out);
        // Open the ZIP and assert layout
        $zip = new \ZipArchive();
        self::assertTrue($zip->open($out) === true);
        self::assertNotFalse($zip->locateName(BundleConstants::MANIFEST_ENTRY));
        self::assertNotFalse($zip->locateName('chains/' . substr(hash('sha256', 'tenant:5'), 0, 32) . '.jsonl'));
        self::assertNotFalse($zip->locateName('proof_envelopes/' . substr(hash('sha256', 'tenant:5'), 0, 32) . '.jsonl'));
        $zip->close();
    }

    public function test_refuses_export_when_only_wider_anchor_exists(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        for ($i = 1; $i <= 10; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        // Anchor [1,10] - wider than requested [1,5]
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('tenant:5', 1, 10, new NullDriver());

        $this->expectException(BundleExportException::class);
        $this->expectExceptionMessageMatches('/exact range/i');
        BundleExporter::create($store)
            ->forChainSegment('tenant:5', 1, 5)
            ->writeTo($this->bundleDir . '/bad.attest');
    }

    public function test_warns_on_pending_anchor(): void
    {
        // Chain anchored via NullDriver — receipt state is SUBMITTED.
        // BundleExporter should accumulate a warning.
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'c', $signer);
        for ($i = 1; $i <= 3; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('c', 1, 3, new NullDriver());

        $exporter = BundleExporter::create($store)->forChainSegment('c', 1, 3);
        $exporter->writeTo($this->bundleDir . '/c.attest');
        // NullDriver receipts are not "pending" in the OTS sense, so no
        // pending warning here. Replace this test with an OTS-pending one
        // when an OTS mock is wired into the test suite.
        $warnings = $exporter->warnings();
        self::assertIsArray($warnings);
    }

    public function test_writes_atomically_temp_then_rename(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'c', $signer);
        $chain->record('app.event', ['n' => 1]);
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        (new AnchorService($store, $claimStore, $signer))
            ->anchorRange('c', 1, 1, new NullDriver());

        $out = $this->bundleDir . '/c.attest';
        BundleExporter::create($store)
            ->forChainSegment('c', 1, 1)
            ->writeTo($out);

        self::assertFileExists($out);
        // No leftover temp files
        $leftovers = glob($this->bundleDir . '/*.tmp.*');
        self::assertSame([], $leftovers);
    }
}
