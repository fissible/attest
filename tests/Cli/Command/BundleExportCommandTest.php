<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Command;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Command\BundleExportCommand;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class BundleExportCommandTest extends TestCase
{
    private string $tmpDir;
    private string $outDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-bec-' . bin2hex(random_bytes(8));
        $this->outDir = $this->tmpDir . '/out';
        mkdir($this->tmpDir, 0o700, recursive: true);
        mkdir($this->outDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    private function makeTester(): CommandTester
    {
        $application = new Application();
        $application->add(new BundleExportCommand());
        $application->setAutoExit(false);
        $command = $application->find('bundle:export');
        return new CommandTester($command);
    }

    /**
     * Build a chain, anchor a range with NullDriver, return store.
     */
    private function buildChainWithAnchor(
        string $chainId,
        int $count,
        int $anchorFrom,
        int $anchorTo,
    ): void {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, $chainId, $signer);
        for ($i = 1; $i <= $count; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange($chainId, $anchorFrom, $anchorTo, new NullDriver());
    }

    private function buildChainWithPendingOtsAnchor(
        string $chainId,
        int $count,
        int $anchorFrom,
        int $anchorTo,
    ): AnchorReceipt {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, $chainId, $signer);
        for ($i = 1; $i <= $count; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }

        $receipt = $this->pendingOtsReceipt($store, $chainId, $anchorFrom, $anchorTo);
        $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt));

        return $receipt;
    }

    private function targetFor(FileChainStore $store, string $chainId, int $fromSeq, int $toSeq): AnchorTarget
    {
        $rawBytes = iterator_to_array($store->readRawRange($chainId, $fromSeq, $toSeq), false);

        return new AnchorTarget(
            chainId: $chainId,
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex($rawBytes),
        );
    }

    private function pendingOtsReceipt(FileChainStore $store, string $chainId, int $fromSeq, int $toSeq): AnchorReceipt
    {
        $target = $this->targetFor($store, $chainId, $fromSeq, $toSeq);
        $rootBytes = hex2bin($target->rootHex);
        self::assertIsString($rootBytes);
        $timestamp = (new OpenTimestampsTimestamp($rootBytes))
            ->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example'));

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: ProofState::PENDING,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-06-06T00:00:00.000Z',
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Happy path — anchored [1,5] range; export succeeds, file exists
    // ─────────────────────────────────────────────────────────────────────────

    public function test_exports_bundle_to_path(): void
    {
        $this->buildChainWithAnchor('tenant:5', 5, 1, 5);

        $outPath = $this->outDir . '/incident.attest';
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain'        => 'tenant:5',
            '--from'         => '1',
            '--to'           => '5',
            '--out'          => $outPath,
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $tester->getDisplay());
        self::assertFileExists($outPath, 'Bundle file must exist after export');
        self::assertStringContainsString('bundle exported to', $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Wider-only anchor → exit 4 + BundleExportException message
    // ─────────────────────────────────────────────────────────────────────────

    public function test_refuses_export_when_only_wider_anchor_exists(): void
    {
        // Anchor [1,10] but request [1,5]
        $this->buildChainWithAnchor('tenant:5', 10, 1, 10);

        $outPath = $this->outDir . '/bad.attest';
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain'        => 'tenant:5',
            '--from'         => '1',
            '--to'           => '5',
            '--out'          => $outPath,
        ], ['catch_exceptions' => true]);

        self::assertSame(4, $exitCode, 'Expected exit 4; output: ' . $tester->getDisplay());
        self::assertStringContainsString('exact range', strtolower($tester->getDisplay()));
        self::assertFileDoesNotExist($outPath, 'Bundle file must NOT exist after failed export');
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Missing required --chain → exit 1
    // ─────────────────────────────────────────────────────────────────────────

    public function test_exits_1_on_invalid_options(): void
    {
        $outPath = $this->outDir . '/out.attest';
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            // --chain deliberately omitted
            '--from' => '1',
            '--to'   => '5',
            '--out'  => $outPath,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: PENDING anchor warning [INCOMPLETE — NullDriver produces SUBMITTED]
    // ─────────────────────────────────────────────────────────────────────────

    public function test_emits_pending_warning_when_anchor_is_pending(): void
    {
        $receipt = $this->buildChainWithPendingOtsAnchor('tenant:5', 5, 1, 5);

        $outPath = $this->outDir . '/pending.attest';
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain'        => 'tenant:5',
            '--from'         => '1',
            '--to'           => '5',
            '--out'          => $outPath,
            '--json'         => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $display);
        self::assertFileExists($outPath, 'Bundle file must exist after export');

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON; got: ' . $display);
        self::assertCount(1, $payload['warnings']);
        self::assertSame('bundle_export_pending_anchor', $payload['warnings'][0]['code']);
        self::assertSame($receipt->anchorId, $payload['warnings'][0]['context']['anchor_id']);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: --json output has expected attest.cli.export.v1 schema
    // ─────────────────────────────────────────────────────────────────────────

    public function test_json_output_has_expected_schema(): void
    {
        $this->buildChainWithAnchor('tenant:5', 5, 1, 5);

        $outPath = $this->outDir . '/incident.attest';
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain'        => 'tenant:5',
            '--from'         => '1',
            '--to'           => '5',
            '--out'          => $outPath,
            '--json'         => true,
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $tester->getDisplay());

        $display = $tester->getDisplay();
        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON; got: ' . $display);
        self::assertSame('attest.cli.export.v1', $payload['format_version']);
        self::assertSame('bundle:export', $payload['command']);
        self::assertSame($outPath, $payload['out']);
        self::assertIsInt($payload['bytes_written']);
        self::assertGreaterThan(0, $payload['bytes_written']);
        self::assertArrayHasKey('chain_segments', $payload);
        self::assertArrayHasKey('anchors', $payload);
        self::assertArrayHasKey('warnings', $payload);
        self::assertIsArray($payload['chain_segments']);
        self::assertCount(1, $payload['chain_segments']);
        self::assertSame('tenant:5', $payload['chain_segments'][0]['chain_id']);
        self::assertSame(1, $payload['chain_segments'][0]['from_seq']);
        self::assertSame(5, $payload['chain_segments'][0]['to_seq']);
        self::assertSame(5, $payload['chain_segments'][0]['envelope_count']);
    }
}
