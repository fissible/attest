<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Command;

use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Command\BundleVerifyCommand;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class BundleVerifyCommandTest extends TestCase
{
    private string $tmpDir;
    private string $bundleDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-bvc-' . bin2hex(random_bytes(8));
        $this->bundleDir = $this->tmpDir . '/bundles';
        mkdir($this->tmpDir, 0o700, recursive: true);
        mkdir($this->bundleDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    private function makeTester(): CommandTester
    {
        $application = new Application();
        $application->add(new BundleVerifyCommand());
        $application->setAutoExit(false);
        $command = $application->find('bundle:verify');
        return new CommandTester($command);
    }

    /**
     * Build a chain with $count envelopes, anchor the full range with NullDriver,
     * then export to a bundle. Returns the [bundle path, key pair].
     *
     * @return array{0: string, 1: KeyPair}
     */
    private function buildAndExportBundle(
        string $chainId,
        int $count,
        bool $withClaimedKey = false,
    ): array {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, $chainId, $signer);
        for ($i = 1; $i <= $count; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }

        // Anchor the full range
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange($chainId, 1, $count, new NullDriver());

        $bundlePath = $this->bundleDir . '/' . bin2hex(random_bytes(4)) . '.attest';
        $exporter = BundleExporter::create($store)
            ->forChainSegment($chainId, 1, $count);

        if ($withClaimedKey) {
            $exporter->withClaimedKey($kp->publicKey, keyId: 'k1', sigAlg: 'ed25519');
        }

        $exporter->writeTo($bundlePath);

        return [$bundlePath, $kp];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Happy path — verify bundle with trusted key + min-anchor local_only → exit 0
    // ─────────────────────────────────────────────────────────────────────────

    public function test_verifies_bundle_with_local_only_anchor(): void
    {
        [$bundlePath, $kp] = $this->buildAndExportBundle('chain1', 3);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--bundle'      => $bundlePath,
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--min-anchor'  => 'local_only',
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $tester->getDisplay());
        self::assertStringContainsString('verified', $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: min-anchor above local_only for a locally-anchored bundle → exit 3
    // ─────────────────────────────────────────────────────────────────────────

    public function test_bundle_with_local_anchor_fails_higher_min_anchor(): void
    {
        [$bundlePath, $kp] = $this->buildAndExportBundle('chain1', 3);

        $tester = $this->makeTester();
        // The bundle has a NullDriver (local-only) anchor; bitcoin_verified is higher → exit 3
        $exitCode = $tester->execute([
            '--bundle'      => $bundlePath,
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--min-anchor'  => 'bitcoin_verified',
        ]);

        self::assertSame(3, $exitCode, 'Expected exit 3 (ANCHOR_BELOW_MIN); output: ' . $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: CRITICAL — claimed keys alone do NOT satisfy trust → exit 2
    // ─────────────────────────────────────────────────────────────────────────

    public function test_claimed_keys_alone_do_not_satisfy_trust(): void
    {
        // Export bundle WITH the issuer's pubkey embedded as a claimed key.
        // But we do NOT pass --trusted-key when running bundle:verify.
        [$bundlePath] = $this->buildAndExportBundle('chain1', 2, withClaimedKey: true);

        $tester = $this->makeTester();
        // No --trusted-key → claimed keys in bundle are NOT trusted → INTEGRITY_VERIFIED_UNTRUSTED
        $exitCode = $tester->execute([
            '--bundle' => $bundlePath,
            // Intentionally no --trusted-key or --trusted-key-file
        ]);

        self::assertSame(2, $exitCode, 'Expected exit 2 (INTEGRITY_VERIFIED_UNTRUSTED); output: ' . $tester->getDisplay());
        self::assertStringContainsString('untrusted', $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: --allow-untrusted downgrades INTEGRITY_VERIFIED_UNTRUSTED → exit 0
    // ─────────────────────────────────────────────────────────────────────────

    public function test_allow_untrusted_exits_0_without_trusted_key(): void
    {
        [$bundlePath] = $this->buildAndExportBundle('chain1', 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--bundle'          => $bundlePath,
            '--allow-untrusted' => true,
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0 with --allow-untrusted; output: ' . $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: --json output matches attest.cli.result.v1 schema with command=bundle:verify
    // ─────────────────────────────────────────────────────────────────────────

    public function test_json_output_matches_schema_v1(): void
    {
        [$bundlePath, $kp] = $this->buildAndExportBundle('chain1', 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--bundle'      => $bundlePath,
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--json'        => true,
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $tester->getDisplay());

        $display = $tester->getDisplay();
        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON; got: ' . $display);
        self::assertSame('attest.cli.result.v1', $payload['format_version']);
        self::assertSame('bundle:verify', $payload['command'], '--json must set command=bundle:verify');
        self::assertSame('verified', $payload['outcome']);
        self::assertTrue($payload['verified']);
        self::assertSame(0, $payload['exit_code']);
        self::assertArrayHasKey('chain_stats', $payload);
        self::assertArrayHasKey('signature_summary', $payload);
        self::assertArrayHasKey('warnings', $payload);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Non-existent --bundle path → exit 1 (config error)
    // ─────────────────────────────────────────────────────────────────────────

    public function test_invalid_bundle_path_exits_1(): void
    {
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--bundle' => '/does/not/exist/attest-' . bin2hex(random_bytes(4)) . '.attest',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Invalid --min-anchor value → exit 1
    // ─────────────────────────────────────────────────────────────────────────

    public function test_invalid_min_anchor_value_exits_1(): void
    {
        [$bundlePath] = $this->buildAndExportBundle('chain1', 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--bundle'     => $bundlePath,
            '--min-anchor' => 'not_a_valid_level',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: Default to first chain when --chain is omitted
    // ─────────────────────────────────────────────────────────────────────────

    public function test_uses_first_chain_when_chain_option_omitted(): void
    {
        [$bundlePath, $kp] = $this->buildAndExportBundle('my-chain-id', 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--bundle'      => $bundlePath,
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $tester->getDisplay());
        // Human output must mention the resolved chain ID
        self::assertStringContainsString('my-chain-id', $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: --bundle option missing entirely → exit 1
    // ─────────────────────────────────────────────────────────────────────────

    public function test_missing_bundle_option_exits_1(): void
    {
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            // --bundle intentionally omitted
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 10: Proof envelope with invalid signature — warns, drops group
    // [INCOMPLETE — costly to construct a tampered bundle; Verifier-level coverage
    //  exists in VerifierDetachedAnchorSigTest]
    // ─────────────────────────────────────────────────────────────────────────

    public function test_bundle_with_invalid_proof_envelope_signature_warns_and_drops_group(): void
    {
        $this->markTestIncomplete(
            'Constructing a bundle with a tampered proof envelope signature is expensive. ' .
            'The Verifier-level behavior (DETACHED_ANCHOR_INVALID_SIGNATURE warning + group drop) ' .
            'is already covered by VerifierDetachedAnchorSigTest. ' .
            'Will be revisited if a BundleWriter mutation helper is added.'
        );
    }
}
