<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Command;

use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\PathMapper;
use Fissible\Attest\Cli\Command\VerifyCommand;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class VerifyCommandTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-verify-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    private function makeTester(): CommandTester
    {
        $application = new Application();
        $application->add(new VerifyCommand());
        $application->setAutoExit(false);
        $command = $application->find('verify');
        return new CommandTester($command);
    }

    /**
     * Build a chain with 2 events, signed by $kp with keyId 'k1'.
     */
    private function buildChain(string $chainId, KeyPair $kp, int $count = 2): void
    {
        $store = new FileChainStore($this->tmpDir);
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, $chainId, $signer);
        for ($i = 1; $i <= $count; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Happy path — trusted key, exit 0
    // ─────────────────────────────────────────────────────────────────────────

    public function test_verifies_chain_and_exits_0(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('verified', $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Invalid --min-anchor value → exit 1
    // ─────────────────────────────────────────────────────────────────────────

    public function test_invalid_min_anchor_value_exits_1(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--min-anchor' => 'garbage',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Non-existent storage-root → exit 1
    // ─────────────────────────────────────────────────────────────────────────

    public function test_missing_storage_root_exits_1(): void
    {
        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => '/does/not/exist/attest-' . bin2hex(random_bytes(4)),
            '--chain' => 'chain1',
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Untrusted signature (no trusted key passed) → exit 2
    // ─────────────────────────────────────────────────────────────────────────

    public function test_untrusted_signature_exits_2(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        // No --trusted-key → all signatures are untrusted → INTEGRITY_VERIFIED_UNTRUSTED → exit 2
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
        ]);

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('untrusted', $tester->getDisplay());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Anchor below min (chain has no anchor, --min-anchor local_only) → exit 3
    // ─────────────────────────────────────────────────────────────────────────

    public function test_anchor_below_min_exits_3(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--min-anchor' => 'local_only',
        ]);

        // Chain has no anchor → ANCHOR_BELOW_MIN → exit 3
        self::assertSame(3, $exitCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 6: Invalid chain (mutated prev_hash in JSONL) → exit 4
    // ─────────────────────────────────────────────────────────────────────────

    public function test_invalid_chain_exits_4(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 3);

        // Locate the JSONL file and corrupt the second line's prev_hash
        $mapper = new PathMapper($this->tmpDir);
        $jsonlPath = $mapper->jsonlPath('chain1');
        $lines = file($jsonlPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($lines);
        self::assertGreaterThanOrEqual(2, count($lines));

        // Decode line 2 (seq=2), change its prev_hash to random bytes, re-sign
        // To keep it simple: just swap two bytes in the raw line to corrupt the JSON.
        // This will cause JSON parse to fail or produce an invalid self-hash check.
        $lines[1] = str_replace('"prev_hash":"', '"prev_hash":"CORRUPTED', $lines[1]);
        file_put_contents($jsonlPath, implode("\n", $lines) . "\n");

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
        ]);

        // Corrupted chain → INVALID_CHAIN or INVALID_SIGNATURE → exit 4
        self::assertSame(4, $exitCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Provider disagreement → exit 5 [DEFERRED]
    // ─────────────────────────────────────────────────────────────────────────

    public function test_provider_disagreement_exits_5(): void
    {
        // TODO: Provider disagreement requires mocking header providers (Bitcoin Core / Esplora)
        // that return conflicting confirmations. NullDriver alone produces LOCAL_ONLY and never
        // reaches the header-provider code path. This scenario will be covered in
        // BundleVerifyCommandTest (Task 3.10) where HTTP mocking is set up.
        $this->markTestIncomplete(
            'Provider disagreement (exit 5) requires conflicting header providers. ' .
            'Will be covered in BundleVerifyCommandTest (Task 3.10) with mocked HTTP.'
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 8: --allow-untrusted downgrades INTEGRITY_VERIFIED_UNTRUSTED → exit 0
    // ─────────────────────────────────────────────────────────────────────────

    public function test_allow_untrusted_downgrades_to_0(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        // No --trusted-key, but --allow-untrusted → INTEGRITY_VERIFIED_UNTRUSTED → exit 0
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--allow-untrusted' => true,
        ]);

        self::assertSame(0, $exitCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 9: --json output matches attest.cli.result.v1 schema
    // ─────────────────────────────────────────────────────────────────────────

    public function test_json_output_matches_schema_v1(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--json' => true,
        ]);

        self::assertSame(0, $exitCode);

        $display = $tester->getDisplay();
        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('attest.cli.result.v1', $payload['format_version']);
        self::assertSame('verify', $payload['command']);
        self::assertSame('verified', $payload['outcome']);
        self::assertTrue($payload['verified']);
        self::assertSame(0, $payload['exit_code']);
        self::assertArrayHasKey('chain_stats', $payload);
        self::assertArrayHasKey('signature_summary', $payload);
        self::assertArrayHasKey('warnings', $payload);
    }
}
