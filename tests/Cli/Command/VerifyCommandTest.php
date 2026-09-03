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
use Fissible\Attest\Chain\PathMapper;
use Fissible\Attest\Cli\Command\VerifyCommand;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Headers\ActiveChainHeader;
use Fissible\Attest\Headers\BlockHeaderProvider;
use Fissible\Attest\Headers\HeaderLookupResult;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Headers\TrustLevel;
use Fissible\Attest\Merkle\MerkleTree;
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

    /**
     * @param (callable(?string, ?string, ?string): HeaderProviderSet)|null $headerProviderFactory
     */
    private function makeTester(?callable $headerProviderFactory = null): CommandTester
    {
        $application = new Application();
        $application->addCommand(new VerifyCommand($headerProviderFactory));
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

    private function buildChainWithUpgradedOtsAnchor(string $chainId, KeyPair $kp, int $count = 3): AnchorReceipt
    {
        $store = new FileChainStore($this->tmpDir);
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, $chainId, $signer);
        $records = [];
        for ($i = 1; $i <= $count; $i++) {
            $records[] = $chain->record('app.event', ['n' => $i]);
        }

        $target = new AnchorTarget(
            chainId: $chainId,
            fromSeq: 1,
            toSeq: $count,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex(array_map(
                static fn (SignedEnvelope $signed): string => $signed->signedCanonicalBytes(),
                $records,
            )),
        );
        $receipt = $this->upgradedOtsReceipt($target);
        $chain->record(AnchorEnvelope::UPGRADED_TYPE, AnchorEnvelope::upgradedPayload($receipt));

        return $receipt;
    }

    private function upgradedOtsReceipt(AnchorTarget $target): AnchorReceipt
    {
        $rootBytes = hex2bin($target->rootHex);
        self::assertIsString($rootBytes);
        $timestamp = (new OpenTimestampsTimestamp($rootBytes))
            ->withAttestation(OpenTimestampsAttestation::bitcoin(840000));

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: ProofState::UPGRADED,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-06-06T00:00:00.000Z',
        );
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
    // Issue #36: --trusted-key-file accepts "<key_id>=<path>"
    // ─────────────────────────────────────────────────────────────────────────

    public function test_trusted_key_file_with_key_id_verifies_human_keyed_chain(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2); // signed with keyId 'k1'
        $pub = $this->tmpDir . '/k1.pub';
        file_put_contents($pub, base64_encode($kp->publicKey) . "\n");

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key-file' => ['k1=' . $pub],
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, $display);
        $payload = json_decode($display, true);
        self::assertIsArray($payload);
        self::assertSame('verified', $payload['outcome']);
        self::assertSame(2, $payload['chain_stats']['trusted_signatures']);
        self::assertSame(['k1' => 2], $payload['signature_summary']['trusted_keys_matched']);
    }

    public function test_trusted_key_file_without_key_id_cannot_match_human_keyed_chain(): void
    {
        // Documents the fingerprint-only behaviour of a plain path: the key is
        // right, but nothing routes envelopes signed under 'k1' to it.
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);
        $pub = $this->tmpDir . '/k1.pub';
        file_put_contents($pub, base64_encode($kp->publicKey) . "\n");

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key-file' => [$pub],
            '--json' => true,
        ]);

        self::assertSame(2, $exitCode);
        $payload = json_decode($tester->getDisplay(), true);
        self::assertIsArray($payload);
        self::assertSame('integrity_verified_untrusted', $payload['outcome']);
        self::assertSame(0, $payload['chain_stats']['trusted_signatures']);
    }

    public function test_trusted_key_file_option_help_documents_key_id_prefix(): void
    {
        $description = (new VerifyCommand())->getDefinition()->getOption('trusted-key-file')->getDescription();

        self::assertStringContainsString('<key_id>=', $description);
        self::assertStringContainsString('fingerprint', $description);
    }

    public function test_trusted_key_given_a_path_exits_1_and_points_at_trusted_key_file(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 1);
        $pub = $this->tmpDir . '/k1.pub';
        file_put_contents($pub, base64_encode($kp->publicKey) . "\n");

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => [$pub],
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringStartsWith('error: ', $tester->getDisplay());
        self::assertStringContainsString('--trusted-key-file', $tester->getDisplay());
    }

    public function test_undecodable_stored_line_exits_4_with_structured_json(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 3);
        $jsonlPath = (new PathMapper($this->tmpDir))->jsonlPath('chain1');
        $lines = file($jsonlPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        self::assertIsArray($lines);
        $lines[1] = 'this is not json';
        file_put_contents($jsonlPath, implode("\n", $lines) . "\n");

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--json' => true,
        ]);

        self::assertSame(4, $exitCode);
        $payload = json_decode($tester->getDisplay(), true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('attest.cli.result.v1', $payload['format_version']);
        self::assertSame('invalid_chain', $payload['outcome']);
        self::assertSame(2, $payload['broken_at_seq']);
    }

    public function test_non_numeric_from_exits_1_with_error_line(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--from' => 'abc',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringStartsWith('error: --from must be an integer >= 1', $tester->getDisplay());
    }

    public function test_to_below_from_exits_1_with_error_line(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--from' => '2',
            '--to' => '1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringStartsWith('error: --to must be an integer >= --from', $tester->getDisplay());
    }

    public function test_runtime_error_during_verification_exits_1_with_error_line(): void
    {
        $kp = KeyPair::generate();
        $this->buildChain('chain1', $kp, 2);
        $lockPath = (new PathMapper($this->tmpDir))->lockPath('chain1');
        self::assertFileExists($lockPath);
        chmod($lockPath, 0o444);

        $tester = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--json' => true,
        ]);
        chmod($lockPath, 0o644);

        self::assertSame(1, $exitCode);
        $payload = json_decode($tester->getDisplay(), true);
        self::assertIsArray($payload, 'Runtime errors must still produce JSON under --json');
        self::assertSame('attest.cli.error.v1', $payload['format_version']);
        self::assertSame('verify', $payload['command']);
        self::assertSame(1, $payload['exit_code']);
        self::assertStringContainsString('append lock', $payload['error']);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 7: Provider disagreement → exit 5 [DEFERRED]
    // ─────────────────────────────────────────────────────────────────────────

    public function test_provider_disagreement_exits_5(): void
    {
        $kp = KeyPair::generate();
        $receipt = $this->buildChainWithUpgradedOtsAnchor('chain1', $kp, 3);

        $headers = new HeaderProviderSet(
            CliVotingHeaderProvider::pass(
                'bitcoin-core',
                TrustLevel::LOCAL,
                $receipt->target->rootHex,
                blockHash: str_repeat('1', 64),
            ),
            CliVotingHeaderProvider::pass(
                'esplora',
                TrustLevel::REMOTE,
                $receipt->target->rootHex,
                blockHash: str_repeat('2', 64),
            ),
        );

        $tester = $this->makeTester(
            static fn (?string $bitcoinCoreRpc, ?string $bitcoinCoreCookie, ?string $esploraUrl): HeaderProviderSet => $headers,
        );
        $exitCode = $tester->execute([
            '--storage-root' => $this->tmpDir,
            '--chain' => 'chain1',
            '--trusted-key' => ['k1=' . base64_encode($kp->publicKey)],
            '--min-anchor' => 'remote_header_confirmed',
        ]);

        self::assertSame(5, $exitCode, 'Expected exit 5; output: ' . $tester->getDisplay());
        self::assertStringContainsString('provider_disagreement', $tester->getDisplay());
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

final readonly class CliVotingHeaderProvider implements BlockHeaderProvider
{
    private function __construct(
        private string $providerName,
        private TrustLevel $trustLevel,
        private string $merkleRoot,
        private string $blockHash,
    ) {
    }

    public static function pass(
        string $name,
        TrustLevel $trustLevel,
        string $merkleRoot,
        string $blockHash,
    ): self {
        return new self($name, $trustLevel, $merkleRoot, $blockHash);
    }

    public function name(): string
    {
        return $this->providerName;
    }

    public function trustLevel(): TrustLevel
    {
        return $this->trustLevel;
    }

    public function getActiveChainHeaderByHeight(int $height): HeaderLookupResult
    {
        return HeaderLookupResult::active(
            $this->providerName,
            $this->trustLevel,
            new ActiveChainHeader(
                blockHash: $this->blockHash,
                height: $height,
                confirmations: 7,
                merkleRoot: $this->merkleRoot,
                timeUnixSec: 1713571200,
            ),
        );
    }
}
