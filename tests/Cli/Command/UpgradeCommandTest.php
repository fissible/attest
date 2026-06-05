<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Command;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Command\UpgradeCommand;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class UpgradeCommandTest extends TestCase
{
    private string $tmpDir;
    private string $keyFile;
    private string $keyId = 'test-key';

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-upgrade-cmd-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);

        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $this->keyFile = $this->tmpDir . '/key.seed';
        file_put_contents($this->keyFile, base64_encode($seed));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    private function makeTester(): CommandTester
    {
        $application = new Application();
        $application->add(new UpgradeCommand());
        $application->setAutoExit(false);
        $command = $application->find('upgrade');
        return new CommandTester($command);
    }

    private function signerFromKeyFile(): SodiumSigner
    {
        $b64 = trim((string) file_get_contents($this->keyFile));
        $seed = base64_decode($b64, strict: true);
        assert($seed !== false);
        return new SodiumSigner(KeyPair::fromSeed($seed), $this->keyId);
    }

    private function buildChain(string $chainId, int $count): FileChainStore
    {
        $store  = new FileChainStore($this->tmpDir);
        $signer = $this->signerFromKeyFile();
        $chain  = EvidenceChain::open($store, $chainId, $signer);
        for ($i = 0; $i < $count; $i++) {
            $chain->record('app.event', ['n' => $i + 1]);
        }
        return $store;
    }

    /** @return array<string, string|bool> */
    private function baseArgs(string $chainId): array
    {
        return [
            '--storage-root'    => $this->tmpDir,
            '--chain'           => $chainId,
            '--signer-key-file' => $this->keyFile,
            '--signer-key-id'   => $this->keyId,
        ];
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 1: --all-pending on a chain with no anchor envelopes → exit 0
    // ────────────────────────────────────────────────────────────────────────

    public function test_exit_0_when_no_pending_anchors(): void
    {
        // Build a chain with only regular events — no anchor envelopes.
        $this->buildChain('np', 2);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('np'),
            '--all-pending' => true,
            '--json'        => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected exit 0 for no-pending case; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('attest.cli.upgrade.v1', $payload['format_version']);
        self::assertSame('upgrade', $payload['command']);
        self::assertSame([], $payload['upgraded']);
        self::assertSame([], $payload['unchanged']);
        self::assertSame([], $payload['failed']);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 2: --all-pending on an empty chain → exit 0
    // (no JSONL file at all; FileChainStore returns nothing)
    // ────────────────────────────────────────────────────────────────────────

    public function test_exit_0_on_empty_chain_with_all_pending(): void
    {
        // Storage root exists but chain was never written.
        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('empty'),
            '--all-pending' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected exit 0 for empty chain; output: ' . $display);
        self::assertStringContainsString('upgraded 0', $display);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 3: neither --anchor-id nor --all-pending → exit 1
    // ────────────────────────────────────────────────────────────────────────

    public function test_missing_required_options_exits_1(): void
    {
        $this->buildChain('m', 1);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('m'),
            // neither --anchor-id nor --all-pending
        ]);

        self::assertSame(1, $exitCode, 'Expected exit 1 when neither --anchor-id nor --all-pending given');
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 4: both --anchor-id and --all-pending → exit 1
    // ────────────────────────────────────────────────────────────────────────

    public function test_both_anchor_id_and_all_pending_exits_1(): void
    {
        $this->buildChain('b', 1);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('b'),
            '--anchor-id'   => 'someanchorid',
            '--all-pending' => true,
        ]);

        self::assertSame(1, $exitCode, 'Expected exit 1 when both --anchor-id and --all-pending given');
        self::assertStringContainsString('mutually exclusive', strtolower($tester->getDisplay()));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 5: missing --storage-root → exit 1
    // ────────────────────────────────────────────────────────────────────────

    public function test_missing_storage_root_exits_1(): void
    {
        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            '--chain'           => 'x',
            '--all-pending'     => true,
            '--signer-key-file' => $this->keyFile,
            '--signer-key-id'   => $this->keyId,
            // --storage-root deliberately omitted
        ]);

        self::assertSame(1, $exitCode, 'Expected exit 1 for missing --storage-root');
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 6: missing --signer-key-file → exit 1
    // ────────────────────────────────────────────────────────────────────────

    public function test_missing_signer_key_exits_1(): void
    {
        $this->buildChain('sk', 1);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root'   => $this->tmpDir,
            '--chain'          => 'sk',
            '--all-pending'    => true,
            '--signer-key-id'  => $this->keyId,
            // --signer-key-file deliberately omitted
        ]);

        self::assertSame(1, $exitCode, 'Expected exit 1 for missing --signer-key-file');
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 7: --anchor-id with no matching pending anchor → exit 4
    // ────────────────────────────────────────────────────────────────────────

    public function test_anchor_id_not_found_exits_4(): void
    {
        $this->buildChain('af', 2);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('af'),
            '--anchor-id' => 'nonexistent-anchor-id',
            '--json'      => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(4, $exitCode, 'Expected exit 4 for --anchor-id not found; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('attest.cli.upgrade.v1', $payload['format_version']);
        self::assertNotEmpty($payload['failed']);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 8 (incomplete): upgrade idempotent on already-upgraded anchor
    // ────────────────────────────────────────────────────────────────────────

    public function test_upgrade_idempotent_on_already_upgraded(): void
    {
        $this->markTestIncomplete(
            'Requires an OTS receipt that is already in UPGRADED state. '
            . 'Creating such a receipt requires either a mock PSR-18 calendar client '
            . 'or a fixture receipt. Neither is wired into CLI tests yet. '
            . 'TODO: add a factory-closure seam to OpenTimestampsDriver (similar to '
            . 'the blocker documented in AnchorCommandTest) to enable mock injection.'
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 9 (incomplete): CalendarUnavailable continues in --all-pending mode
    // ────────────────────────────────────────────────────────────────────────

    public function test_calendar_unavailable_continues_to_next_anchor(): void
    {
        $this->markTestIncomplete(
            'Exercising CalendarUnavailable on upgrade() requires a mock calendar client '
            . 'that throws CalendarUnavailable. The injection seam (factory closure on '
            . 'OpenTimestampsDriver) is not yet wired. '
            . 'TODO: add seam, then assert that failed[] grows by 1 per unavailable anchor '
            . 'and the command continues processing the remaining candidates.'
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 10 (incomplete): single --anchor-id succeeds → upgraded state + new envelope
    // ────────────────────────────────────────────────────────────────────────

    public function test_upgrades_single_anchor_id_to_upgraded_state(): void
    {
        $this->markTestIncomplete(
            'Requires a PENDING OTS receipt and a mock calendar client returning a '
            . 'completed Bitcoin attestation path. Same injection-seam blocker as above. '
            . 'TODO: once the factory closure is in place, assert that: '
            . '(1) exit code is 0, '
            . '(2) upgraded[] contains one entry with previous_envelope_id and new_envelope_id, '
            . '(3) the new envelope is readable from the chain with type attest.anchor.upgraded, '
            . '(4) supersedes_envelope_id in the new payload matches previous_envelope_id.'
        );
    }
}
