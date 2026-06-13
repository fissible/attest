<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Command;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Command\UpgradeCommand;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
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

    /**
     * @param (callable(): OpenTimestampsCalendarClient)|null $calendarClientFactory
     */
    private function makeTester(?callable $calendarClientFactory = null): CommandTester
    {
        $application = new Application();
        $application->addCommand(new UpgradeCommand($calendarClientFactory));
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

    /**
     * @param list<Response> $responses
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     */
    private function calendarClient(array $responses, array &$transactions): OpenTimestampsCalendarClient
    {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($transactions));
        $http = new Client(['handler' => $stack]);
        $factory = new HttpFactory();

        return new OpenTimestampsCalendarClient($http, $factory, $factory);
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

    private function otsReceipt(
        FileChainStore $store,
        string $chainId,
        int $fromSeq,
        int $toSeq,
        ProofState $state,
    ): AnchorReceipt {
        $target = $this->targetFor($store, $chainId, $fromSeq, $toSeq);
        $rootBytes = hex2bin($target->rootHex);
        self::assertIsString($rootBytes);

        $timestamp = new OpenTimestampsTimestamp($rootBytes);
        if ($state === ProofState::PENDING) {
            $timestamp = $timestamp->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example'));
        } elseif ($state === ProofState::UPGRADED) {
            $timestamp = $timestamp->withAttestation(OpenTimestampsAttestation::bitcoin(840000));
        } else {
            throw new \InvalidArgumentException('OTS fixture receipts must be pending or upgraded');
        }

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: $state,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-06-06T00:00:00.000Z',
        );
    }

    private function appendOtsAnchorEnvelope(
        FileChainStore $store,
        string $chainId,
        AnchorReceipt $receipt,
    ): SignedEnvelope {
        $chain = EvidenceChain::open($store, $chainId, $this->signerFromKeyFile());
        if ($receipt->state === ProofState::UPGRADED) {
            return $chain->record(AnchorEnvelope::UPGRADED_TYPE, AnchorEnvelope::upgradedPayload($receipt));
        }

        return $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt));
    }

    private function bitcoinTimestampBytes(): string
    {
        return OpenTimestampsCodec::encodeTimestampBytes(
            (new OpenTimestampsTimestamp(str_repeat("\x00", 32)))
                ->withAttestation(OpenTimestampsAttestation::bitcoin(840000)),
        );
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
        $store = $this->buildChain('done', 2);
        $receipt = $this->otsReceipt($store, 'done', 1, 2, ProofState::UPGRADED);
        $anchorEnvelope = $this->appendOtsAnchorEnvelope($store, 'done', $receipt);
        $transactions = [];

        $tester = $this->makeTester(function () use (&$transactions): OpenTimestampsCalendarClient {
            return $this->calendarClient([], $transactions);
        });
        $exitCode = $tester->execute([
            ...$this->baseArgs('done'),
            '--anchor-id' => $receipt->anchorId,
            '--calendar-url' => ['https://calendar.example'],
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected idempotent exit 0; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame([], $payload['upgraded']);
        self::assertSame([], $payload['failed']);
        self::assertCount(1, $payload['unchanged']);
        self::assertSame($receipt->anchorId, $payload['unchanged'][0]['anchor_id']);
        self::assertSame($anchorEnvelope->envelope->id, $payload['unchanged'][0]['envelope_id']);
        self::assertSame('upgraded', $payload['unchanged'][0]['state']);
        self::assertSame([], $transactions);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 9 (incomplete): CalendarUnavailable continues in --all-pending mode
    // ────────────────────────────────────────────────────────────────────────

    public function test_calendar_unavailable_continues_to_next_anchor(): void
    {
        $store = $this->buildChain('sweep', 4);
        $first = $this->otsReceipt($store, 'sweep', 1, 2, ProofState::PENDING);
        $second = $this->otsReceipt($store, 'sweep', 3, 4, ProofState::PENDING);
        $firstEnvelope = $this->appendOtsAnchorEnvelope($store, 'sweep', $first);
        $this->appendOtsAnchorEnvelope($store, 'sweep', $second);
        $transactions = [];

        $tester = $this->makeTester(function () use (&$transactions): OpenTimestampsCalendarClient {
            return $this->calendarClient(
                [
                    new Response(503, [], 'calendar down'),
                    new Response(200, ['Content-Type' => OpenTimestampsCalendarClient::CONTENT_TYPE], $this->bitcoinTimestampBytes()),
                ],
                $transactions,
            );
        });
        $exitCode = $tester->execute([
            ...$this->baseArgs('sweep'),
            '--all-pending' => true,
            '--calendar-url' => ['https://calendar.example'],
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected best-effort sweep exit 0; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertCount(1, $payload['upgraded']);
        self::assertCount(1, $payload['unchanged']);
        self::assertSame([], $payload['failed']);
        self::assertSame($first->anchorId, $payload['unchanged'][0]['anchor_id']);
        self::assertSame($firstEnvelope->envelope->id, $payload['unchanged'][0]['envelope_id']);
        self::assertSame('pending', $payload['unchanged'][0]['state']);
        self::assertSame($second->anchorId, $payload['upgraded'][0]['anchor_id']);
        self::assertCount(2, $transactions);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 10 (incomplete): single --anchor-id succeeds → upgraded state + new envelope
    // ────────────────────────────────────────────────────────────────────────

    public function test_upgrades_single_anchor_id_to_upgraded_state(): void
    {
        $store = $this->buildChain('single', 2);
        $receipt = $this->otsReceipt($store, 'single', 1, 2, ProofState::PENDING);
        $anchorEnvelope = $this->appendOtsAnchorEnvelope($store, 'single', $receipt);
        $transactions = [];

        $tester = $this->makeTester(function () use (&$transactions): OpenTimestampsCalendarClient {
            return $this->calendarClient(
                [new Response(200, ['Content-Type' => OpenTimestampsCalendarClient::CONTENT_TYPE], $this->bitcoinTimestampBytes())],
                $transactions,
            );
        });
        $exitCode = $tester->execute([
            ...$this->baseArgs('single'),
            '--anchor-id' => $receipt->anchorId,
            '--calendar-url' => ['https://calendar.example'],
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected upgrade exit 0; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertCount(1, $payload['upgraded']);
        self::assertSame([], $payload['unchanged']);
        self::assertSame([], $payload['failed']);
        self::assertSame($receipt->anchorId, $payload['upgraded'][0]['anchor_id']);
        self::assertSame($anchorEnvelope->envelope->id, $payload['upgraded'][0]['previous_envelope_id']);
        self::assertNotSame($anchorEnvelope->envelope->id, $payload['upgraded'][0]['new_envelope_id']);

        $tail = $store->tail('single');
        self::assertNotNull($tail);
        self::assertSame(AnchorEnvelope::UPGRADED_TYPE, $tail->envelope->type);
        self::assertSame($payload['upgraded'][0]['new_envelope_id'], $tail->envelope->id);
        self::assertSame($anchorEnvelope->envelope->id, $tail->envelope->payload['supersedes_envelope_id']);
        self::assertSame('upgraded', $tail->envelope->payload['state']);
        self::assertCount(1, $transactions);
    }
}
