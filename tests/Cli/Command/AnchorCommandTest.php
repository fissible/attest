<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Command;

use Fissible\Attest\Anchor\AnchorClaim;
use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Command\AnchorCommand;
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

final class AnchorCommandTest extends TestCase
{
    private string $tmpDir;
    private string $keyFile;
    private string $keyId = 'test-key';

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-anchor-cmd-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);

        // Create a deterministic key file from a random seed.
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
        $application->addCommand(new AnchorCommand($calendarClientFactory));
        $application->setAutoExit(false);
        $command = $application->find('anchor');
        return new CommandTester($command);
    }

    /**
     * Load the signer from the test key file (mirrors AnchorCommand logic).
     */
    private function signerFromKeyFile(): SodiumSigner
    {
        $b64 = trim((string) file_get_contents($this->keyFile));
        $seed = base64_decode($b64, strict: true);
        assert($seed !== false);
        return new SodiumSigner(KeyPair::fromSeed($seed), $this->keyId);
    }

    /**
     * Build a chain with N envelopes, return the store.
     */
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
    private function baseArgs(string $chainId, int $from, int $to): array
    {
        return [
            '--storage-root'   => $this->tmpDir,
            '--chain'          => $chainId,
            '--from'           => (string) $from,
            '--to'             => (string) $to,
            '--driver'         => 'local-only',
            '--signer-key-file'=> $this->keyFile,
            '--signer-key-id'  => $this->keyId,
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

    private function pendingTimestampBytes(): string
    {
        return OpenTimestampsCodec::encodeTimestampBytes(
            (new OpenTimestampsTimestamp(str_repeat("\x00", 32)))
                ->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example')),
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 1: local-only driver anchors successfully, exits 0, JSON output ok
    // ────────────────────────────────────────────────────────────────────────

    public function test_anchors_range_with_null_driver_and_exits_0(): void
    {
        $this->buildChain('tenant:5', 3);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('tenant:5', 1, 3),
            '--json' => true,
        ]);

        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $tester->getDisplay());

        $payload = json_decode($tester->getDisplay(), true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('attest.cli.anchor.v1', $payload['format_version']);
        self::assertSame('anchor', $payload['command']);
        self::assertSame('anchored', $payload['result']);
        self::assertSame('submitted', $payload['state']);
        self::assertSame('local-only', $payload['driver']);
        self::assertSame('tenant:5', $payload['target_chain']);
        self::assertSame(1, $payload['from_seq']);
        self::assertSame(3, $payload['to_seq']);
        self::assertNotNull($payload['anchor_id']);
        self::assertNotNull($payload['envelope_id']);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 2: opentimestamps driver (OTS calendar mocking not wired)
    // ────────────────────────────────────────────────────────────────────────

    public function test_anchors_range_with_opentimestamps_driver_via_mocked_calendar_client(): void
    {
        $this->buildChain('tenant:5', 3);
        $transactions = [];

        $tester = $this->makeTester(function () use (&$transactions): OpenTimestampsCalendarClient {
            return $this->calendarClient(
                [new Response(200, ['Content-Type' => OpenTimestampsCalendarClient::CONTENT_TYPE], $this->pendingTimestampBytes())],
                $transactions,
            );
        });

        $exitCode = $tester->execute([
            ...$this->baseArgs('tenant:5', 1, 3),
            '--driver' => 'opentimestamps',
            '--calendar-url' => ['https://calendar.example'],
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected exit 0; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('attest.cli.anchor.v1', $payload['format_version']);
        self::assertSame('anchored', $payload['result']);
        self::assertSame('pending', $payload['state']);
        self::assertSame('opentimestamps', $payload['driver']);
        self::assertNotNull($payload['anchor_id']);
        self::assertNotNull($payload['envelope_id']);

        self::assertCount(1, $transactions);
        self::assertSame('POST', $transactions[0]['request']->getMethod());
        self::assertSame('https://calendar.example/digest', (string) $transactions[0]['request']->getUri());
        self::assertSame(OpenTimestampsCalendarClient::CONTENT_TYPE, $transactions[0]['request']->getHeaderLine('Content-Type'));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 3: claim already held by another worker → skipped, exit 0
    // ────────────────────────────────────────────────────────────────────────

    public function test_skipped_when_claim_already_held_exits_0_with_warning(): void
    {
        // Build the chain so anchor_id can be derived.
        $store  = $this->buildChain('c', 2);
        $signer = $this->signerFromKeyFile();

        // Compute anchor_id for [1,2] with NullDriver (mirrors AnchorService).
        $rawBytes = iterator_to_array($store->readRawRange('c', 1, 2), false);
        $target   = new AnchorTarget(
            chainId: 'c',
            fromSeq: 1,
            toSeq: 2,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex($rawBytes),
        );
        $anchorId = AnchorId::derive($target, NullDriver::NAME);

        // Pre-create a claim so the AnchorService sees it as held.
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $claimStore->claim($anchorId, new AnchorClaim(
            chainId: 'c',
            fromSeq: 1,
            toSeq: 2,
            driver: NullDriver::NAME,
            claimedBy: 'some-other-worker',
            claimedAtIso8601: '2000-01-01T00:00:00.000Z',
        ));
        // Do NOT append an anchor envelope → reconcileExistingAnchor returns null → skipped.

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('c', 1, 2),
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected exit 0 for skipped case; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('skipped', $payload['result'], 'Result must be skipped; got: ' . $payload['result']);
        self::assertNotEmpty($payload['warnings'], 'warnings must be non-empty for skipped case');
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 4: claim held + existing envelope → reconciled, exit 0
    // ────────────────────────────────────────────────────────────────────────

    public function test_reconciles_existing_anchor_envelope_exits_0(): void
    {
        // First anchor run: creates envelope + completed claim.
        $store  = $this->buildChain('r', 3);
        $signer = $this->signerFromKeyFile();
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service    = new AnchorService($store, $claimStore, $signer);
        $firstEnvelope = $service->anchorRange('r', 1, 3, new NullDriver());
        self::assertNotNull($firstEnvelope, 'First anchor call must succeed');

        // The claim is now completed and the envelope is in the chain.
        // Second call to anchorRange: claimStore->claim() returns false because
        // the claim dir already exists; reconcileExistingAnchor finds the envelope.
        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            ...$this->baseArgs('r', 1, 3),
            '--json' => true,
        ]);

        $display = $tester->getDisplay();
        self::assertSame(0, $exitCode, 'Expected exit 0 for reconciled case; output: ' . $display);

        $payload = json_decode($display, true);
        self::assertIsArray($payload, 'Output must be valid JSON');
        self::assertSame('reconciled', $payload['result'], 'Result must be reconciled; full output: ' . $display);
        self::assertSame($firstEnvelope->envelope->id, $payload['envelope_id'],
            'envelope_id must match the first anchor envelope'
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 5: CalendarUnavailable → exit 4 (OTS mocking not wired)
    // ────────────────────────────────────────────────────────────────────────

    public function test_calendar_unavailable_exits_4(): void
    {
        $this->buildChain('cu', 2);
        $transactions = [];

        $tester = $this->makeTester(function () use (&$transactions): OpenTimestampsCalendarClient {
            return $this->calendarClient(
                [new Response(503, [], 'calendar down')],
                $transactions,
            );
        });

        $exitCode = $tester->execute([
            ...$this->baseArgs('cu', 1, 2),
            '--driver' => 'opentimestamps',
            '--calendar-url' => ['https://calendar.example'],
        ]);

        self::assertSame(4, $exitCode, 'Expected exit 4; output: ' . $tester->getDisplay());
        self::assertStringContainsString('calendar unavailable', strtolower($tester->getDisplay()));
        self::assertCount(1, $transactions);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 6: missing --driver exits 1
    // ────────────────────────────────────────────────────────────────────────

    public function test_missing_driver_option_exits_1(): void
    {
        $this->buildChain('d', 1);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root'    => $this->tmpDir,
            '--chain'           => 'd',
            '--from'            => '1',
            '--to'              => '1',
            // --driver deliberately omitted
            '--signer-key-file' => $this->keyFile,
            '--signer-key-id'   => $this->keyId,
        ]);

        self::assertSame(1, $exitCode, 'Expected exit 1 for missing --driver');
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Test 7: missing --signer-key-file exits 1
    // ────────────────────────────────────────────────────────────────────────

    public function test_missing_signer_key_exits_1(): void
    {
        $this->buildChain('s', 1);

        $tester   = $this->makeTester();
        $exitCode = $tester->execute([
            '--storage-root'   => $this->tmpDir,
            '--chain'          => 's',
            '--from'           => '1',
            '--to'             => '1',
            '--driver'         => 'local-only',
            // --signer-key-file deliberately omitted
            '--signer-key-id'  => $this->keyId,
        ]);

        self::assertSame(1, $exitCode, 'Expected exit 1 for missing --signer-key-file');
        self::assertStringContainsString('error', strtolower($tester->getDisplay()));
    }
}
