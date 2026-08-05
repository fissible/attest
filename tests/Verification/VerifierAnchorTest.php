<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Headers\ActiveChainHeader;
use Fissible\Attest\Headers\BlockHeaderProvider;
use Fissible\Attest\Headers\HeaderLookupResult;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Headers\TrustLevel;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;

final class VerifierAnchorTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private KeyPair $keyPair;
    private SodiumSigner $signer;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-anchor-verify-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->keyPair = KeyPair::generate();
        $this->signer = new SodiumSigner($this->keyPair, 'app-prod');
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_pending_receipt_satisfies_pending_threshold(): void
    {
        $records = $this->appendRecords(2);
        $target = $this->targetFor($records);
        $this->appendAnchorReceipt($this->otsReceipt($target, ProofState::PENDING));

        $result = $this->verifier(AnchorOutcome::PENDING)->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::PENDING, $result->anchorVerification->outcome);
    }

    public function test_upgraded_receipt_with_no_providers_satisfies_upgraded_no_headers_threshold(): void
    {
        $records = $this->appendRecords(2);
        $target = $this->targetFor($records);
        $this->appendAnchorReceipt($this->otsReceipt($target, ProofState::UPGRADED, bitcoinHeight: 840000));

        $result = $this->verifier(AnchorOutcome::UPGRADED_NO_HEADERS)->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::UPGRADED_NO_HEADERS, $result->anchorVerification->outcome);
    }

    public function test_remote_provider_success_yields_remote_header_confirmed(): void
    {
        $records = $this->appendRecords(2);
        $target = $this->targetFor($records);
        $this->appendAnchorReceipt($this->otsReceipt($target, ProofState::UPGRADED, bitcoinHeight: 840000));

        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(new StaticHeaderProvider('esplora', TrustLevel::REMOTE, 840000, $target->rootHex)),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::REMOTE_HEADER_CONFIRMED, $result->anchorVerification->outcome);
        $this->assertSame('esplora', $result->anchorVerification->providerName);
    }

    public function test_local_provider_success_yields_bitcoin_verified(): void
    {
        $records = $this->appendRecords(2);
        $target = $this->targetFor($records);
        $this->appendAnchorReceipt($this->otsReceipt($target, ProofState::UPGRADED, bitcoinHeight: 840000));

        $result = $this->verifier(
            AnchorOutcome::BITCOIN_VERIFIED,
            new HeaderProviderSet(new StaticHeaderProvider('bitcoin-core', TrustLevel::LOCAL, 840000, $target->rootHex)),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::BITCOIN_VERIFIED, $result->anchorVerification->outcome);
        $this->assertSame('bitcoin-core', $result->anchorVerification->providerName);
    }

    public function test_anchor_range_with_root_mismatch_returns_invalid_anchor(): void
    {
        $records = $this->appendRecords(2);
        $target = $this->targetFor($records, rootHex: str_repeat('b', 64));
        $this->appendAnchorReceipt(new AnchorReceipt(
            driverName: NullDriver::NAME,
            target: $target,
            state: ProofState::SUBMITTED,
            receiptBytes: '',
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        ));

        $result = $this->verifier(AnchorOutcome::LOCAL_ONLY)->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::INVALID_ANCHOR, $result->outcome);
        $this->assertStringContainsString('root does not match', (string) $result->message);
    }

    public function test_missing_exact_anchor_with_threshold_returns_anchor_below_min(): void
    {
        $this->appendRecords(2);

        $result = $this->verifier(AnchorOutcome::PENDING)->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::ANCHOR_BELOW_MIN, $result->outcome);
        $this->assertStringContainsString('No exact anchor', (string) $result->message);
    }

    /**
     * @return list<SignedEnvelope>
     */
    private function appendRecords(int $count): array
    {
        $chain = EvidenceChain::open($this->store, 'tenant:5', $this->signer);
        $records = [];
        for ($i = 1; $i <= $count; $i++) {
            $records[] = $chain->record('fixture.event', ['i' => $i]);
        }

        return $records;
    }

    private function appendAnchorReceipt(AnchorReceipt $receipt): SignedEnvelope
    {
        $chain = EvidenceChain::open($this->store, 'tenant:5', $this->signer);
        if ($receipt->state === ProofState::UPGRADED) {
            return $chain->record(AnchorEnvelope::UPGRADED_TYPE, AnchorEnvelope::upgradedPayload($receipt));
        }

        return $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt));
    }

    /**
     * @param list<SignedEnvelope> $records
     */
    private function targetFor(array $records, ?string $rootHex = null): AnchorTarget
    {
        return new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: count($records),
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: $rootHex ?? MerkleTree::rootHex(array_map(
                static fn (SignedEnvelope $signed): string => $signed->signedCanonicalBytes(),
                $records,
            )),
        );
    }

    private function otsReceipt(AnchorTarget $target, ProofState $state, ?int $bitcoinHeight = null): AnchorReceipt
    {
        $rootBytes = hex2bin($target->rootHex);
        $this->assertIsString($rootBytes);
        $timestamp = new OpenTimestampsTimestamp($rootBytes);
        if ($state === ProofState::UPGRADED) {
            $this->assertIsInt($bitcoinHeight);
            $timestamp = $timestamp->withAttestation(OpenTimestampsAttestation::bitcoin($bitcoinHeight));
        } else {
            $timestamp = $timestamp->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example'));
        }

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: $state,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );
    }

    private function verifier(AnchorOutcome $minimum, ?HeaderProviderSet $headers = null): Verifier
    {
        return new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->keyPair->publicKey, keyId: 'app-prod')]),
            new VerificationPolicy(minAnchorOutcome: $minimum),
            [new NullDriver(), $this->otsDriver()],
            $headers ?? new HeaderProviderSet(),
        );
    }

    private function otsDriver(): OpenTimestampsDriver
    {
        $factory = new HttpFactory();

        return new OpenTimestampsDriver(
            new OpenTimestampsCalendarClient(
                new Client(['handler' => HandlerStack::create(new MockHandler([]))]),
                $factory,
                $factory,
            ),
            calendarUrls: ['https://calendar.example'],
        );
    }
}

final readonly class StaticHeaderProvider implements BlockHeaderProvider
{
    public function __construct(
        private string $providerName,
        private TrustLevel $trustLevel,
        private int $height,
        private string $merkleRoot,
    ) {
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
        if ($height !== $this->height) {
            return HeaderLookupResult::notFoundOrBehind($this->providerName, $this->trustLevel);
        }

        return HeaderLookupResult::active(
            $this->providerName,
            $this->trustLevel,
            new ActiveChainHeader(
                blockHash: str_repeat('1', 64),
                height: $height,
                confirmations: 7,
                merkleRoot: $this->merkleRoot,
                timeUnixSec: 1713571200,
            ),
        );
    }
}
