<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorOutcome;
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
use Fissible\Attest\Verification\Warning;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;

final class ProviderDisagreementTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private KeyPair $keyPair;
    private SodiumSigner $signer;
    private AnchorTarget $target;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-provider-disagreement-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->keyPair = KeyPair::generate();
        $this->signer = new SodiumSigner($this->keyPair, 'station-prod');

        $records = $this->appendRecords(2);
        $this->target = $this->targetFor($records);
        $this->appendAnchorReceipt($this->otsReceipt($this->target, 840000));
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_local_and_remote_pass_with_same_hash_yields_bitcoin_verified(): void
    {
        $result = $this->verifier(
            AnchorOutcome::BITCOIN_VERIFIED,
            new HeaderProviderSet(
                VotingHeaderProvider::pass('bitcoin-core', TrustLevel::LOCAL, $this->target->rootHex, blockHash: str_repeat('1', 64)),
                VotingHeaderProvider::pass('esplora', TrustLevel::REMOTE, $this->target->rootHex, blockHash: str_repeat('1', 64)),
            ),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::BITCOIN_VERIFIED, $result->anchorVerification->outcome);
    }

    public function test_passing_providers_with_different_hashes_are_provider_disagreement(): void
    {
        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(
                VotingHeaderProvider::pass('bitcoin-core', TrustLevel::LOCAL, $this->target->rootHex, blockHash: str_repeat('1', 64)),
                VotingHeaderProvider::pass('esplora', TrustLevel::REMOTE, $this->target->rootHex, blockHash: str_repeat('2', 64)),
            ),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::PROVIDER_DISAGREEMENT, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::PROVIDER_DISAGREEMENT, $result->anchorVerification->outcome);
        $this->assertArrayHasKey('active_hashes_by_provider', $result->anchorVerification->context);
    }

    public function test_remote_pass_only_yields_remote_header_confirmed(): void
    {
        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(
                VotingHeaderProvider::pass('esplora', TrustLevel::REMOTE, $this->target->rootHex),
            ),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::REMOTE_HEADER_CONFIRMED, $result->anchorVerification->outcome);
    }

    public function test_pass_plus_mismatch_is_provider_disagreement(): void
    {
        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(
                VotingHeaderProvider::pass('bitcoin-core', TrustLevel::LOCAL, $this->target->rootHex),
                VotingHeaderProvider::mismatch('esplora', TrustLevel::REMOTE),
            ),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::PROVIDER_DISAGREEMENT, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(['bitcoin-core'], $result->anchorVerification->context['passing_providers']);
        $this->assertSame(['esplora'], $result->anchorVerification->context['mismatching_providers']);
    }

    public function test_unknown_plus_remote_pass_yields_remote_confirmed_with_warning(): void
    {
        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(
                VotingHeaderProvider::unknown('bitcoin-core', TrustLevel::LOCAL),
                VotingHeaderProvider::pass('esplora', TrustLevel::REMOTE, $this->target->rootHex),
            ),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::REMOTE_HEADER_CONFIRMED, $result->anchorVerification->outcome);
        $this->assertSame(Warning::HEADER_PROVIDER_UNKNOWN, $result->warnings[0]->code);
    }

    public function test_mismatch_plus_unknown_is_invalid_anchor(): void
    {
        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(
                VotingHeaderProvider::mismatch('bitcoin-core', TrustLevel::LOCAL),
                VotingHeaderProvider::unknown('esplora', TrustLevel::REMOTE),
            ),
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::INVALID_ANCHOR, $result->outcome);
        $this->assertStringContainsString('did not match', (string) $result->message);
    }

    public function test_policy_can_allow_disagreement_and_use_strongest_passing_outcome(): void
    {
        $result = $this->verifier(
            AnchorOutcome::BITCOIN_VERIFIED,
            new HeaderProviderSet(
                VotingHeaderProvider::pass('bitcoin-core', TrustLevel::LOCAL, $this->target->rootHex),
                VotingHeaderProvider::mismatch('esplora', TrustLevel::REMOTE),
            ),
            allowProviderDisagreement: true,
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertSame(AnchorOutcome::BITCOIN_VERIFIED, $result->anchorVerification->outcome);
        $this->assertSame(Warning::PROVIDER_DISAGREEMENT_ALLOWED, $result->warnings[0]->code);
    }

    public function test_policy_cannot_downgrade_hash_conflict_without_agreed_passing_hash(): void
    {
        $result = $this->verifier(
            AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            new HeaderProviderSet(
                VotingHeaderProvider::pass('bitcoin-core', TrustLevel::LOCAL, $this->target->rootHex, blockHash: str_repeat('1', 64)),
                VotingHeaderProvider::pass('esplora', TrustLevel::REMOTE, $this->target->rootHex, blockHash: str_repeat('2', 64)),
            ),
            allowProviderDisagreement: true,
        )->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::PROVIDER_DISAGREEMENT, $result->outcome);
        $this->assertNotNull($result->anchorVerification);
        $this->assertNull($result->anchorVerification->strongestPassingOutcome);
        $this->assertNull($result->anchorVerification->context['agreed_passing_hash']);
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
        return EvidenceChain::open($this->store, 'tenant:5', $this->signer)
            ->record(AnchorEnvelope::UPGRADED_TYPE, AnchorEnvelope::upgradedPayload($receipt));
    }

    /**
     * @param list<SignedEnvelope> $records
     */
    private function targetFor(array $records): AnchorTarget
    {
        return new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: count($records),
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex(array_map(
                static fn (SignedEnvelope $signed): string => $signed->signedCanonicalBytes(),
                $records,
            )),
        );
    }

    private function otsReceipt(AnchorTarget $target, int $bitcoinHeight): AnchorReceipt
    {
        $rootBytes = hex2bin($target->rootHex);
        $this->assertIsString($rootBytes);
        $timestamp = (new OpenTimestampsTimestamp($rootBytes))
            ->withAttestation(OpenTimestampsAttestation::bitcoin($bitcoinHeight));

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: ProofState::UPGRADED,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );
    }

    private function verifier(
        AnchorOutcome $minimum,
        HeaderProviderSet $headers,
        bool $allowProviderDisagreement = false,
    ): Verifier {
        return new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->keyPair->publicKey, keyId: 'station-prod')]),
            new VerificationPolicy(
                minAnchorOutcome: $minimum,
                allowProviderDisagreement: $allowProviderDisagreement,
            ),
            [$this->otsDriver()],
            $headers,
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

final readonly class VotingHeaderProvider implements BlockHeaderProvider
{
    private function __construct(
        private string $providerName,
        private TrustLevel $trustLevel,
        private string $mode,
        private string $merkleRoot,
        private string $blockHash,
    ) {
    }

    public static function pass(
        string $name,
        TrustLevel $trustLevel,
        string $merkleRoot,
        string $blockHash = '3333333333333333333333333333333333333333333333333333333333333333',
    ): self {
        return new self($name, $trustLevel, 'pass', $merkleRoot, $blockHash);
    }

    public static function mismatch(string $name, TrustLevel $trustLevel): self
    {
        return new self($name, $trustLevel, 'mismatch', str_repeat('f', 64), str_repeat('3', 64));
    }

    public static function unknown(string $name, TrustLevel $trustLevel): self
    {
        return new self($name, $trustLevel, 'unknown', str_repeat('0', 64), str_repeat('0', 64));
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
        if ($this->mode === 'unknown') {
            return HeaderLookupResult::providerError($this->providerName, $this->trustLevel, 'provider unavailable');
        }

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
