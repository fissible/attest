<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Chain\AppendContext;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\PathMapper;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use Fissible\Attest\Verification\Warning;
use PHPUnit\Framework\TestCase;

final class VerifierChainTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private KeyPair $keyPair;
    private SodiumSigner $signer;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-verify-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->keyPair = KeyPair::generate();
        $this->signer = new SodiumSigner($this->keyPair, 'station-prod');
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_valid_chain_returns_verified(): void
    {
        $this->appendRecords(3);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertTrue($result->isVerified());
        $this->assertSame(3, $result->stats->envelopeCount);
        $this->assertSame(3, $result->stats->trustedSignatureCount);
        $this->assertSame(0, $result->stats->untrustedSignatureCount);
        $this->assertSame([], $result->warnings);
    }

    public function test_broken_sequence_returns_invalid_chain(): void
    {
        $records = $this->appendRecords(2);
        $badSecond = new SignedEnvelope(
            new EvidenceEnvelope(
                id: $records[1]->envelope->id,
                chain: $records[1]->envelope->chain,
                seq: 3,
                ts: $records[1]->envelope->ts,
                type: $records[1]->envelope->type,
                payload: $records[1]->envelope->payload,
                prevHash: $records[1]->envelope->prevHash,
                keyId: $records[1]->envelope->keyId,
                sigAlg: $records[1]->envelope->sigAlg,
            ),
            $records[1]->sig,
        );
        $this->writeRawChain([$records[0]->signedCanonicalBytes(), $badSecond->signedCanonicalBytes()]);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::INVALID_CHAIN, $result->outcome);
        $this->assertSame(2, $result->brokenAtSeq);
        $this->assertStringContainsString('sequence 2', (string) $result->message);
    }

    public function test_broken_prev_hash_returns_invalid_chain(): void
    {
        $records = $this->appendRecords(2);
        $badSecondEnvelope = new EvidenceEnvelope(
            id: $records[1]->envelope->id,
            chain: $records[1]->envelope->chain,
            seq: $records[1]->envelope->seq,
            ts: $records[1]->envelope->ts,
            type: $records[1]->envelope->type,
            payload: $records[1]->envelope->payload,
            prevHash: 'sha256:not-the-previous-hash',
            keyId: $records[1]->envelope->keyId,
            sigAlg: $records[1]->envelope->sigAlg,
        );
        $badSecond = SignedEnvelope::sign($badSecondEnvelope, $this->signer);
        $this->writeRawChain([$records[0]->signedCanonicalBytes(), $badSecond->signedCanonicalBytes()]);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::INVALID_CHAIN, $result->outcome);
        $this->assertSame(2, $result->brokenAtSeq);
        $this->assertStringContainsString('prev_hash', (string) $result->message);
    }

    public function test_subrange_verification_validates_first_prev_hash_against_prior_envelope(): void
    {
        $records = $this->appendRecords(3);
        $badSecondEnvelope = new EvidenceEnvelope(
            id: $records[1]->envelope->id,
            chain: $records[1]->envelope->chain,
            seq: $records[1]->envelope->seq,
            ts: $records[1]->envelope->ts,
            type: $records[1]->envelope->type,
            payload: $records[1]->envelope->payload,
            prevHash: 'sha256:not-the-previous-hash',
            keyId: $records[1]->envelope->keyId,
            sigAlg: $records[1]->envelope->sigAlg,
        );
        $badSecond = SignedEnvelope::sign($badSecondEnvelope, $this->signer);
        $this->writeRawChain([
            $records[0]->signedCanonicalBytes(),
            $badSecond->signedCanonicalBytes(),
            $records[2]->signedCanonicalBytes(),
        ]);

        $result = $this->verifier()->verifyChain('tenant:5', 2, 3);

        $this->assertSame(VerificationOutcome::INVALID_CHAIN, $result->outcome);
        $this->assertSame(2, $result->brokenAtSeq);
        $this->assertStringContainsString('prev_hash', (string) $result->message);
    }

    public function test_mutated_raw_bytes_that_decode_to_same_envelope_return_invalid_chain(): void
    {
        $records = $this->appendRecords(1);
        $this->writeRawChain([$records[0]->signedCanonicalBytes() . ' ']);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 1);

        $this->assertSame(VerificationOutcome::INVALID_CHAIN, $result->outcome);
        $this->assertSame(1, $result->brokenAtSeq);
        $this->assertStringContainsString('canonical', (string) $result->message);
    }

    public function test_tampered_payload_returns_invalid_signature(): void
    {
        $records = $this->appendRecords(1);
        $tampered = new SignedEnvelope(
            new EvidenceEnvelope(
                id: $records[0]->envelope->id,
                chain: $records[0]->envelope->chain,
                seq: $records[0]->envelope->seq,
                ts: $records[0]->envelope->ts,
                type: $records[0]->envelope->type,
                payload: ['i' => 999],
                prevHash: $records[0]->envelope->prevHash,
                keyId: $records[0]->envelope->keyId,
                sigAlg: $records[0]->envelope->sigAlg,
            ),
            $records[0]->sig,
        );
        $this->writeRawChain([$tampered->signedCanonicalBytes()]);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 1);

        $this->assertSame(VerificationOutcome::INVALID_SIGNATURE, $result->outcome);
        $this->assertSame(1, $result->brokenAtSeq);
        $this->assertStringContainsString('did not verify', (string) $result->message);
    }

    public function test_valid_signatures_with_no_trusted_key_return_untrusted_integrity(): void
    {
        $this->appendRecords(2);

        $result = (new Verifier(
            $this->store,
            new SignatureVerifier([]),
        ))->verifyChain('tenant:5', 1, 2);

        $this->assertSame(VerificationOutcome::INTEGRITY_VERIFIED_UNTRUSTED, $result->outcome);
        $this->assertSame(2, $result->stats->untrustedSignatureCount);
        $this->assertFalse($result->signatureResults[0]->invalid);
    }

    public function test_policy_can_allow_untrusted_signatures(): void
    {
        $this->appendRecords(1);

        $result = (new Verifier(
            $this->store,
            new SignatureVerifier([]),
            new VerificationPolicy(requireTrustedKey: false),
        ))->verifyChain('tenant:5', 1, 1);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
    }

    public function test_missing_raw_byte_capability_adds_warning(): void
    {
        $this->appendRecords(1);
        $store = new class ($this->store) implements ChainStore {
            public function __construct(private readonly ChainStore $inner)
            {
            }

            public function append(string $chainId, callable $buildAndSign): SignedEnvelope
            {
                return $this->inner->append($chainId, $buildAndSign);
            }

            public function tail(string $chainId): ?SignedEnvelope
            {
                return $this->inner->tail($chainId);
            }

            public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
            {
                return $this->inner->readRange($chainId, $fromSeq, $toSeq);
            }

            public function listChains(): iterable
            {
                return $this->inner->listChains();
            }

            public function exists(string $chainId): bool
            {
                return $this->inner->exists($chainId);
            }
        };

        $result = (new Verifier(
            $store,
            new SignatureVerifier([new TrustedKey($this->keyPair->publicKey, keyId: 'station-prod')]),
        ))->verifyChain('tenant:5', 1, 1);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertCount(1, $result->warnings);
        $this->assertSame(Warning::NO_RAW_BYTES, $result->warnings[0]->code);
    }

    public function test_missing_requested_sequence_returns_invalid_chain(): void
    {
        $this->appendRecords(2);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::INVALID_CHAIN, $result->outcome);
        $this->assertSame(3, $result->brokenAtSeq);
        $this->assertStringContainsString('Missing envelope', (string) $result->message);
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

    /**
     * @param list<string> $rawLines
     */
    private function writeRawChain(array $rawLines): void
    {
        $mapper = new PathMapper($this->root);
        $path = $mapper->jsonlPath('tenant:5');
        @mkdir(dirname($path), 0o700, recursive: true);
        file_put_contents($path, implode("\n", $rawLines) . "\n");
    }

    private function verifier(): Verifier
    {
        return new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->keyPair->publicKey, keyId: 'station-prod')]),
        );
    }
}
