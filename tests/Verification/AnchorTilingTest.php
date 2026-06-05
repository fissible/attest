<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use Fissible\Attest\Verification\Warning;
use PHPUnit\Framework\TestCase;

final class AnchorTilingTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private KeyPair $keyPair;
    private SodiumSigner $signer;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-anchor-tiling-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->keyPair = KeyPair::generate();
        $this->signer = new SodiumSigner($this->keyPair, 'station-prod');
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_contiguous_anchor_tiling_verifies_requested_range(): void
    {
        $records = $this->appendRecords(6);
        $this->appendLocalAnchor($this->targetForRange($records, 1, 2));
        $this->appendLocalAnchor($this->targetForRange($records, 3, 4));
        $this->appendLocalAnchor($this->targetForRange($records, 5, 6));

        $result = $this->verifier()->verifyChain('tenant:5', 1, 6);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        $this->assertSame(AnchorOutcome::LOCAL_ONLY, $result->anchorVerification?->outcome);
    }

    public function test_gap_in_anchor_tiling_returns_below_min_with_uncovered_sequence_warning(): void
    {
        $records = $this->appendRecords(6);
        $this->appendLocalAnchor($this->targetForRange($records, 1, 2));
        $this->appendLocalAnchor($this->targetForRange($records, 4, 6));

        $result = $this->verifier()->verifyChain('tenant:5', 1, 6);

        $this->assertSame(VerificationOutcome::ANCHOR_BELOW_MIN, $result->outcome);
        $this->assertSame(Warning::ANCHOR_COVERAGE_GAP, $result->warnings[0]->code);
        $this->assertSame(3, $result->warnings[0]->context['uncovered_seq']);
    }

    public function test_overlapping_anchor_tiling_returns_below_min_with_ambiguous_warning(): void
    {
        $records = $this->appendRecords(6);
        $first = $this->localReceipt($this->targetForRange($records, 1, 4));
        $second = $this->localReceipt($this->targetForRange($records, 3, 6));
        $this->appendAnchorReceipt($first);
        $this->appendAnchorReceipt($second);

        $result = $this->verifier()->verifyChain('tenant:5', 1, 6);

        $this->assertSame(VerificationOutcome::ANCHOR_BELOW_MIN, $result->outcome);
        $this->assertSame(Warning::ANCHOR_COVERAGE_AMBIGUOUS, $result->warnings[0]->code);
        $this->assertEqualsCanonicalizing(
            [$first->anchorId, $second->anchorId],
            $result->warnings[0]->context['anchor_ids'],
        );
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

    private function appendLocalAnchor(AnchorTarget $target): SignedEnvelope
    {
        return $this->appendAnchorReceipt($this->localReceipt($target));
    }

    private function appendAnchorReceipt(AnchorReceipt $receipt): SignedEnvelope
    {
        return EvidenceChain::open($this->store, 'tenant:5', $this->signer)
            ->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt));
    }

    /**
     * @param list<SignedEnvelope> $records
     */
    private function targetForRange(array $records, int $fromSeq, int $toSeq): AnchorTarget
    {
        return new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: $fromSeq,
            toSeq: $toSeq,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: MerkleTree::rootHex(array_map(
                static fn (SignedEnvelope $signed): string => $signed->signedCanonicalBytes(),
                array_slice($records, $fromSeq - 1, $toSeq - $fromSeq + 1),
            )),
        );
    }

    private function localReceipt(AnchorTarget $target): AnchorReceipt
    {
        return new AnchorReceipt(
            driverName: NullDriver::NAME,
            target: $target,
            state: ProofState::SUBMITTED,
            receiptBytes: '',
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );
    }

    private function verifier(): Verifier
    {
        return new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->keyPair->publicKey, keyId: 'station-prod')]),
            new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY),
            [new NullDriver()],
        );
    }
}
