<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\AppendContext;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\EvidenceEnvelope;
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
use Symfony\Component\Uid\Ulid;

final class VerifierDetachedAnchorSigTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private KeyPair $trustedKp;
    private SodiumSigner $trustedSigner;
    private KeyPair $untrustedKp;
    private SodiumSigner $untrustedSigner;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-detached-anchor-sig-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->trustedKp = KeyPair::generate();
        $this->trustedSigner = new SodiumSigner($this->trustedKp, 'trusted-key');
        $this->untrustedKp = KeyPair::generate();
        $this->untrustedSigner = new SodiumSigner($this->untrustedKp, 'untrusted-key');
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_untrusted_detached_anchor_is_rejected_for_min_anchor_satisfaction(): void
    {
        // Build chain seqs 1..3 signed by trustedKp
        $records = $this->appendRecords(3);

        // Build a real anchor receipt for [1,3] via NullDriver
        $target = $this->targetFor($records);
        $receipt = (new NullDriver())->anchor($target);

        // Append an anchor envelope at seq 4 signed by untrustedKp
        $this->appendAnchorEnvelopeWithSigner($receipt, $this->untrustedSigner);

        // Verify [1,3] with requireTrustedKey=true, trusted set contains only trustedKp
        $result = $this->verifier(AnchorOutcome::LOCAL_ONLY)->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::ANCHOR_BELOW_MIN, $result->outcome);
        $warningCodes = array_map(static fn (Warning $w): string => $w->code, $result->warnings);
        $this->assertContains(Warning::DETACHED_ANCHOR_UNTRUSTED, $warningCodes);
    }

    public function test_invalid_detached_anchor_signature_drops_group_with_warning(): void
    {
        // Build chain seqs 1..3 signed by trustedKp
        $records = $this->appendRecords(3);

        // Build a proper anchor receipt for [1,3] via NullDriver
        $target = $this->targetFor($records);
        $receipt = (new NullDriver())->anchor($target);

        // Append an anchor envelope with a completely forged/broken signature
        $this->appendAnchorEnvelopeWithBrokenSig($receipt);

        // Verify [1,3] with trusted set containing only trustedKp
        $result = $this->verifier(AnchorOutcome::LOCAL_ONLY)->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::ANCHOR_BELOW_MIN, $result->outcome);
        $warningCodes = array_map(static fn (Warning $w): string => $w->code, $result->warnings);
        $this->assertContains(Warning::DETACHED_ANCHOR_INVALID_SIGNATURE, $warningCodes);
    }

    public function test_trusted_detached_anchor_satisfies_min_anchor(): void
    {
        // Build chain seqs 1..3 signed by trustedKp
        $records = $this->appendRecords(3);

        // Build a proper anchor receipt for [1,3] via NullDriver, append via trustedSigner
        $target = $this->targetFor($records);
        $receipt = (new NullDriver())->anchor($target);
        $this->appendAnchorEnvelopeWithSigner($receipt, $this->trustedSigner);

        // Verify [1,3] with trusted set containing trustedKp
        $result = $this->verifier(AnchorOutcome::LOCAL_ONLY)->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
    }

    /**
     * @return list<SignedEnvelope>
     */
    private function appendRecords(int $count): array
    {
        $chain = EvidenceChain::open($this->store, 'tenant:5', $this->trustedSigner);
        $records = [];
        for ($i = 1; $i <= $count; $i++) {
            $records[] = $chain->record('fixture.event', ['i' => $i]);
        }
        return $records;
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
                static fn (SignedEnvelope $s): string => $s->signedCanonicalBytes(),
                $records,
            )),
        );
    }

    private function appendAnchorEnvelopeWithSigner(AnchorReceipt $receipt, SodiumSigner $signer): SignedEnvelope
    {
        $chain = EvidenceChain::open($this->store, 'tenant:5', $signer);
        return $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt));
    }

    /**
     * Appends an anchor envelope whose Ed25519 signature is all-zeros
     * (i.e., cryptographically invalid against the payload).
     */
    private function appendAnchorEnvelopeWithBrokenSig(AnchorReceipt $receipt): SignedEnvelope
    {
        $payload = AnchorEnvelope::submittedPayload($receipt);
        $type = AnchorEnvelope::SUBMITTED_TYPE;
        $keyId = $this->trustedSigner->keyId();

        return $this->store->append('tenant:5', function (AppendContext $ctx) use ($type, $payload, $keyId): SignedEnvelope {
            $envelope = new EvidenceEnvelope(
                id: (string) Ulid::generate(),
                chain: $ctx->chainId,
                seq: $ctx->sequence,
                ts: $ctx->timestampIso8601,
                type: $type,
                payload: $payload,
                prevHash: $ctx->prevHash,
                keyId: $keyId,
                sigAlg: 'ed25519',
            );
            // 64 bytes of zeros — will not verify against the trusted public key
            $brokenSig = str_repeat("\x00", SODIUM_CRYPTO_SIGN_BYTES);
            return new SignedEnvelope($envelope, $brokenSig);
        });
    }

    private function verifier(AnchorOutcome $minimum): Verifier
    {
        return new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->trustedKp->publicKey, keyId: 'trusted-key')]),
            new VerificationPolicy(minAnchorOutcome: $minimum, requireTrustedKey: true),
            [new NullDriver()],
        );
    }
}
