<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\NullDriver;
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

final class VerifierDetachedInputTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private KeyPair $trustedKp;
    private SodiumSigner $trustedSigner;
    private KeyPair $untrustedKp;
    private SodiumSigner $untrustedSigner;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-verifier-detached-input-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->trustedKp = KeyPair::generate();
        $this->trustedSigner = new SodiumSigner($this->trustedKp, 'k1');
        $this->untrustedKp = KeyPair::generate();
        $this->untrustedSigner = new SodiumSigner($this->untrustedKp, 'k2');
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_verifier_accepts_explicit_detached_anchor_envelopes_for_min_anchor(): void
    {
        // Build chain seqs 1-3 signed by trustedKp
        $records = $this->appendRecords(3);

        // Compute Merkle root over in-chain envelopes [1,3]
        $bytes = [];
        foreach ($this->store->readRange('tenant:5', 1, 3) as $env) {
            $bytes[] = $env->signedCanonicalBytes();
        }
        $computedRoot = MerkleTree::rootHex($bytes);

        // Derive anchor id for [1,3] via NullDriver
        $target = new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: 3,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: $computedRoot,
        );
        $derivedAnchorId = AnchorId::derive($target, NullDriver::NAME);

        // Build the out-of-band anchor envelope (not appended to the chain)
        $detachedEnv = new EvidenceEnvelope(
            id: (string) Ulid::generate(),
            chain: 'tenant:5',
            seq: 9999,
            ts: gmdate('Y-m-d\TH:i:s.v\Z'),
            type: 'attest.anchor.submitted',
            payload: [
                'anchor_id' => $derivedAnchorId,
                'target_chain' => 'tenant:5',
                'from_seq' => 1,
                'to_seq' => 3,
                'merkle_algorithm' => MerkleTree::ALGORITHM,
                'root' => $computedRoot,
                'driver' => NullDriver::NAME,
                'state' => 'submitted',
                'receipt_bytes' => 'base64:',
                'anchored_at' => gmdate('c'),
            ],
            prevHash: null,
            keyId: 'k1',
            sigAlg: 'ed25519',
        );
        $signedDetached = SignedEnvelope::sign($detachedEnv, $this->trustedSigner);

        $verifier = new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->trustedKp->publicKey, keyId: 'k1')]),
            new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY, requireTrustedKey: true),
            [new NullDriver()],
            detachedAnchorEnvelopes: [$signedDetached],
        );

        $result = $verifier->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
    }

    public function test_explicit_detached_envelopes_are_classified_by_signature(): void
    {
        // Build chain seqs 1-3 signed by trustedKp
        $records = $this->appendRecords(3);

        // Compute Merkle root over in-chain envelopes [1,3]
        $bytes = [];
        foreach ($this->store->readRange('tenant:5', 1, 3) as $env) {
            $bytes[] = $env->signedCanonicalBytes();
        }
        $computedRoot = MerkleTree::rootHex($bytes);

        // Derive anchor id for [1,3] via NullDriver
        $target = new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: 3,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: $computedRoot,
        );
        $derivedAnchorId = AnchorId::derive($target, NullDriver::NAME);

        // Build out-of-band anchor envelope signed by the UNTRUSTED keypair
        $detachedEnv = new EvidenceEnvelope(
            id: (string) Ulid::generate(),
            chain: 'tenant:5',
            seq: 9999,
            ts: gmdate('Y-m-d\TH:i:s.v\Z'),
            type: 'attest.anchor.submitted',
            payload: [
                'anchor_id' => $derivedAnchorId,
                'target_chain' => 'tenant:5',
                'from_seq' => 1,
                'to_seq' => 3,
                'merkle_algorithm' => MerkleTree::ALGORITHM,
                'root' => $computedRoot,
                'driver' => NullDriver::NAME,
                'state' => 'submitted',
                'receipt_bytes' => 'base64:',
                'anchored_at' => gmdate('c'),
            ],
            prevHash: null,
            keyId: 'k2',
            sigAlg: 'ed25519',
        );
        $signedDetached = SignedEnvelope::sign($detachedEnv, $this->untrustedSigner);

        // Verifier only trusts trustedKp (k1), not untrustedKp (k2)
        $verifier = new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->trustedKp->publicKey, keyId: 'k1')]),
            new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY, requireTrustedKey: true),
            [new NullDriver()],
            detachedAnchorEnvelopes: [$signedDetached],
        );

        $result = $verifier->verifyChain('tenant:5', 1, 3);

        $this->assertSame(VerificationOutcome::ANCHOR_BELOW_MIN, $result->outcome);
        $warningCodes = array_map(static fn (Warning $w): string => $w->code, $result->warnings);
        $this->assertContains(Warning::DETACHED_ANCHOR_UNTRUSTED, $warningCodes);
    }

    public function test_in_chain_and_explicit_detached_envelopes_merge_by_anchor_id(): void
    {
        // Build chain seqs 1-3 signed by trustedKp
        $records = $this->appendRecords(3);

        // Compute Merkle root over in-chain envelopes [1,3]
        $bytes = [];
        foreach ($this->store->readRange('tenant:5', 1, 3) as $env) {
            $bytes[] = $env->signedCanonicalBytes();
        }
        $computedRoot = MerkleTree::rootHex($bytes);

        // Derive anchor id for [1,3] via NullDriver
        $target = new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: 3,
            merkleAlgorithm: MerkleTree::ALGORITHM,
            rootHex: $computedRoot,
        );
        $derivedAnchorId = AnchorId::derive($target, NullDriver::NAME);
        $anchorPayload = [
            'anchor_id' => $derivedAnchorId,
            'target_chain' => 'tenant:5',
            'from_seq' => 1,
            'to_seq' => 3,
            'merkle_algorithm' => MerkleTree::ALGORITHM,
            'root' => $computedRoot,
            'driver' => NullDriver::NAME,
            'state' => 'submitted',
            'receipt_bytes' => 'base64:',
            'anchored_at' => gmdate('c'),
        ];

        // Append a TRUSTED anchor envelope at seq 4 (in-chain)
        $trustedChain = EvidenceChain::open($this->store, 'tenant:5', $this->trustedSigner);
        $trustedChain->record('attest.anchor.submitted', $anchorPayload);

        // Construct an UNTRUSTED out-of-band envelope with the SAME anchor_id for [1,3]
        $untrustedEnv = new EvidenceEnvelope(
            id: (string) Ulid::generate(),
            chain: 'tenant:5',
            seq: 9998,
            ts: gmdate('Y-m-d\TH:i:s.v\Z'),
            type: 'attest.anchor.submitted',
            payload: $anchorPayload,
            prevHash: null,
            keyId: 'k2',
            sigAlg: 'ed25519',
        );
        $untrustedDetached = SignedEnvelope::sign($untrustedEnv, $this->untrustedSigner);

        // Verifier only trusts trustedKp (k1), not untrustedKp (k2)
        // The in-chain envelope (trusted) and the explicit detached (untrusted) share the same
        // anchor_id group. Because at least one classification is TRUSTED, $allUntrusted is false,
        // so the group is kept and the outcome should be VERIFIED.
        $verifier = new Verifier(
            $this->store,
            new SignatureVerifier([new TrustedKey($this->trustedKp->publicKey, keyId: 'k1')]),
            new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY, requireTrustedKey: true),
            [new NullDriver()],
            detachedAnchorEnvelopes: [$untrustedDetached],
        );

        $result = $verifier->verifyChain('tenant:5', 1, 3);

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
}
