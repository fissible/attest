<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Bundle\BundleReader;
use Fissible\Attest\Bundle\BundleStore;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use Fissible\Attest\Anchor\AnchorOutcome;
use PHPUnit\Framework\TestCase;

final class BundleRoundTripTest extends TestCase
{
    private string $tmpDir;
    private string $bundleDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-bundle-roundtrip-' . bin2hex(random_bytes(8));
        $this->bundleDir = $this->tmpDir . '/out';
        mkdir($this->tmpDir, 0o700, recursive: true);
        mkdir($this->bundleDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_bundle_verifies_with_same_outcome_as_live_chain(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');

        // Build chain seqs 1-5
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        for ($i = 1; $i <= 5; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }

        // Anchor [1,5] with NullDriver via AnchorService
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('tenant:5', 1, 5, new NullDriver());

        $sigVerifier = new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'k1')]);
        $policy = new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY, requireTrustedKey: true);

        // Live chain verification
        $liveVerifier = new Verifier($store, $sigVerifier, $policy, [new NullDriver()]);
        $liveResult = $liveVerifier->verifyChain('tenant:5', 1, 5);

        $this->assertSame(VerificationOutcome::VERIFIED, $liveResult->outcome);

        // Export the chain to a bundle
        $bundlePath = $this->bundleDir . '/incident.attest';
        BundleExporter::create($store)
            ->forChainSegment('tenant:5', 1, 5)
            ->withClaimedKey($kp->publicKey, keyId: 'k1', sigAlg: 'ed25519')
            ->writeTo($bundlePath);

        // Open bundle and set up BundleStore
        $reader = BundleReader::open($bundlePath);
        $bundleStore = new BundleStore($reader);

        // Collect proof envelopes from the bundle
        $proofEnvelopes = iterator_to_array($reader->readProofEnvelopes('tenant:5'), false);

        // Verify using bundle store and explicit detached anchor envelopes
        $bundleVerifier = new Verifier(
            $bundleStore,
            $sigVerifier,
            $policy,
            [new NullDriver()],
            detachedAnchorEnvelopes: $proofEnvelopes,
        );
        $bundleResult = $bundleVerifier->verifyChain('tenant:5', 1, 5);

        // Outcome must match live verification
        $this->assertSame($liveResult->outcome, $bundleResult->outcome);

        // Envelope counts must match
        $this->assertSame(
            $liveResult->chainStats->envelopeCount,
            $bundleResult->chainStats->envelopeCount,
        );
    }
}
