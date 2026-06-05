<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\StaticVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use PHPUnit\Framework\TestCase;

final class StaticVerifierTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-static-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        @exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_facade_verifies_single_chain_with_trusted_key(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        $chain->record('app.event', ['a' => 1]);
        $chain->record('app.event', ['a' => 2]);

        $result = StaticVerifier::verifyChain(
            store: $store,
            chainId: 'tenant:5',
            trustedKeys: [new TrustedKey($kp->publicKey, keyId: 'k1')],
        );

        self::assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        self::assertSame(2, $result->chainStats->envelopeCount);
    }
}
