<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\StaticVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use PHPUnit\Framework\TestCase;

/**
 * The README documents handing evidence over by copying the store directory,
 * as the answer for anyone without ext-zip. That is a documented promise with
 * no other coverage — the bundle suite proves the bundle path, not this one —
 * so it is pinned here rather than left to rot silently.
 */
final class DirectoryHandoffTest extends TestCase
{
    private string $producerRoot;
    private string $recipientRoot;
    private KeyPair $keys;

    protected function setUp(): void
    {
        $suffix = bin2hex(random_bytes(8));
        $this->producerRoot = sys_get_temp_dir() . '/attest-handoff-src-' . $suffix;
        $this->recipientRoot = sys_get_temp_dir() . '/attest-handoff-dst-' . $suffix;
        mkdir($this->producerRoot, 0o700, recursive: true);
        $this->keys = KeyPair::generate();
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->producerRoot);
        $this->removeDir($this->recipientRoot);
    }

    public function test_a_copied_store_directory_verifies_at_the_recipient(): void
    {
        $this->recordThree();
        $this->copyDir($this->producerRoot, $this->recipientRoot);

        $result = $this->verifyRecipient();

        $this->assertTrue($result->isVerified());
        $this->assertSame(VerificationOutcome::VERIFIED, $result->outcome);
    }

    /**
     * The point of the handoff: the recipient is not trusting the sender's
     * word that the copy is faithful.
     */
    public function test_tampering_in_transit_breaks_at_the_altered_entry(): void
    {
        $this->recordThree();
        $this->copyDir($this->producerRoot, $this->recipientRoot);

        $jsonl = $this->recipientChainFile();
        file_put_contents($jsonl, str_replace('"n":2', '"n":9', (string) file_get_contents($jsonl)));

        $result = $this->verifyRecipient();

        $this->assertFalse($result->isVerified());
        $this->assertSame(2, $result->brokenAtSeq);
    }

    /** Dropping the tail is the quiet edit a flat file makes easy. */
    public function test_a_truncated_copy_does_not_pass_as_a_shorter_chain(): void
    {
        $this->recordThree();
        $this->copyDir($this->producerRoot, $this->recipientRoot);

        $jsonl = $this->recipientChainFile();
        $lines = array_values(array_filter(explode("\n", (string) file_get_contents($jsonl))));
        array_pop($lines);
        file_put_contents($jsonl, implode("\n", $lines) . "\n");

        // A truncated copy still verifies as a chain — it is internally
        // consistent — so completeness is exactly what the recipient must
        // establish out of band, from the range the sender stated.
        $result = $this->verifyRecipient();

        $this->assertTrue($result->isVerified());
        $this->assertSame(2, $result->chainStats->envelopeCount);
    }

    private function recordThree(): void
    {
        $chain = EvidenceChain::open(
            store: new FileChainStore($this->producerRoot),
            chainId: 'tenant:5',
            signer: new SodiumSigner($this->keys, 'prod-2026-01'),
        );
        foreach ([1, 2, 3] as $n) {
            $chain->record('contract.approved', ['n' => $n]);
        }
    }

    private function verifyRecipient(): \Fissible\Attest\Verification\VerificationResult
    {
        return StaticVerifier::verifyChain(
            store: new FileChainStore($this->recipientRoot),
            chainId: 'tenant:5',
            trustedKeys: [new TrustedKey($this->keys->publicKey, keyId: 'prod-2026-01')],
        );
    }

    private function recipientChainFile(): string
    {
        $matches = glob($this->recipientRoot . '/chains/*.jsonl');
        $this->assertNotEmpty($matches, 'copied store has no chain file');

        return $matches[0];
    }

    private function copyDir(string $from, string $to): void
    {
        mkdir($to, 0o700, recursive: true);
        $entries = scandir($from);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $src = $from . '/' . $entry;
            $dst = $to . '/' . $entry;
            if (is_dir($src)) {
                $this->copyDir($src, $dst);
            } else {
                copy($src, $dst);
            }
        }
    }

    private function removeDir(string $path): void
    {
        if (! is_dir($path)) {
            return;
        }
        $entries = scandir($path);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $child = $path . '/' . $entry;
            if (is_dir($child)) {
                $this->removeDir($child);
            } else {
                @unlink($child);
            }
        }
        @rmdir($path);
    }
}
