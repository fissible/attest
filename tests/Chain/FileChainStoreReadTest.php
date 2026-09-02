<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\PathMapper;
use Fissible\Attest\Chain\UndecodableRecord;
use Fissible\Attest\Envelope\EvidenceEnvelope;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class FileChainStoreReadTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    public function test_tail_returns_null_for_empty_chain(): void
    {
        $store = new FileChainStore($this->root);
        $this->assertNull($store->tail('c1'));
    }

    public function test_tail_reads_last_envelope_from_jsonl(): void
    {
        $store = new FileChainStore($this->root);
        $signer = new SodiumSigner(KeyPair::generate(), 'k1');
        $this->writeFixtureChain('c1', $signer, count: 3);

        $tail = $store->tail('c1');
        $this->assertNotNull($tail);
        $this->assertSame(3, $tail->envelope->seq);
    }

    public function test_tail_handles_large_chain_via_backward_chunk_read(): void
    {
        $store = new FileChainStore($this->root);
        $signer = new SodiumSigner(KeyPair::generate(), 'k1');
        $this->writeFixtureChain('big', $signer, count: 1000);

        $tail = $store->tail('big');
        $this->assertNotNull($tail);
        $this->assertSame(1000, $tail->envelope->seq);
    }

    public function test_read_range_yields_envelopes_in_range(): void
    {
        $store = new FileChainStore($this->root);
        $signer = new SodiumSigner(KeyPair::generate(), 'k1');
        $this->writeFixtureChain('c1', $signer, count: 5);

        $envs = iterator_to_array($store->readRange('c1', 2, 4), false);
        $this->assertCount(3, $envs);
        $this->assertSame([2, 3, 4], array_map(fn ($e) => $e->envelope->seq, $envs));
    }

    public function test_read_range_without_to_seq_reads_to_end(): void
    {
        $store = new FileChainStore($this->root);
        $signer = new SodiumSigner(KeyPair::generate(), 'k1');
        $this->writeFixtureChain('c1', $signer, count: 5);

        $envs = iterator_to_array($store->readRange('c1', 3), false);
        $this->assertSame([3, 4, 5], array_map(fn ($e) => $e->envelope->seq, $envs));
    }

    public function test_exists_returns_true_after_file_exists(): void
    {
        $store = new FileChainStore($this->root);
        $signer = new SodiumSigner(KeyPair::generate(), 'k1');
        $this->assertFalse($store->exists('c1'));
        $this->writeFixtureChain('c1', $signer, count: 1);
        $this->assertTrue($store->exists('c1'));
    }

    public function test_list_chains_yields_nothing_for_empty_root(): void
    {
        $store = new FileChainStore($this->root);
        $this->assertSame([], iterator_to_array($store->listChains(), false));
    }

    public function test_read_range_throws_undecodable_record_for_corrupt_line_in_range(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 3);
        $this->replaceLine('c1', 1, 'this is not json');

        try {
            iterator_to_array($store->readRange('c1', 1, 3), false);
            $this->fail('Expected UndecodableRecord');
        } catch (UndecodableRecord $e) {
            $this->assertSame('c1', $e->chainId);
            $this->assertSame(2, $e->seq);
            $this->assertStringContainsString('not valid JSON', $e->getMessage());
        }
    }

    public function test_read_range_maps_type_mismatch_to_undecodable_record(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 2);
        $this->replaceLine('c1', 1, static fn (string $l): string => str_replace('"seq":2', '"seq":"2"', $l));

        $this->expectException(UndecodableRecord::class);
        iterator_to_array($store->readRange('c1', 1), false);
    }

    public function test_read_range_ignores_corrupt_line_after_requested_range(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 3);
        $this->replaceLine('c1', 1, 'garbage');

        $envs = iterator_to_array($store->readRange('c1', 1, 1), false);

        $this->assertCount(1, $envs);
        $this->assertSame(1, $envs[0]->envelope->seq);
    }

    public function test_read_range_skips_corrupt_line_before_requested_range(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 3);
        $this->replaceLine('c1', 0, 'garbage');

        $envs = iterator_to_array($store->readRange('c1', 2, 3), false);

        $this->assertSame([2, 3], array_map(static fn ($e) => $e->envelope->seq, $envs));
    }

    public function test_read_range_ignores_truncated_trailing_line(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 3);
        $path = (new PathMapper($this->root))->jsonlPath('c1');
        $bytes = (string) file_get_contents($path);
        file_put_contents($path, substr($bytes, 0, strlen($bytes) - 40));

        $envs = iterator_to_array($store->readRange('c1', 1), false);

        $this->assertSame([1, 2], array_map(static fn ($e) => $e->envelope->seq, $envs));
    }

    public function test_tail_ignores_truncated_trailing_line(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 3);
        $path = (new PathMapper($this->root))->jsonlPath('c1');
        $bytes = (string) file_get_contents($path);
        file_put_contents($path, substr($bytes, 0, strlen($bytes) - 40));

        $tail = $store->tail('c1');

        $this->assertNotNull($tail);
        $this->assertSame(2, $tail->envelope->seq);
    }

    public function test_tail_throws_undecodable_record_for_corrupt_last_line(): void
    {
        $store = new FileChainStore($this->root);
        $this->writeFixtureChain('c1', new SodiumSigner(KeyPair::generate(), 'k1'), count: 2);
        $this->replaceLine('c1', 1, 'garbage');

        $this->expectException(UndecodableRecord::class);
        $store->tail('c1');
    }

    /**
     * @param string|callable(string): string $replacement
     */
    private function replaceLine(string $chainId, int $index, string|callable $replacement): void
    {
        $path = (new PathMapper($this->root))->jsonlPath($chainId);
        $lines = explode("\n", rtrim((string) file_get_contents($path), "\n"));
        $lines[$index] = is_string($replacement) ? $replacement : $replacement($lines[$index]);
        file_put_contents($path, implode("\n", $lines) . "\n");
    }

    private function writeFixtureChain(string $chainId, SodiumSigner $signer, int $count): void
    {
        $mapper = new PathMapper($this->root);
        $path = $mapper->jsonlPath($chainId);
        @mkdir(dirname($path), 0o700, recursive: true);
        $prevHash = null;
        $lines = [];
        for ($i = 1; $i <= $count; $i++) {
            $env = new EvidenceEnvelope(
                id: '01H' . str_pad((string) $i, 23, '0', STR_PAD_LEFT),
                chain: $chainId, seq: $i, ts: '2026-05-25T14:32:11.000Z',
                type: 'fixture', payload: ['i' => $i],
                prevHash: $prevHash, keyId: $signer->keyId(), sigAlg: 'ed25519',
            );
            $signed = SignedEnvelope::sign($env, $signer);
            $lines[] = $signed->signedCanonicalBytes();
            $prevHash = $signed->selfHash();
        }
        file_put_contents($path, implode("\n", $lines) . "\n");
    }
}
