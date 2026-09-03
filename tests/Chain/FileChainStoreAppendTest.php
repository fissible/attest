<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\PathMapper;
use Fissible\Attest\Testing\ChainStoreContractTests;
use PHPUnit\Framework\TestCase;

final class FileChainStoreAppendTest extends TestCase
{
    use ChainStoreContractTests;

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

    protected function makeStore(): ChainStore
    {
        return new FileChainStore($this->root);
    }

    // ── Issue #35: append after a torn tail ─────────────────────────────────
    //
    // A crash mid-write leaves a final line with no "\n". tail() already
    // ignores it (#21). append() must not write the next record onto that
    // same line: it discards the torn bytes under the append lock so the new
    // record starts on a fresh line and the file stays fully decodable.

    public function test_append_after_torn_tail_discards_partial_and_writes_clean_line(): void
    {
        $store = $this->makeStore();
        $signer = $this->signer();
        $first = $this->appendOne($store, 'c1', $signer, type: 'first');
        $this->appendOne($store, 'c1', $signer, type: 'second');
        $path = $this->jsonlPath('c1');
        $intact = (string) file_get_contents($path);
        $torn = substr($intact, 0, strlen($intact) - 40);
        file_put_contents($path, $torn);
        $tornFragment = substr($torn, strlen($first->signedCanonicalBytes()) + 1);
        $this->assertNotSame('', $tornFragment);

        $appended = $this->appendOne($store, 'c1', $signer, type: 'third');

        $this->assertSame(2, $appended->envelope->seq, 'torn record is gone, so the next seq is 2');
        $this->assertSame($first->selfHash(), $appended->envelope->prevHash);
        $bytes = (string) file_get_contents($path);
        $this->assertSame(
            $first->signedCanonicalBytes() . "\n" . $appended->signedCanonicalBytes() . "\n",
            $bytes,
            'file must be exactly the intact record followed by the new record',
        );
        $this->assertStringNotContainsString($tornFragment, $bytes, 'torn bytes must be discarded');
        $seqs = array_map(static fn ($e) => $e->envelope->seq, iterator_to_array($store->readRange('c1', 1), false));
        $this->assertSame([1, 2], $seqs);

        $next = $this->appendOne($store, 'c1', $signer, type: 'fourth');
        $this->assertSame(3, $next->envelope->seq);
        $this->assertSame($appended->selfHash(), $next->envelope->prevHash);
    }

    public function test_append_after_torn_only_record_starts_chain_at_seq_1(): void
    {
        $store = $this->makeStore();
        $signer = $this->signer();
        $this->appendOne($store, 'c1', $signer);
        $path = $this->jsonlPath('c1');
        $intact = (string) file_get_contents($path);
        file_put_contents($path, substr($intact, 0, strlen($intact) - 40));
        $this->assertNull($store->tail('c1'));

        $appended = $this->appendOne($store, 'c1', $signer);

        $this->assertSame(1, $appended->envelope->seq);
        $this->assertNull($appended->envelope->prevHash);
        $this->assertSame($appended->signedCanonicalBytes() . "\n", (string) file_get_contents($path));
        // Fresh instance: phpstan otherwise narrows tail() to the null asserted above.
        $tail = (new FileChainStore($this->root))->tail('c1');
        $this->assertNotNull($tail);
        $this->assertSame(1, $tail->envelope->seq);
    }

    public function test_append_after_torn_tail_with_fsync_enabled(): void
    {
        $store = new FileChainStore($this->root, fsync: true);
        $signer = $this->signer();
        $first = $this->appendOne($store, 'c1', $signer);
        $this->appendOne($store, 'c1', $signer);
        $path = $this->jsonlPath('c1');
        $intact = (string) file_get_contents($path);
        file_put_contents($path, substr($intact, 0, strlen($intact) - 40));

        $appended = $this->appendOne($store, 'c1', $signer);

        $this->assertSame(2, $appended->envelope->seq);
        $this->assertSame(
            $first->signedCanonicalBytes() . "\n" . $appended->signedCanonicalBytes() . "\n",
            (string) file_get_contents($path),
        );
    }

    public function test_append_after_large_torn_tail(): void
    {
        // A torn partial much larger than a single read buffer, so recovery
        // has to find the last complete record well before EOF.
        $store = $this->makeStore();
        $signer = $this->signer();
        $first = $this->appendOne($store, 'c1', $signer);
        $this->appendOne($store, 'c1', $signer, payload: ['blob' => str_repeat('x', 20000)]);
        $path = $this->jsonlPath('c1');
        $intact = (string) file_get_contents($path);
        file_put_contents($path, substr($intact, 0, strlen($intact) - 100));

        $appended = $this->appendOne($store, 'c1', $signer);

        $this->assertSame(2, $appended->envelope->seq);
        $this->assertSame(
            $first->signedCanonicalBytes() . "\n" . $appended->signedCanonicalBytes() . "\n",
            (string) file_get_contents($path),
        );
    }

    public function test_append_on_intact_file_does_not_rewrite_existing_bytes(): void
    {
        $store = $this->makeStore();
        $signer = $this->signer();
        $this->appendOne($store, 'c1', $signer);
        $this->appendOne($store, 'c1', $signer);
        $path = $this->jsonlPath('c1');
        $before = (string) file_get_contents($path);

        $appended = $this->appendOne($store, 'c1', $signer);

        $this->assertSame(3, $appended->envelope->seq);
        $this->assertSame($before . $appended->signedCanonicalBytes() . "\n", (string) file_get_contents($path));
    }

    private function jsonlPath(string $chainId): string
    {
        return (new PathMapper($this->root))->jsonlPath($chainId);
    }

    public function test_metadata_sidecar_written_after_append(): void
    {
        $store = $this->makeStore();
        $signer = $this->signer();
        $this->appendOne($store, 'c1', $signer);
        $metaPath = $this->root . '/chains/' . substr(hash('sha256', 'c1'), 0, 32) . '.meta.json';
        $this->assertFileExists($metaPath);
        $meta = json_decode((string) file_get_contents($metaPath), true);
        $this->assertIsArray($meta);
        $this->assertSame('c1', $meta['chain_id']);
        $this->assertSame(1, $meta['envelope_count']);
    }

    public function test_global_index_updated_with_new_chain(): void
    {
        $store = $this->makeStore();
        $signer = $this->signer();
        $this->appendOne($store, 'tenant:5', $signer);
        $index = json_decode((string) file_get_contents($this->root . '/index.json'), true);
        $this->assertIsArray($index);
        $this->assertArrayHasKey('tenant:5', $index);
    }

    public function test_envelope_count_increments_across_appends(): void
    {
        $store = $this->makeStore();
        $signer = $this->signer();
        $this->appendOne($store, 'c1', $signer);
        $this->appendOne($store, 'c1', $signer);
        $this->appendOne($store, 'c1', $signer);
        $metaPath = $this->root . '/chains/' . substr(hash('sha256', 'c1'), 0, 32) . '.meta.json';
        $meta = json_decode((string) file_get_contents($metaPath), true);
        $this->assertSame(3, $meta['envelope_count']);
    }

    public function test_append_with_fsync_enabled_persists_and_reads_back(): void
    {
        $store = new FileChainStore($this->root, fsync: true);
        $signer = $this->signer();
        $this->appendOne($store, 'c1', $signer, type: 'first');
        $this->appendOne($store, 'c1', $signer, type: 'second');

        $tail = $store->tail('c1');
        $this->assertNotNull($tail);
        $this->assertSame('second', $tail->envelope->type);
        $this->assertSame(2, $tail->envelope->seq);

        $envs = iterator_to_array($store->readRange('c1', 1), false);
        $this->assertCount(2, $envs);
    }
}
