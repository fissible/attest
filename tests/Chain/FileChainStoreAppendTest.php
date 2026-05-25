<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\FileChainStore;
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
}
