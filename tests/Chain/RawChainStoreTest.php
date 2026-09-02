<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\PathMapper;
use Fissible\Attest\Chain\UndecodableRecord;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class RawChainStoreTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private EvidenceChain $chain;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-raw-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->chain = EvidenceChain::open(
            store: $this->store,
            chainId: 'tenant:5',
            signer: new SodiumSigner(KeyPair::generate(), 'test-key'),
        );
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    public function test_read_raw_range_yields_canonical_bytes_without_terminators(): void
    {
        $first = $this->chain->record('t1', ['n' => 1]);
        $second = $this->chain->record('t2', ['n' => 2]);
        $third = $this->chain->record('t3', ['n' => 3]);

        $raw = iterator_to_array($this->store->readRawRange('tenant:5', 1, 3), false);

        $this->assertSame([
            $first->signedCanonicalBytes(),
            $second->signedCanonicalBytes(),
            $third->signedCanonicalBytes(),
        ], $raw);
        foreach ($raw as $line) {
            $this->assertStringNotContainsString("\n", $line);
            $this->assertStringNotContainsString("\r", $line);
        }
    }

    public function test_read_raw_range_returns_sub_ranges(): void
    {
        $first = $this->chain->record('t1', ['n' => 1]);
        $second = $this->chain->record('t2', ['n' => 2]);
        $third = $this->chain->record('t3', ['n' => 3]);

        $raw = iterator_to_array($this->store->readRawRange('tenant:5', 2, 2), false);

        $this->assertSame([$second->signedCanonicalBytes()], $raw);
        $this->assertNotContains($first->signedCanonicalBytes(), $raw);
        $this->assertNotContains($third->signedCanonicalBytes(), $raw);
    }

    public function test_torn_final_line_is_not_yielded(): void
    {
        $first = $this->chain->record('t1', ['n' => 1]);
        $mapper = new PathMapper($this->root);
        file_put_contents($mapper->jsonlPath('tenant:5'), '{"partial":true}', FILE_APPEND);

        $raw = iterator_to_array($this->store->readRawRange('tenant:5', 1, 2), false);

        $this->assertSame([$first->signedCanonicalBytes()], $raw);
    }

    public function test_read_raw_range_throws_undecodable_record_for_corrupt_line_in_range(): void
    {
        $this->chain->record('t1', ['n' => 1]);
        $this->chain->record('t2', ['n' => 2]);
        $this->chain->record('t3', ['n' => 3]);
        $this->replaceLine(1, 'not json');

        try {
            iterator_to_array($this->store->readRawRange('tenant:5', 1, 3), false);
            $this->fail('Expected UndecodableRecord');
        } catch (UndecodableRecord $e) {
            $this->assertSame(2, $e->seq);
        }
    }

    public function test_read_raw_range_ignores_corrupt_line_after_requested_range(): void
    {
        $first = $this->chain->record('t1', ['n' => 1]);
        $this->chain->record('t2', ['n' => 2]);
        $this->replaceLine(1, 'not json');

        $raw = iterator_to_array($this->store->readRawRange('tenant:5', 1, 1), false);

        $this->assertSame([$first->signedCanonicalBytes()], $raw);
    }

    public function test_read_raw_range_skips_corrupt_line_before_requested_range(): void
    {
        $this->chain->record('t1', ['n' => 1]);
        $second = $this->chain->record('t2', ['n' => 2]);
        $this->replaceLine(0, 'not json');

        $raw = iterator_to_array($this->store->readRawRange('tenant:5', 2, 2), false);

        $this->assertSame([$second->signedCanonicalBytes()], $raw);
    }

    private function replaceLine(int $index, string $replacement): void
    {
        $path = (new PathMapper($this->root))->jsonlPath('tenant:5');
        $lines = explode("\n", rtrim((string) file_get_contents($path), "\n"));
        $lines[$index] = $replacement;
        file_put_contents($path, implode("\n", $lines) . "\n");
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

