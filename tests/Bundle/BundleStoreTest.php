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
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Chain\UndecodableRecord;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class BundleStoreTest extends TestCase
{
    private string $tmpDir;
    private string $bundleDir;

    protected function setUp(): void
    {
        $this->tmpDir   = sys_get_temp_dir() . '/attest-bs-' . bin2hex(random_bytes(8));
        $this->bundleDir = $this->tmpDir . '/out';
        mkdir($this->tmpDir, 0o700, recursive: true);
        mkdir($this->bundleDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Build a FileChainStore with $count envelopes on $chainId, anchor it,
     * export to a bundle, open a BundleReader, return the store + signed envelopes.
     *
     * @return array{store: BundleStore, envelopes: list<SignedEnvelope>, bundlePath: string}
     */
    private function buildBundleStore(
        string $chainId = 'tenant:5',
        int $count = 3
    ): array {
        $fileStore  = new FileChainStore($this->tmpDir);
        $kp         = KeyPair::generate();
        $signer     = new SodiumSigner($kp, keyId: 'k1');
        $chain      = EvidenceChain::open($fileStore, $chainId, $signer);

        $envelopes = [];
        for ($i = 1; $i <= $count; $i++) {
            $envelopes[] = $chain->record('app.event', ['n' => $i]);
        }

        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        (new AnchorService($fileStore, $claimStore, $signer))
            ->anchorRange($chainId, 1, $count, new NullDriver());

        $bundlePath = $this->bundleDir . '/test.attest';
        BundleExporter::create($fileStore)
            ->forChainSegment($chainId, 1, $count)
            ->writeTo($bundlePath);

        $reader = BundleReader::open($bundlePath);
        return [
            'store'      => new BundleStore($reader),
            'envelopes'  => $envelopes,
            'bundlePath' => $bundlePath,
        ];
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    public function test_readRawRange_yields_raw_chain_segment_bytes(): void
    {
        ['store' => $store, 'envelopes' => $envelopes] = $this->buildBundleStore();

        $rawLines = iterator_to_array($store->readRawRange('tenant:5', 1), false);

        self::assertCount(3, $rawLines);
        foreach ($rawLines as $i => $raw) {
            self::assertIsString($raw);
            // Each raw line must equal the original signed canonical bytes
            self::assertSame($envelopes[$i]->signedCanonicalBytes(), $raw);
        }
    }

    public function test_corrupt_segment_line_in_range_throws_undecodable_record(): void
    {
        ['bundlePath' => $bundlePath, 'envelopes' => $envelopes] = $this->buildBundleStore();
        $entry = 'chains/' . substr(hash('sha256', 'tenant:5'), 0, 32) . '.jsonl';
        $zip = new \ZipArchive();
        self::assertTrue($zip->open($bundlePath));
        $zip->addFromString($entry, implode("\n", [
            $envelopes[0]->signedCanonicalBytes(),
            'not json',
            $envelopes[2]->signedCanonicalBytes(),
        ]) . "\n");
        $zip->close();
        $store = new BundleStore(BundleReader::open($bundlePath));

        try {
            iterator_to_array($store->readRawRange('tenant:5', 1, 3), false);
            self::fail('Expected UndecodableRecord');
        } catch (UndecodableRecord $e) {
            self::assertSame(2, $e->seq);
        }

        self::assertCount(1, iterator_to_array($store->readRange('tenant:5', 1, 1), false));
    }

    public function test_readRange_decodes_envelopes(): void
    {
        ['store' => $store] = $this->buildBundleStore();

        $decoded = iterator_to_array($store->readRange('tenant:5', 1), false);

        self::assertCount(3, $decoded);
        foreach ($decoded as $i => $env) {
            self::assertInstanceOf(SignedEnvelope::class, $env);
            self::assertSame($i + 1, $env->envelope->seq);
        }
    }

    public function test_tail_returns_last_envelope(): void
    {
        $count = 4;
        ['store' => $store] = $this->buildBundleStore(count: $count);

        $tail = $store->tail('tenant:5');

        self::assertNotNull($tail);
        self::assertSame($count, $tail->envelope->seq);
    }

    public function test_exists_returns_true_for_chains_in_manifest(): void
    {
        ['store' => $store] = $this->buildBundleStore();

        self::assertTrue($store->exists('tenant:5'));
        self::assertFalse($store->exists('other-chain'));
    }

    public function test_listChains_lists_chain_ids_from_manifest(): void
    {
        ['store' => $store] = $this->buildBundleStore();

        $ids = iterator_to_array($store->listChains(), false);

        self::assertContains('tenant:5', $ids);
    }

    public function test_append_throws_unsupported_operation(): void
    {
        ['store' => $store] = $this->buildBundleStore();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/read-only/i');

        $store->append('tenant:5', fn ($ctx) => throw new \RuntimeException('should not be called'));
    }

    public function test_bundle_store_implements_raw_chain_store(): void
    {
        ['store' => $store] = $this->buildBundleStore();

        self::assertInstanceOf(RawChainStore::class, $store);
    }
}
