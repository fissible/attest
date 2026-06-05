<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Bundle\AnchorMeta;
use Fissible\Attest\Bundle\BundleManifest;
use Fissible\Attest\Bundle\ChainSegmentMeta;
use Fissible\Attest\Bundle\ClaimedKeyMeta;
use Fissible\Attest\Bundle\InvalidBundleManifest;
use PHPUnit\Framework\TestCase;

final class BundleManifestTest extends TestCase
{
    public function test_roundtrips_minimal_manifest(): void
    {
        $manifest = new BundleManifest(
            createdAt: '2026-06-05T00:00:00Z',
            chains: [new ChainSegmentMeta(
                chainId: 'tenant:5',
                file: 'chains/abc.jsonl',
                fromSeq: 1, toSeq: 100,
                envelopeCount: 100,
                headHash: str_repeat('a', 64),
            )],
            anchors: [],
            claimedKeys: [],
        );
        $json = $manifest->toJson();
        $parsed = BundleManifest::fromJson($json);
        self::assertEquals($manifest, $parsed);
    }

    public function test_rejects_unknown_format(): void
    {
        $this->expectException(InvalidBundleManifest::class);
        $this->expectExceptionMessageMatches('/unsupported format/i');
        BundleManifest::fromJson('{"format":"fissible.attest.bundle/v2","created_at":"2026-06-05T00:00:00Z","chains":[]}');
    }

    public function test_rejects_missing_required_field(): void
    {
        $this->expectException(InvalidBundleManifest::class);
        BundleManifest::fromJson('{"format":"fissible.attest.bundle/v1"}');
    }

    public function test_rejects_invalid_chain_seq_range(): void
    {
        $this->expectException(InvalidBundleManifest::class);
        $this->expectExceptionMessageMatches('/from_seq/i');
        BundleManifest::fromJson(json_encode([
            'format' => 'fissible.attest.bundle/v1',
            'created_at' => '2026-06-05T00:00:00Z',
            'chains' => [[
                'chain_id' => 'c', 'file' => 'chains/a.jsonl',
                'from_seq' => 5, 'to_seq' => 3,
                'envelope_count' => 0, 'head_hash' => str_repeat('a', 64),
            ]],
            'anchors' => [],
        ]));
    }

    public function test_anchor_meta_carries_receipt_envelope_id(): void
    {
        $json = json_encode([
            'format' => 'fissible.attest.bundle/v1',
            'created_at' => '2026-06-05T00:00:00Z',
            'chains' => [],
            'anchors' => [[
                'anchor_id' => str_repeat('b', 64),
                'chain_id' => 'c',
                'from_seq' => 1, 'to_seq' => 100,
                'merkle_algorithm' => 'sha256-rfc6962',
                'root' => str_repeat('c', 64),
                'driver' => 'opentimestamps',
                'state' => 'upgraded',
                'receipt_envelope_id' => '01H' . str_repeat('A', 23),
                'receipt_cache_file' => 'receipts/' . str_repeat('b', 64) . '.ots',
            ]],
        ]);
        $manifest = BundleManifest::fromJson($json);
        self::assertCount(1, $manifest->anchors);
        self::assertSame('upgraded', $manifest->anchors[0]->state);
    }

    public function test_claimed_key_meta_carries_fingerprint_and_path(): void
    {
        $json = json_encode([
            'format' => 'fissible.attest.bundle/v1',
            'created_at' => '2026-06-05T00:00:00Z',
            'chains' => [],
            'anchors' => [],
            'claimed_keys' => [[
                'key_id' => 'k1',
                'sig_alg' => 'ed25519',
                'fingerprint' => 'sha256:' . str_repeat('d', 64),
                'file' => 'keys/' . str_repeat('d', 64) . '.pub',
            ]],
        ]);
        $manifest = BundleManifest::fromJson($json);
        self::assertCount(1, $manifest->claimedKeys);
        self::assertSame('k1', $manifest->claimedKeys[0]->keyId);
    }
}
