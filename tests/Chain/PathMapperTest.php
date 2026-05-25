<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\PathMapper;
use PHPUnit\Framework\TestCase;

final class PathMapperTest extends TestCase
{
    public function test_maps_chain_id_to_32_hex_char_filename(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $this->assertMatchesRegularExpression(
            '#^/var/lib/attest/chains/[0-9a-f]{32}\.jsonl$#',
            $mapper->jsonlPath('tenant:5')
        );
    }

    public function test_lock_meta_and_claims_paths_share_the_same_hash(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $jsonl = $mapper->jsonlPath('chain-1');
        $lock  = $mapper->lockPath('chain-1');
        $meta  = $mapper->metaPath('chain-1');
        $claims = $mapper->anchorClaimsDir('chain-1');

        $extract = static function (string $p): ?string {
            if (preg_match('#/([0-9a-f]{32})\.#', $p, $m) === 1) {
                return $m[1];
            }
            if (preg_match('#/([0-9a-f]{32})/?$#', $p, $m) === 1) {
                return $m[1];
            }
            return null;
        };
        $h1 = $extract($jsonl);
        $h2 = $extract($lock);
        $h3 = $extract($meta);
        $h4 = $extract(rtrim($claims, '/'));
        $this->assertNotNull($h1);
        $this->assertSame($h1, $h2);
        $this->assertSame($h1, $h3);
        $this->assertSame($h1, $h4);
    }

    public function test_rejects_chain_id_with_null_byte(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $this->expectException(\InvalidArgumentException::class);
        $mapper->jsonlPath("bad\x00id");
    }

    public function test_rejects_chain_id_with_control_chars(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $this->expectException(\InvalidArgumentException::class);
        $mapper->jsonlPath("bad\nid");
    }

    public function test_rejects_overlong_chain_id(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $this->expectException(\InvalidArgumentException::class);
        $mapper->jsonlPath(str_repeat('x', 192));
    }

    public function test_rejects_empty_chain_id(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $this->expectException(\InvalidArgumentException::class);
        $mapper->jsonlPath('');
    }

    public function test_accepts_normal_labels(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $mapper->jsonlPath('tenant:5');
        $mapper->jsonlPath('runbook:abc-123');
        $mapper->jsonlPath('global');
        $this->expectNotToPerformAssertions();
    }

    public function test_index_and_chains_dir_paths(): void
    {
        $mapper = new PathMapper('/var/lib/attest');
        $this->assertSame('/var/lib/attest/index.json', $mapper->indexPath());
        $this->assertSame('/var/lib/attest/chains', $mapper->chainsDir());
    }
}
