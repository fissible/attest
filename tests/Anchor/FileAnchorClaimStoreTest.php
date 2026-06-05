<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorClaimStore;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use PHPUnit\Framework\TestCase;

final class FileAnchorClaimStoreTest extends TestCase
{
    use AnchorClaimStoreContractTests;

    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-claim-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    protected function store(): AnchorClaimStore
    {
        return new FileAnchorClaimStore($this->root);
    }

    public function test_complete_missing_claim_fails(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('not found');

        $this->store()->complete($this->anchorId(), '01HX');
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

