<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Support;

use Fissible\Attest\Cli\Support\TrustedKeyLoader;
use Fissible\Attest\Signing\Fingerprint;
use Fissible\Attest\Signing\KeyPair;
use PHPUnit\Framework\TestCase;

/**
 * Issue #36: --trusted-key-file accepts "[<key_id>=]<path>", matching
 * fissible/attest-laravel's TrustedKeyResolver. A plain path keeps the
 * fingerprint-only behaviour; the "<key_id>=" prefix binds the key to the
 * id envelopes were signed under.
 */
final class TrustedKeyLoaderTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/attest-tkl-' . bin2hex(random_bytes(8));
        mkdir($this->dir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    public function test_file_entry_with_key_id_prefix_sets_key_id(): void
    {
        $kp = KeyPair::generate();
        $path = $this->writePub('app.pub', $kp);

        $keys = TrustedKeyLoader::load([], ['app-prod-2026-01=' . $path]);

        $this->assertCount(1, $keys);
        $this->assertSame('app-prod-2026-01', $keys[0]->keyId);
        $this->assertSame($kp->publicKey, $keys[0]->publicKey);
        $this->assertSame(Fingerprint::of($kp->publicKey), $keys[0]->fingerprint);
    }

    public function test_plain_file_entry_has_no_key_id(): void
    {
        $kp = KeyPair::generate();
        $path = $this->writePub('app.pub', $kp);

        $keys = TrustedKeyLoader::load([], [$path]);

        $this->assertCount(1, $keys);
        $this->assertNull($keys[0]->keyId);
        $this->assertSame($kp->publicKey, $keys[0]->publicKey);
    }

    public function test_file_entry_trims_whitespace_around_key_id_and_path(): void
    {
        $kp = KeyPair::generate();
        $path = $this->writePub('app.pub', $kp);

        $keys = TrustedKeyLoader::load([], ['  app-prod =  ' . $path . ' ']);

        $this->assertSame('app-prod', $keys[0]->keyId);
        $this->assertSame($kp->publicKey, $keys[0]->publicKey);
    }

    public function test_file_entry_with_empty_key_id_is_rejected(): void
    {
        $path = $this->writePub('app.pub', KeyPair::generate());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('key_id must not be empty');

        TrustedKeyLoader::load([], ['=' . $path]);
    }

    public function test_file_entry_with_empty_path_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('path must not be empty');

        TrustedKeyLoader::load([], ['app-prod=']);
    }

    public function test_file_entry_with_missing_file_names_the_path(): void
    {
        $missing = $this->dir . '/nope.pub';

        try {
            TrustedKeyLoader::load([], ['app-prod=' . $missing]);
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString($missing, $e->getMessage());
        }
    }

    public function test_file_path_may_contain_equals_after_the_key_id(): void
    {
        // Only the first "=" separates key id from path.
        $kp = KeyPair::generate();
        mkdir($this->dir . '/a=b');
        $path = $this->writePub('a=b/app.pub', $kp);

        $keys = TrustedKeyLoader::load([], ['app-prod=' . $path]);

        $this->assertSame('app-prod', $keys[0]->keyId);
        $this->assertSame($kp->publicKey, $keys[0]->publicKey);
    }

    public function test_inline_entry_still_requires_key_id_and_base64(): void
    {
        $kp = KeyPair::generate();

        $keys = TrustedKeyLoader::load(['app-prod=' . base64_encode($kp->publicKey)], []);

        $this->assertSame('app-prod', $keys[0]->keyId);
        $this->assertSame($kp->publicKey, $keys[0]->publicKey);
    }

    public function test_inline_entry_without_equals_is_rejected_with_a_trusted_key_file_hint(): void
    {
        try {
            TrustedKeyLoader::load(['not-an-entry'], []);
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('--trusted-key-file', $e->getMessage());
        }
    }

    public function test_inline_entry_does_not_accept_key_id_equals_path(): void
    {
        // The "<key_id>=<path>" form belongs to --trusted-key-file only; for
        // --trusted-key the right-hand side must be the base64 key itself.
        $path = $this->writePub('app.pub', KeyPair::generate());

        $this->expectException(\InvalidArgumentException::class);

        TrustedKeyLoader::load(['app-prod=' . $path], []);
    }

    public function test_file_entry_with_whitespace_only_key_id_is_rejected(): void
    {
        $path = $this->writePub('app.pub', KeyPair::generate());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('key_id must not be empty');

        TrustedKeyLoader::load([], ['   =' . $path]);
    }

    public function test_file_entry_with_whitespace_only_path_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('path must not be empty');

        TrustedKeyLoader::load([], ['app-prod=   ']);
    }

    public function test_plain_file_entry_that_is_whitespace_only_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('path must not be empty');

        TrustedKeyLoader::load([], ['   ']);
    }

    private function writePub(string $name, KeyPair $kp): string
    {
        $path = $this->dir . '/' . $name;
        file_put_contents($path, base64_encode($kp->publicKey) . "\n");

        return $path;
    }
}
