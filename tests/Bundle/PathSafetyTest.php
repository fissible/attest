<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Bundle\BundleEntryPath;
use PHPUnit\Framework\TestCase;

final class PathSafetyTest extends TestCase
{
    public static function unsafePaths(): array
    {
        return [
            'absolute'             => ['/etc/passwd'],
            'parent traversal'     => ['../escape'],
            'embedded traversal'   => ['chains/../etc/passwd'],
            'leading dot'          => ['./manifest.json'],
            'backslash'            => ["chains\\x.jsonl"],
            'null byte'            => ["chains/x.jsonl\0"],
            'control char'         => ["chains/x.\nls"],
            'empty'                => [''],
            'just slash'           => ['/'],
            'too long'             => [str_repeat('a/', 2000)],
        ];
    }

    /** @dataProvider unsafePaths */
    public function test_rejects_unsafe_entry_path(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        BundleEntryPath::validate($path);
    }

    public static function safePaths(): array
    {
        return [
            ['manifest.json'],
            ['chains/abc123.jsonl'],
            ['proof_envelopes/abc123.jsonl'],
            ['receipts/' . str_repeat('a', 64) . '.ots'],
            ['keys/' . str_repeat('a', 64) . '.pub'],
        ];
    }

    /** @dataProvider safePaths */
    public function test_accepts_safe_entry_path(string $path): void
    {
        // Should not throw.
        BundleEntryPath::validate($path);
        self::assertTrue(true);
    }

    public function test_only_known_top_level_prefixes_allowed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/unknown top-level prefix/i');
        BundleEntryPath::validate('unknown/file.txt');
    }
}
