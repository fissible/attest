<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

final class PathSafety
{
    public static function ensureDirectoryExists(string $dir): void
    {
        if (! is_dir($dir) && ! @mkdir($dir, 0o700, recursive: true) && ! is_dir($dir)) {
            throw new \RuntimeException("Could not create directory: $dir");
        }
        if (! is_writable($dir)) {
            throw new \RuntimeException("Directory is not writable: $dir");
        }
    }

    public static function ensureWritableParent(string $path): void
    {
        $parent = dirname($path);
        self::ensureDirectoryExists($parent);
    }
}
