<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class BundleEntryPath
{
    public static function validate(string $path): void
    {
        if ($path === '') {
            throw new \InvalidArgumentException('Bundle entry path is empty');
        }
        if (strlen($path) > BundleConstants::MAX_ENTRY_PATH_LEN) {
            throw new \InvalidArgumentException(
                'Bundle entry path exceeds ' . BundleConstants::MAX_ENTRY_PATH_LEN . ' bytes'
            );
        }
        if (str_contains($path, "\0")) {
            throw new \InvalidArgumentException('Bundle entry path contains null byte');
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $path)) {
            throw new \InvalidArgumentException('Bundle entry path contains control character');
        }
        if (str_contains($path, '\\')) {
            throw new \InvalidArgumentException('Bundle entry path contains backslash');
        }
        if ($path[0] === '/' || str_starts_with($path, './') || str_contains($path, '/../') || str_ends_with($path, '/..')) {
            throw new \InvalidArgumentException('Bundle entry path is absolute or contains traversal');
        }
        if (str_contains($path, '..')) {
            // Catch "../foo" too.
            $parts = explode('/', $path);
            if (in_array('..', $parts, true)) {
                throw new \InvalidArgumentException('Bundle entry path contains parent traversal');
            }
        }

        if ($path === BundleConstants::MANIFEST_ENTRY) {
            return;
        }

        foreach (BundleConstants::ALLOWED_PREFIXES as $prefix) {
            if (str_starts_with($path, $prefix)) {
                if (strlen($path) === strlen($prefix)) {
                    throw new \InvalidArgumentException("Bundle entry path is bare prefix '$prefix'");
                }
                return;
            }
        }

        throw new \InvalidArgumentException("Bundle entry path uses unknown top-level prefix: $path");
    }
}
