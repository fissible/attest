<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Chain\PathSafety;

/**
 * @internal
 */
final class BundleWriter
{
    private \ZipArchive $zip;
    private string $tmpPath;
    private string $finalPath;
    private int $totalBytes = 0;

    public static function open(string $finalPath): self
    {
        if (! extension_loaded('zip')) {
            throw BundleSupportUnavailable::missingZipExtension('write');
        }
        $self = new self();
        PathSafety::ensureWritableParent($finalPath);
        $self->finalPath = $finalPath;
        $self->tmpPath = $finalPath . '.tmp.' . bin2hex(random_bytes(8));
        $self->zip = new \ZipArchive();
        $opened = $self->zip->open($self->tmpPath, \ZipArchive::CREATE | \ZipArchive::EXCL);
        if ($opened !== true) {
            throw new BundleExportException("Could not open zip for write: {$self->tmpPath} (code: $opened)");
        }
        return $self;
    }

    public function addEntry(string $entryPath, string $bytes): void
    {
        BundleEntryPath::validate($entryPath);
        if (strlen($bytes) > BundleConstants::MAX_MEMBER_BYTES) {
            throw new BundleExportException("Entry $entryPath exceeds per-member size cap");
        }
        $this->totalBytes += strlen($bytes);
        if ($this->totalBytes > BundleConstants::MAX_TOTAL_UNCOMPRESSED_BYTES) {
            throw new BundleExportException('Bundle exceeds total uncompressed size cap');
        }
        if ($this->zip->addFromString($entryPath, $bytes) !== true) {
            throw new BundleExportException("Could not add entry to zip: $entryPath");
        }
        // Store uncompressed (ZIP_STORED) for byte-accounting symmetry.
        $this->zip->setCompressionName($entryPath, \ZipArchive::CM_STORE);
    }

    public function commit(): void
    {
        if ($this->zip->close() !== true) {
            throw new BundleExportException("Could not close zip: {$this->tmpPath}");
        }
        if (! rename($this->tmpPath, $this->finalPath)) {
            @unlink($this->tmpPath);
            throw new BundleExportException("Could not rename temp bundle to {$this->finalPath}");
        }
    }

    public function discard(): void
    {
        @$this->zip->close();
        @unlink($this->tmpPath);
    }
}
