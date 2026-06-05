<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Verification\Warning;

final class BundleReader
{
    private \ZipArchive $zip;
    private BundleManifest $manifest;

    /** @var list<Warning> */
    private array $warnings = [];

    public static function open(string $path): self
    {
        $self = new self();
        $self->zip = new \ZipArchive();
        $opened = $self->zip->open($path, \ZipArchive::RDONLY);
        if ($opened !== true) {
            throw new InvalidBundle("Could not open bundle: $path (code $opened)");
        }
        $self->validateAndLoad();
        return $self;
    }

    private function validateAndLoad(): void
    {
        $numFiles = $this->zip->numFiles;
        $totalUncompressed = 0;
        $totalCompressed = 0;
        $sawManifest = false;
        $seen = [];

        for ($i = 0; $i < $numFiles; $i++) {
            $stat = $this->zip->statIndex($i);
            if ($stat === false) {
                throw new InvalidBundle("Could not stat entry $i");
            }
            $name = $stat['name'];

            try {
                BundleEntryPath::validate($name);
            } catch (\InvalidArgumentException $e) {
                throw new InvalidBundle(
                    "Bundle entry has invalid path '$name': " . $e->getMessage(),
                    previous: $e,
                );
            }

            if (isset($seen[$name])) {
                throw new InvalidBundle("Duplicate entry: $name");
            }
            $seen[$name] = true;

            $uncompressed = (int) $stat['size'];
            $compressed   = (int) $stat['comp_size'];

            if ($uncompressed > BundleConstants::MAX_MEMBER_BYTES) {
                throw new InvalidBundle("Entry $name exceeds per-member size cap");
            }

            $totalUncompressed += $uncompressed;
            $totalCompressed   += $compressed;

            if ($totalUncompressed > BundleConstants::MAX_TOTAL_UNCOMPRESSED_BYTES) {
                throw new InvalidBundle('Bundle exceeds total uncompressed size cap');
            }

            if ($name === BundleConstants::MANIFEST_ENTRY) {
                $sawManifest = true;
            }
        }

        if ($totalCompressed > 0
            && $totalUncompressed / max(1, $totalCompressed) > BundleConstants::MAX_COMPRESSION_RATIO
        ) {
            throw new InvalidBundle('Bundle compression ratio exceeds cap (zip-bomb guard)');
        }

        if (! $sawManifest) {
            throw new InvalidBundle('Bundle is missing manifest.json');
        }

        $manifestBytes = $this->zip->getFromName(BundleConstants::MANIFEST_ENTRY);
        if ($manifestBytes === false) {
            throw new InvalidBundle('Could not read manifest.json');
        }
        $this->manifest = BundleManifest::fromJson($manifestBytes);
    }

    public function manifest(): BundleManifest
    {
        return $this->manifest;
    }

    /**
     * Yields raw signed canonical envelope bytes, one per line, from the
     * chain segment JSONL file for $chainId.
     *
     * @return iterable<string>
     * @throws InvalidBundle if the chain file is absent.
     */
    public function readChainSegmentRaw(string $chainId): iterable
    {
        $expectedPath = BundleConstants::CHAINS_PREFIX
            . substr(hash('sha256', $chainId), 0, 32) . '.jsonl';
        $bytes = $this->zip->getFromName($expectedPath);
        if ($bytes === false) {
            throw new InvalidBundle("Bundle is missing chain segment for $chainId");
        }
        foreach (explode("\n", $bytes) as $line) {
            if ($line === '') {
                continue;
            }
            yield $line;
        }
    }

    /**
     * Yields decoded proof envelopes for $chainId.
     * Returns an empty iterable when the file is absent (no proof envelopes is valid).
     *
     * @return iterable<SignedEnvelope>
     */
    public function readProofEnvelopes(string $chainId): iterable
    {
        $expectedPath = BundleConstants::PROOF_ENVELOPES_PREFIX
            . substr(hash('sha256', $chainId), 0, 32) . '.jsonl';
        $bytes = $this->zip->getFromName($expectedPath);
        if ($bytes === false) {
            return;
        }
        foreach (explode("\n", $bytes) as $line) {
            if ($line === '') {
                continue;
            }
            yield EnvelopeCodec::decodeSigned($line);
        }
    }

    /**
     * Iterates manifest claimed keys, reads and decodes the key file from the
     * bundle, verifies the fingerprint, and yields validated entries.
     *
     * Fingerprint mismatches and missing/malformed key files emit a Warning and
     * skip the entry rather than throwing.
     *
     * @return iterable<array{fingerprint:string, keyId:string, pubkey:string}>
     */
    public function readClaimedKeys(): iterable
    {
        foreach ($this->manifest->claimedKeys as $km) {
            $b64 = $this->zip->getFromName($km->file);
            if ($b64 === false) {
                $this->warnings[] = new Warning(
                    'bundle_missing_claimed_key',
                    "Claimed key file not present: {$km->file}",
                    ['key_id' => $km->keyId, 'file' => $km->file],
                );
                continue;
            }

            $raw = base64_decode(trim($b64), strict: true);
            if ($raw === false || strlen($raw) !== 32) {
                $this->warnings[] = new Warning(
                    'bundle_invalid_claimed_key',
                    "Claimed key file is not a valid 32-byte Ed25519 pubkey: {$km->file}",
                    ['key_id' => $km->keyId, 'file' => $km->file],
                );
                continue;
            }

            $computed = bin2hex(hash('sha256', $raw, binary: true));
            $stated   = str_replace('sha256:', '', $km->fingerprint);

            if ($computed !== $stated) {
                $this->warnings[] = new Warning(
                    'bundle_claimed_key_fingerprint_mismatch',
                    "Claimed key fingerprint mismatch for {$km->keyId}",
                    ['key_id' => $km->keyId, 'expected' => $stated, 'computed' => $computed],
                );
                continue;
            }

            yield ['fingerprint' => $computed, 'keyId' => $km->keyId, 'pubkey' => $raw];
        }
    }

    /**
     * Returns the raw bytes of the receipt cache file for $anchorId, or null if
     * the file is not present in the bundle.
     */
    public function getReceiptCache(string $anchorId): ?string
    {
        $path  = BundleConstants::RECEIPTS_PREFIX . $anchorId . '.ots';
        $bytes = $this->zip->getFromName($path);
        return $bytes === false ? null : $bytes;
    }

    /**
     * @return list<Warning>
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    public function close(): void
    {
        $this->zip->close();
    }
}
