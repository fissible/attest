<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;

/**
 * @api
 */
final class FileChainStore implements ChainStore, RawChainStore
{
    private readonly PathMapper $mapper;

    public function __construct(string $rootDir, private readonly bool $fsync = false)
    {
        $this->mapper = new PathMapper($rootDir);
        if (! is_dir($this->mapper->chainsDir())) {
            @mkdir($this->mapper->chainsDir(), 0o700, recursive: true);
        }
    }

    /**
     * Appends an envelope under the per-chain lock.
     *
     * A torn trailing line is discarded under that lock before the tail is
     * read. This is the only repair append() performs: a trailing line that
     * contains a "\n" is not torn (canonical JSON has no raw newlines), but
     * corruption, which tail() reports as UndecodableRecord and append() does
     * not repair.
     */
    public function append(string $chainId, callable $buildAndSign): SignedEnvelope
    {
        $lockPath = $this->mapper->lockPath($chainId);
        @mkdir(dirname($lockPath), 0o700, recursive: true);
        $lockFp = @fopen($lockPath, 'cb'); // failure is reported as ChainLockUnavailable below
        if ($lockFp === false) {
            throw new ChainLockUnavailable($chainId);
        }
        try {
            if (! flock($lockFp, LOCK_EX)) {
                throw new ChainLockUnavailable($chainId);
            }

            $jsonlPath = $this->mapper->jsonlPath($chainId);
            $this->discardTornTrailingLine($jsonlPath);
            $tail = $this->tail($chainId);
            $nextSeq = $tail === null ? 1 : ($tail->envelope->seq + 1);
            $prevHash = $tail === null ? null : $tail->selfHash();
            $now = $this->monotonicTimestamp($tail);
            $ctx = new AppendContext($chainId, $nextSeq, $prevHash, $now);

            $signed = $buildAndSign($ctx);

            if ($signed->envelope->chain !== $ctx->chainId
                || $signed->envelope->seq !== $ctx->sequence
                || $signed->envelope->prevHash !== $ctx->prevHash
                || $signed->envelope->ts !== $ctx->timestampIso8601
            ) {
                throw new ContextMismatch(sprintf(
                    "Envelope context mismatch (expected chain=%s seq=%d prev=%s ts=%s; got chain=%s seq=%d prev=%s ts=%s)",
                    $ctx->chainId,
                    $ctx->sequence,
                    $ctx->prevHash ?? 'null',
                    $ctx->timestampIso8601,
                    $signed->envelope->chain,
                    $signed->envelope->seq,
                    $signed->envelope->prevHash ?? 'null',
                    $signed->envelope->ts,
                ));
            }

            $line = $signed->signedCanonicalBytes() . "\n";
            $dataFp = fopen($jsonlPath, 'ab');
            if ($dataFp === false) {
                throw new \RuntimeException("Could not open chain file: $jsonlPath");
            }
            try {
                fwrite($dataFp, $line);
                fflush($dataFp);
                // fflush pushes PHP's buffers to the OS — durable against process
                // crashes. With fsync enabled, also force the OS to flush to the
                // physical disk for power-loss durability. This is opt-in because an
                // fsync per append costs throughput. fsync() requires PHP >= 8.1;
                // core requires >= 8.2. Note: the .meta.json / index.json sidecars
                // are written via atomic rename and are not separately fsynced.
                if ($this->fsync) {
                    fsync($dataFp);
                }
            } finally {
                fclose($dataFp);
            }

            $this->writeMetaAtomic($chainId, $nextSeq);
            $this->updateIndexAtomic($chainId);

            return $signed;
        } finally {
            flock($lockFp, LOCK_UN);
            fclose($lockFp);
        }
    }

    private function monotonicTimestamp(?SignedEnvelope $tail): string
    {
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z');
        if ($tail === null) {
            return $now;
        }
        if (strcmp($now, $tail->envelope->ts) > 0) {
            return $now;
        }
        // Tail's ts is >= now; bump by 1ms to guarantee monotonicity.
        $tailDt = new \DateTimeImmutable($tail->envelope->ts);
        $bumped = $tailDt->modify('+1 millisecond');
        if ($bumped === false) {
            throw new \RuntimeException('Could not advance tail timestamp');
        }
        return $bumped->format('Y-m-d\TH:i:s.v\Z');
    }

    private function writeMetaAtomic(string $chainId, int $envelopeCount): void
    {
        $metaPath = $this->mapper->metaPath($chainId);
        $tmp = $metaPath . '.tmp.' . bin2hex(random_bytes(4));
        $createdAt = gmdate('c');
        if (is_file($metaPath)) {
            $existing = json_decode((string) file_get_contents($metaPath), true);
            if (is_array($existing) && isset($existing['created_at']) && is_string($existing['created_at'])) {
                $createdAt = $existing['created_at'];
            }
        }
        $meta = [
            'chain_id' => $chainId,
            'created_at' => $createdAt,
            'envelope_count' => $envelopeCount,
            'updated_at' => gmdate('c'),
        ];
        file_put_contents($tmp, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        rename($tmp, $metaPath);
    }

    private function updateIndexAtomic(string $chainId): void
    {
        $indexPath = $this->mapper->indexPath();
        /** @var array<string, string> $current */
        $current = [];
        if (is_file($indexPath)) {
            $decoded = json_decode((string) file_get_contents($indexPath), true);
            if (is_array($decoded)) {
                $current = $decoded;
            }
        }
        if (! array_key_exists($chainId, $current)) {
            $current[$chainId] = substr(hash('sha256', $chainId), 0, 32);
            $tmp = $indexPath . '.tmp.' . bin2hex(random_bytes(4));
            file_put_contents($tmp, json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            rename($tmp, $indexPath);
        }
    }

    public function tail(string $chainId): ?SignedEnvelope
    {
        $path = $this->mapper->jsonlPath($chainId);
        if (! is_file($path)) {
            return null;
        }
        $last = $this->readLastLine($path);
        if ($last === null) {
            return null;
        }
        try {
            return EnvelopeCodec::decodeSigned($last);
        } catch (\Throwable $e) {
            throw UndecodableRecord::wrap($chainId, null, $e);
        }
    }

    public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
    {
        $path = $this->mapper->jsonlPath($chainId);
        if (! is_file($path)) {
            return;
        }
        $fp = fopen($path, 'rb');
        if ($fp === false) {
            return;
        }
        try {
            foreach ($this->decodedLines($fp, $chainId, $fromSeq, $toSeq) as $record) {
                yield $record['env'];
            }
        } finally {
            fclose($fp);
        }
    }

    public function readRawRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
    {
        if ($fromSeq < 1) {
            throw new \InvalidArgumentException('fromSeq must be >= 1');
        }
        if ($toSeq !== null && $toSeq < $fromSeq) {
            throw new \InvalidArgumentException('toSeq must be >= fromSeq');
        }

        $path = $this->mapper->jsonlPath($chainId);
        if (! is_file($path)) {
            return;
        }

        $lockPath = $this->mapper->lockPath($chainId);
        @mkdir(dirname($lockPath), 0o700, recursive: true);
        $lockFp = @fopen($lockPath, 'cb'); // failure is reported as ChainLockUnavailable below
        if ($lockFp === false) {
            throw new ChainLockUnavailable($chainId);
        }

        try {
            if (! flock($lockFp, LOCK_SH)) {
                throw new ChainLockUnavailable($chainId);
            }

            $fp = fopen($path, 'rb');
            if ($fp === false) {
                return;
            }

            try {
                foreach ($this->decodedLines($fp, $chainId, $fromSeq, $toSeq) as $record) {
                    yield $record['raw'];
                }
            } finally {
                fclose($fp);
            }
        } finally {
            flock($lockFp, LOCK_UN);
            fclose($lockFp);
        }
    }

    /**
     * Shared line reader for readRange()/readRawRange().
     *
     * - Stops at a line without a trailing newline: append() always writes one,
     *   so its absence means a torn or truncated write, never a complete record.
     * - A line that fails to decode is assigned the sequence it occupies by
     *   position (last decoded seq + 1). Inside the requested range that is an
     *   UndecodableRecord; before the range it is skipped; after the range it
     *   ends the read. A corrupt record outside [fromSeq, toSeq] therefore
     *   cannot break a read of an intact range.
     *
     * @param resource $fp
     * @return iterable<array{raw: string, env: SignedEnvelope}>
     */
    private function decodedLines($fp, string $chainId, int $fromSeq, ?int $toSeq): iterable
    {
        $lastSeq = 0;
        while (($line = fgets($fp)) !== false) {
            if (! str_ends_with($line, "\n")) {
                break;
            }
            $raw = rtrim($line, "\r\n");
            if ($raw === '') {
                continue;
            }
            try {
                $env = EnvelopeCodec::decodeSigned($raw);
            } catch (\Throwable $e) {
                $assumedSeq = $lastSeq + 1;
                if ($toSeq !== null && $assumedSeq > $toSeq) {
                    break;
                }
                if ($assumedSeq < $fromSeq) {
                    $lastSeq = $assumedSeq;
                    continue;
                }
                throw UndecodableRecord::wrap($chainId, $assumedSeq, $e);
            }
            $lastSeq = $env->envelope->seq;
            if ($env->envelope->seq < $fromSeq) {
                continue;
            }
            if ($toSeq !== null && $env->envelope->seq > $toSeq) {
                break;
            }
            yield ['raw' => $raw, 'env' => $env];
        }
    }

    public function listChains(): iterable
    {
        $indexPath = $this->mapper->indexPath();
        if (! is_file($indexPath)) {
            return;
        }
        $contents = file_get_contents($indexPath);
        if ($contents === false) {
            return;
        }
        try {
            /** @var array<string, string> $index */
            $index = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return;
        }
        yield from array_keys($index);
    }

    public function exists(string $chainId): bool
    {
        return is_file($this->mapper->jsonlPath($chainId));
    }

    /**
     * Efficient last-line read for large JSONL files: seek to EOF, scan
     * backwards in 8KB chunks looking for the last newline.
     */
    private function readLastLine(string $path): ?string
    {
        $fp = fopen($path, 'rb');
        if ($fp === false) {
            return null;
        }
        try {
            $size = filesize($path);
            if ($size === false || $size === 0) {
                return null;
            }
            // append() always terminates a record with "\n"; a file that does
            // not end with one has a torn or truncated last line, which is not
            // a record. Drop it and report the last complete line instead.
            fseek($fp, $size - 1);
            if (fread($fp, 1) !== "\n") {
                $lastNewline = $this->lastNewlinePosition($fp, $size);
                if ($lastNewline === null) {
                    return null;
                }
                $size = $lastNewline + 1;
            }
            $chunk = 8192;
            $pos = $size;
            $buffer = '';
            while ($pos > 0) {
                $read = min($chunk, $pos);
                $pos -= $read;
                fseek($fp, $pos);
                $buffer = fread($fp, $read) . $buffer;
                $trimmed = rtrim($buffer, "\n");
                $nlPos = strrpos($trimmed, "\n");
                if ($nlPos !== false) {
                    return substr($trimmed, $nlPos + 1);
                }
                if ($pos === 0) {
                    return $trimmed === '' ? null : $trimmed;
                }
            }
            return null;
        } finally {
            fclose($fp);
        }
    }

    /**
     * Discards an unterminated final line, if present.
     */
    private function discardTornTrailingLine(string $path): void
    {
        if (! is_file($path)) {
            return;
        }

        $fp = fopen($path, 'r+b');
        if ($fp === false) {
            throw new \RuntimeException("Could not open chain file: $path");
        }

        try {
            clearstatcache(true, $path);
            $size = filesize($path);
            if ($size === false || $size === 0) {
                return;
            }

            fseek($fp, $size - 1);
            if (fread($fp, 1) === "\n") {
                return;
            }

            $lastNewline = $this->lastNewlinePosition($fp, $size);
            $newSize = max(0, ($lastNewline ?? -1) + 1);
            if (! ftruncate($fp, $newSize)) {
                throw new \RuntimeException("Could not truncate chain file: $path");
            }
            fflush($fp);
            if ($this->fsync) {
                fsync($fp);
            }
            clearstatcache(true, $path);
        } finally {
            fclose($fp);
        }
    }

    /**
     * Offset of the last "\n" strictly before $end, or null if there is none.
     *
     * @param resource $fp
     */
    private function lastNewlinePosition($fp, int $end): ?int
    {
        $chunk = 8192;
        $pos = $end;
        while ($pos > 0) {
            $read = min($chunk, $pos);
            $pos -= $read;
            fseek($fp, $pos);
            $buffer = fread($fp, $read);
            if ($buffer === false) {
                return null;
            }
            $nl = strrpos($buffer, "\n");
            if ($nl !== false) {
                return $pos + $nl;
            }
        }

        return null;
    }
}
