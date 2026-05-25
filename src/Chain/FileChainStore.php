<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;

final class FileChainStore implements ChainStore
{
    private readonly PathMapper $mapper;

    public function __construct(string $rootDir)
    {
        $this->mapper = new PathMapper($rootDir);
        if (! is_dir($this->mapper->chainsDir())) {
            @mkdir($this->mapper->chainsDir(), 0o700, recursive: true);
        }
    }

    public function append(string $chainId, callable $buildAndSign): SignedEnvelope
    {
        $lockPath = $this->mapper->lockPath($chainId);
        @mkdir(dirname($lockPath), 0o700, recursive: true);
        $lockFp = fopen($lockPath, 'cb');
        if ($lockFp === false) {
            throw new ChainLockUnavailable($chainId);
        }
        try {
            if (! flock($lockFp, LOCK_EX)) {
                throw new ChainLockUnavailable($chainId);
            }

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

            $jsonlPath = $this->mapper->jsonlPath($chainId);
            $line = $signed->signedCanonicalBytes() . "\n";
            $dataFp = fopen($jsonlPath, 'ab');
            if ($dataFp === false) {
                throw new \RuntimeException("Could not open chain file: $jsonlPath");
            }
            try {
                fwrite($dataFp, $line);
                fflush($dataFp);
                // PHP has no portable fsync; fflush + close is sufficient on common
                // POSIX filesystems for durability against process crashes. Power-loss
                // durability requires an OS-level fsync hook — documented as a future
                // enhancement in CHANGELOG.
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
        return $last === null ? null : EnvelopeCodec::decodeSigned($last);
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
            while (($line = fgets($fp)) !== false) {
                $line = rtrim($line, "\n");
                if ($line === '') {
                    continue;
                }
                $env = EnvelopeCodec::decodeSigned($line);
                if ($env->envelope->seq < $fromSeq) {
                    continue;
                }
                if ($toSeq !== null && $env->envelope->seq > $toSeq) {
                    break;
                }
                yield $env;
            }
        } finally {
            fclose($fp);
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
}
