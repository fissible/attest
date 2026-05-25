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
        throw new \LogicException('append() implemented in Task 1.10');
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
