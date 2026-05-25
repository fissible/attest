<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

final readonly class PathMapper
{
    private const int MAX_CHAIN_ID_LEN = 191;

    public function __construct(public string $rootDir)
    {
    }

    public function jsonlPath(string $chainId): string
    {
        return $this->rootDir . '/chains/' . $this->hash($chainId) . '.jsonl';
    }

    public function lockPath(string $chainId): string
    {
        return $this->rootDir . '/chains/' . $this->hash($chainId) . '.lock';
    }

    public function metaPath(string $chainId): string
    {
        return $this->rootDir . '/chains/' . $this->hash($chainId) . '.meta.json';
    }

    public function anchorClaimsDir(string $chainId): string
    {
        return $this->rootDir . '/chains/' . $this->hash($chainId) . '.anchor-claims';
    }

    public function indexPath(): string
    {
        return $this->rootDir . '/index.json';
    }

    public function chainsDir(): string
    {
        return $this->rootDir . '/chains';
    }

    private function hash(string $chainId): string
    {
        $this->validate($chainId);
        return substr(hash('sha256', $chainId), 0, 32);
    }

    private function validate(string $chainId): void
    {
        if ($chainId === '') {
            throw new \InvalidArgumentException('chain_id must not be empty');
        }
        if (strlen($chainId) > self::MAX_CHAIN_ID_LEN) {
            throw new \InvalidArgumentException(
                'chain_id exceeds ' . self::MAX_CHAIN_ID_LEN . ' bytes'
            );
        }
        // Reject null byte and other control characters (0x00-0x1F, 0x7F).
        if (preg_match('/[\x00-\x1F\x7F]/', $chainId)) {
            throw new \InvalidArgumentException('chain_id contains control characters');
        }
    }
}
