<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Chain\PathMapper;

/**
 * @experimental
 */
final class FileAnchorClaimStore implements AnchorClaimStore
{
    private readonly PathMapper $mapper;

    public function __construct(string $rootDir)
    {
        $this->mapper = new PathMapper($rootDir);
    }

    public function claim(string $anchorId, AnchorClaim $details): bool
    {
        AnchorClaim::assertAnchorId($anchorId);

        $dir = $this->claimDir($anchorId, $details->chainId);
        $parent = dirname($dir);
        if (! is_dir($parent)) {
            @mkdir($parent, 0o700, recursive: true);
        }

        if (! @mkdir($dir, 0o700)) {
            return false;
        }

        try {
            $this->writeClaimAtomic($dir, $anchorId, $details);
        } catch (\Throwable $e) {
            @rmdir($dir);
            throw $e;
        }

        return true;
    }

    public function release(string $anchorId): void
    {
        $dir = $this->findClaimDir($anchorId);
        if ($dir === null) {
            return;
        }

        $claim = $this->readClaim($dir, $anchorId);
        if ($claim->isCompleted()) {
            return;
        }

        @unlink($this->claimPath($dir));
        @rmdir($dir);
    }

    public function complete(string $anchorId, string $envelopeId): void
    {
        if ($envelopeId === '') {
            throw new \InvalidArgumentException('envelopeId must not be empty');
        }

        $dir = $this->findClaimDir($anchorId);
        if ($dir === null) {
            throw new \RuntimeException('Anchor claim not found: ' . $anchorId);
        }

        $claim = $this->readClaim($dir, $anchorId);
        if ($claim->isCompleted()) {
            if ($claim->completedEnvelopeId !== $envelopeId) {
                throw new \RuntimeException('Anchor claim already completed with a different envelope ID');
            }
            return;
        }

        $completed = $claim->complete($envelopeId, $this->nowIso8601());
        $this->writeClaimAtomic($dir, $anchorId, $completed);
    }

    public function reclaimExpired(int $ttlSeconds): iterable
    {
        if ($ttlSeconds < 0) {
            throw new \InvalidArgumentException('ttlSeconds must be >= 0');
        }

        $now = time();
        foreach ($this->claimFiles() as $anchorId => $claimFile) {
            $claim = $this->readClaim(dirname($claimFile), $anchorId);
            if ($claim->isCompleted()) {
                continue;
            }

            $claimedAt = strtotime($claim->claimedAtIso8601);
            if ($claimedAt === false) {
                continue;
            }
            if ($claimedAt + $ttlSeconds < $now) {
                yield $anchorId => $claim;
            }
        }
    }

    private function claimDir(string $anchorId, string $chainId): string
    {
        return $this->mapper->anchorClaimsDir($chainId) . '/' . $anchorId;
    }

    private function claimPath(string $dir): string
    {
        return $dir . '/claim.json';
    }

    private function writeClaimAtomic(string $dir, string $anchorId, AnchorClaim $claim): void
    {
        $path = $this->claimPath($dir);
        $tmp = $path . '.tmp.' . bin2hex(random_bytes(4));
        $json = json_encode($claim->toArray($anchorId), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Could not encode anchor claim metadata');
        }
        if (file_put_contents($tmp, $json) === false) {
            throw new \RuntimeException('Could not write anchor claim metadata: ' . $path);
        }
        if (! @rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('Could not publish anchor claim metadata: ' . $path);
        }
    }

    private function readClaim(string $dir, string $anchorId): AnchorClaim
    {
        $path = $this->claimPath($dir);
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException('Could not read anchor claim metadata: ' . $path);
        }

        try {
            $decoded = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException('Invalid anchor claim metadata: ' . $path, previous: $e);
        }

        if (! is_array($decoded)) {
            throw new \RuntimeException('Anchor claim metadata must be an object: ' . $path);
        }

        return AnchorClaim::fromArray($decoded, $anchorId);
    }

    private function findClaimDir(string $anchorId): ?string
    {
        AnchorClaim::assertAnchorId($anchorId);
        foreach ($this->claimFiles() as $candidateAnchorId => $claimFile) {
            if ($candidateAnchorId === $anchorId) {
                return dirname($claimFile);
            }
        }
        return null;
    }

    /**
     * @return iterable<string, string> anchor_id => claim.json path
     */
    private function claimFiles(): iterable
    {
        $pattern = $this->mapper->chainsDir() . '/*.anchor-claims/*/claim.json';
        $files = glob($pattern);
        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            $anchorId = basename(dirname($file));
            if (preg_match('/\A[0-9a-f]{64}\z/', $anchorId) !== 1) {
                continue;
            }
            yield $anchorId => $file;
        }
    }

    private function nowIso8601(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z');
    }
}

