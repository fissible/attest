<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

final class EsploraHeaderProvider implements BlockHeaderProvider
{
    private string $baseUrl;

    public function __construct(
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        string $baseUrl = 'https://blockstream.info/api',
        private readonly string $name = 'esplora',
    ) {
        if ($name === '') {
            throw new \InvalidArgumentException('provider name must not be empty');
        }
        $this->baseUrl = $this->normalizeBaseUrl($baseUrl);
    }

    public function name(): string
    {
        return $this->name;
    }

    public function trustLevel(): TrustLevel
    {
        return TrustLevel::REMOTE;
    }

    public function getActiveChainHeaderByHeight(int $height): HeaderLookupResult
    {
        if ($height < 0) {
            throw new \InvalidArgumentException('height must be >= 0');
        }

        try {
            $tipHeight = $this->getInt('/blocks/tip/height');
            if ($height > $tipHeight) {
                return HeaderLookupResult::notFoundOrBehind(
                    $this->name(),
                    $this->trustLevel(),
                    "tip $tipHeight is behind requested height $height",
                );
            }

            $hash = strtolower($this->getText('/block-height/' . $height));
            $status = $this->getJson('/block/' . $hash . '/status');
            if (($status['in_best_chain'] ?? null) !== true) {
                return HeaderLookupResult::notFoundOrBehind(
                    $this->name(),
                    $this->trustLevel(),
                    'block is not in Esplora best chain',
                );
            }

            $block = $this->getJson('/block/' . $hash);
            $blockHeight = $this->arrayInt($block, 'height');
            if ($blockHeight !== $height) {
                throw new \RuntimeException("Esplora block height mismatch: expected $height, got $blockHeight");
            }

            return HeaderLookupResult::active($this->name(), $this->trustLevel(), new ActiveChainHeader(
                blockHash: strtolower($this->arrayString($block, 'id', fallback: $hash)),
                height: $blockHeight,
                confirmations: $tipHeight - $height + 1,
                merkleRoot: strtolower($this->arrayString($block, 'merkle_root')),
                timeUnixSec: $this->arrayInt($block, 'timestamp'),
            ));
        } catch (\Throwable $e) {
            return HeaderLookupResult::providerError($this->name(), $this->trustLevel(), $e->getMessage());
        }
    }

    private function getInt(string $path): int
    {
        $text = $this->getText($path);
        if (! preg_match('/\A\d+\z/', $text)) {
            throw new \RuntimeException('Esplora integer endpoint returned invalid body');
        }

        return (int) $text;
    }

    /**
     * @return array<string, mixed>
     */
    private function getJson(string $path): array
    {
        $text = $this->getText($path);
        try {
            $decoded = json_decode($text, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException('Esplora returned malformed JSON: ' . $e->getMessage(), previous: $e);
        }
        if (! is_array($decoded)) {
            throw new \RuntimeException('Esplora JSON endpoint must return an object');
        }

        return $decoded;
    }

    private function getText(string $path): string
    {
        $request = $this->requests
            ->createRequest('GET', $this->baseUrl . $path)
            ->withHeader('Accept', 'application/json, text/plain');

        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new \RuntimeException('Esplora request failed: ' . $e->getMessage(), previous: $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException("Esplora HTTP $status from " . $this->baseUrl . $path);
        }

        return trim((string) $response->getBody());
    }

    /**
     * @param array<string, mixed> $data
     */
    private function arrayString(array $data, string $key, ?string $fallback = null): string
    {
        if (! array_key_exists($key, $data)) {
            if ($fallback !== null) {
                return $fallback;
            }
            throw new \RuntimeException("Esplora block missing string field: $key");
        }
        if (! is_string($data[$key])) {
            throw new \RuntimeException("Esplora block field must be string: $key");
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function arrayInt(array $data, string $key): int
    {
        if (! array_key_exists($key, $data) || ! is_int($data[$key])) {
            throw new \RuntimeException("Esplora block missing integer field: $key");
        }

        return $data[$key];
    }

    private function normalizeBaseUrl(string $baseUrl): string
    {
        $parts = parse_url($baseUrl);
        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('baseUrl must be an absolute HTTP URL');
        }
        if ($parts['scheme'] !== 'http' && $parts['scheme'] !== 'https') {
            throw new \InvalidArgumentException('baseUrl must use http or https');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new \InvalidArgumentException('baseUrl must not contain credentials');
        }

        return rtrim($baseUrl, '/');
    }
}

