<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class BitcoinCoreRpcHeaderProvider implements BlockHeaderProvider
{
    private string $rpcUrl;
    private ?string $username;
    private ?string $password;
    private int $id = 0;

    public function __construct(
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        string $rpcUrl,
        ?string $username = null,
        ?string $password = null,
        ?string $cookieFile = null,
        private readonly string $name = 'bitcoin-core-rpc',
    ) {
        if ($name === '') {
            throw new \InvalidArgumentException('provider name must not be empty');
        }

        [$cleanUrl, $urlUsername, $urlPassword] = $this->normalizeRpcUrl($rpcUrl);
        $this->rpcUrl = $cleanUrl;

        if ($cookieFile !== null && ($username === null || $password === null) && ($urlUsername === null || $urlPassword === null)) {
            [$username, $password] = $this->credentialsFromCookieFile($cookieFile);
        }

        $this->username = $username ?? $urlUsername;
        $this->password = $password ?? $urlPassword;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function trustLevel(): TrustLevel
    {
        return TrustLevel::LOCAL;
    }

    public function getActiveChainHeaderByHeight(int $height): HeaderLookupResult
    {
        if ($height < 0) {
            throw new \InvalidArgumentException('height must be >= 0');
        }

        try {
            $blockCount = $this->rpcInt('getblockcount');
            if ($height > $blockCount) {
                return HeaderLookupResult::notFoundOrBehind(
                    $this->name(),
                    $this->trustLevel(),
                    "node tip $blockCount is behind requested height $height",
                );
            }

            $blockHash = $this->rpcString('getblockhash', [$height]);
            $header = $this->rpcArray('getblockheader', [$blockHash, true]);
            $confirmations = $this->arrayInt($header, 'confirmations');
            if ($confirmations < 1) {
                return HeaderLookupResult::notFoundOrBehind(
                    $this->name(),
                    $this->trustLevel(),
                    'block header is not on the active chain',
                );
            }

            return HeaderLookupResult::active($this->name(), $this->trustLevel(), new ActiveChainHeader(
                blockHash: strtolower($this->arrayString($header, 'hash')),
                height: $this->arrayInt($header, 'height'),
                confirmations: $confirmations,
                merkleRoot: strtolower($this->arrayString($header, 'merkleroot')),
                timeUnixSec: $this->arrayInt($header, 'time'),
            ));
        } catch (\Throwable $e) {
            return HeaderLookupResult::providerError($this->name(), $this->trustLevel(), $e->getMessage());
        }
    }

    /**
     * @param list<mixed> $params
     */
    private function rpcInt(string $method, array $params = []): int
    {
        $result = $this->rpc($method, $params);
        if (! is_int($result)) {
            throw new \RuntimeException("Bitcoin Core RPC $method result must be an integer");
        }

        return $result;
    }

    /**
     * @param list<mixed> $params
     */
    private function rpcString(string $method, array $params = []): string
    {
        $result = $this->rpc($method, $params);
        if (! is_string($result)) {
            throw new \RuntimeException("Bitcoin Core RPC $method result must be a string");
        }

        return $result;
    }

    /**
     * @param list<mixed> $params
     * @return array<string, mixed>
     */
    private function rpcArray(string $method, array $params = []): array
    {
        $result = $this->rpc($method, $params);
        if (! is_array($result)) {
            throw new \RuntimeException("Bitcoin Core RPC $method result must be an object");
        }

        return $result;
    }

    /**
     * @param list<mixed> $params
     */
    private function rpc(string $method, array $params = []): mixed
    {
        $payload = [
            'jsonrpc' => '1.0',
            'id' => ++$this->id,
            'method' => $method,
            'params' => $params,
        ];
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Could not encode Bitcoin Core RPC payload');
        }

        $request = $this->requests
            ->createRequest('POST', $this->rpcUrl)
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streams->createStream($json));

        if ($this->username !== null && $this->password !== null) {
            $request = $request->withHeader(
                'Authorization',
                'Basic ' . base64_encode($this->username . ':' . $this->password),
            );
        }

        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new \RuntimeException('Bitcoin Core RPC request failed: ' . $e->getMessage(), previous: $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new \RuntimeException("Bitcoin Core RPC HTTP $status from " . $this->rpcUrl);
        }

        try {
            $decoded = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \RuntimeException('Bitcoin Core RPC returned malformed JSON: ' . $e->getMessage(), previous: $e);
        }

        if (! is_array($decoded)) {
            throw new \RuntimeException('Bitcoin Core RPC response must be a JSON object');
        }
        if (($decoded['error'] ?? null) !== null) {
            throw new \RuntimeException('Bitcoin Core RPC error: ' . json_encode($decoded['error'], JSON_UNESCAPED_SLASHES));
        }
        if (! array_key_exists('result', $decoded)) {
            throw new \RuntimeException('Bitcoin Core RPC response missing result');
        }

        return $decoded['result'];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function arrayString(array $data, string $key): string
    {
        if (! array_key_exists($key, $data) || ! is_string($data[$key])) {
            throw new \RuntimeException("Bitcoin Core header missing string field: $key");
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function arrayInt(array $data, string $key): int
    {
        if (! array_key_exists($key, $data) || ! is_int($data[$key])) {
            throw new \RuntimeException("Bitcoin Core header missing integer field: $key");
        }

        return $data[$key];
    }

    /**
     * @return array{0:string,1:?string,2:?string}
     */
    private function normalizeRpcUrl(string $rpcUrl): array
    {
        $parts = parse_url($rpcUrl);
        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('rpcUrl must be an absolute HTTP URL');
        }
        if ($parts['scheme'] !== 'http' && $parts['scheme'] !== 'https') {
            throw new \InvalidArgumentException('rpcUrl must use http or https');
        }

        $user = isset($parts['user']) ? rawurldecode($parts['user']) : null;
        $pass = isset($parts['pass']) ? rawurldecode($parts['pass']) : null;
        $url = $parts['scheme'] . '://' . $parts['host'];
        if (isset($parts['port'])) {
            $url .= ':' . $parts['port'];
        }
        $url .= $parts['path'] ?? '/';
        if (isset($parts['query'])) {
            $url .= '?' . $parts['query'];
        }

        return [$url, $user, $pass];
    }

    /**
     * @return array{0:string,1:string}
     */
    private function credentialsFromCookieFile(string $cookieFile): array
    {
        $contents = file_get_contents($cookieFile);
        if ($contents === false) {
            throw new \InvalidArgumentException('Could not read Bitcoin Core RPC cookie file');
        }
        $contents = trim($contents);
        $parts = explode(':', $contents, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException('Bitcoin Core RPC cookie file must contain username:password');
        }

        return [$parts[0], $parts[1]];
    }
}
