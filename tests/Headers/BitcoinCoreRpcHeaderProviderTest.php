<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Headers;

use Fissible\Attest\Headers\BitcoinCoreRpcHeaderProvider;
use Fissible\Attest\Headers\HeaderLookupStatus;
use Fissible\Attest\Headers\TrustLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class BitcoinCoreRpcHeaderProviderTest extends TestCase
{
    public function test_happy_path_maps_active_header(): void
    {
        $transactions = [];
        $hash = str_repeat('a', 64);
        $provider = $this->provider([
            $this->rpcResponse(840010),
            $this->rpcResponse($hash),
            $this->rpcResponse([
                'hash' => $hash,
                'height' => 840000,
                'confirmations' => 11,
                'merkleroot' => str_repeat('b', 64),
                'time' => 1713571200,
            ]),
        ], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(840000);

        $this->assertSame(HeaderLookupStatus::ACTIVE, $result->status);
        $this->assertSame(TrustLevel::LOCAL, $result->trustLevel);
        $this->assertNotNull($result->header);
        $this->assertSame($hash, $result->header->blockHash);
        $this->assertSame(840000, $result->header->height);
        $this->assertSame(11, $result->header->confirmations);
        $this->assertSame(str_repeat('b', 64), $result->header->merkleRoot);
        $this->assertSame(['getblockcount', 'getblockhash', 'getblockheader'], $this->methods($transactions));
    }

    public function test_node_behind_height_returns_not_found_or_behind(): void
    {
        $transactions = [];
        $provider = $this->provider([$this->rpcResponse(10)], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(11);

        $this->assertSame(HeaderLookupStatus::NOT_FOUND_OR_BEHIND, $result->status);
        $this->assertNull($result->header);
        $this->assertCount(1, $transactions);
    }

    public function test_negative_confirmations_are_not_active(): void
    {
        $transactions = [];
        $hash = str_repeat('a', 64);
        $provider = $this->provider([
            $this->rpcResponse(840010),
            $this->rpcResponse($hash),
            $this->rpcResponse([
                'hash' => $hash,
                'height' => 840000,
                'confirmations' => -1,
                'merkleroot' => str_repeat('b', 64),
                'time' => 1713571200,
            ]),
        ], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(840000);

        $this->assertSame(HeaderLookupStatus::NOT_FOUND_OR_BEHIND, $result->status);
        $this->assertNull($result->header);
    }

    public function test_http_auth_failure_returns_provider_error_and_redacts_credentials(): void
    {
        $transactions = [];
        $provider = $this->provider([new Response(401)], $transactions, rpcUrl: 'http://user:secret@127.0.0.1:8332');

        $result = $provider->getActiveChainHeaderByHeight(1);

        $this->assertSame(HeaderLookupStatus::PROVIDER_ERROR, $result->status);
        $this->assertStringNotContainsString('secret', $result->diagnostic ?? '');
        $this->assertSame('Basic ' . base64_encode('user:secret'), $transactions[0]['request']->getHeaderLine('Authorization'));
        $this->assertSame('http://127.0.0.1:8332/', (string) $transactions[0]['request']->getUri());
    }

    public function test_malformed_json_returns_provider_error(): void
    {
        $transactions = [];
        $provider = $this->provider([new Response(200, [], '{bad')], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(1);

        $this->assertSame(HeaderLookupStatus::PROVIDER_ERROR, $result->status);
        $this->assertStringContainsString('malformed JSON', $result->diagnostic ?? '');
    }

    public function test_explicit_credentials_are_sent_as_basic_auth(): void
    {
        $transactions = [];
        $provider = $this->provider([new Response(401)], $transactions, username: 'alice', password: 'pw');

        $provider->getActiveChainHeaderByHeight(1);

        $this->assertSame('Basic ' . base64_encode('alice:pw'), $transactions[0]['request']->getHeaderLine('Authorization'));
    }

    public function test_cookie_file_credentials_are_supported(): void
    {
        $cookie = tempnam(sys_get_temp_dir(), 'attest-bitcoin-cookie-');
        $this->assertIsString($cookie);
        file_put_contents($cookie, 'cookieuser:cookiepass');
        $transactions = [];

        try {
            $provider = $this->provider([new Response(401)], $transactions, cookieFile: $cookie);
            $provider->getActiveChainHeaderByHeight(1);
        } finally {
            @unlink($cookie);
        }

        $this->assertSame(
            'Basic ' . base64_encode('cookieuser:cookiepass'),
            $transactions[0]['request']->getHeaderLine('Authorization'),
        );
    }

    /**
     * @param list<Response> $responses
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     */
    private function provider(
        array $responses,
        array &$transactions,
        string $rpcUrl = 'http://127.0.0.1:8332',
        ?string $username = null,
        ?string $password = null,
        ?string $cookieFile = null,
    ): BitcoinCoreRpcHeaderProvider {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($transactions));
        $http = new Client(['handler' => $stack]);
        $factory = new HttpFactory();

        return new BitcoinCoreRpcHeaderProvider(
            http: $http,
            requests: $factory,
            streams: $factory,
            rpcUrl: $rpcUrl,
            username: $username,
            password: $password,
            cookieFile: $cookieFile,
        );
    }

    private function rpcResponse(mixed $result): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'result' => $result,
            'error' => null,
            'id' => 1,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     * @return list<string>
     */
    private function methods(array $transactions): array
    {
        $methods = [];
        foreach ($transactions as $transaction) {
            $body = json_decode((string) $transaction['request']->getBody(), true, flags: JSON_THROW_ON_ERROR);
            $this->assertIsArray($body);
            $this->assertIsString($body['method']);
            $methods[] = $body['method'];
        }

        return $methods;
    }
}

