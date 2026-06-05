<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Headers;

use Fissible\Attest\Headers\EsploraHeaderProvider;
use Fissible\Attest\Headers\HeaderLookupStatus;
use Fissible\Attest\Headers\TrustLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class EsploraHeaderProviderTest extends TestCase
{
    public function test_happy_path_maps_active_header(): void
    {
        $transactions = [];
        $hash = str_repeat('a', 64);
        $provider = $this->provider([
            new Response(200, [], '840010'),
            new Response(200, [], $hash),
            new Response(200, [], json_encode(['in_best_chain' => true], JSON_THROW_ON_ERROR)),
            new Response(200, [], json_encode([
                'id' => $hash,
                'height' => 840000,
                'merkle_root' => str_repeat('b', 64),
                'timestamp' => 1713571200,
            ], JSON_THROW_ON_ERROR)),
        ], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(840000);

        $this->assertSame(HeaderLookupStatus::ACTIVE, $result->status);
        $this->assertSame(TrustLevel::REMOTE, $result->trustLevel);
        $this->assertNotNull($result->header);
        $this->assertSame($hash, $result->header->blockHash);
        $this->assertSame(840000, $result->header->height);
        $this->assertSame(11, $result->header->confirmations);
        $this->assertSame(str_repeat('b', 64), $result->header->merkleRoot);
        $this->assertSame([
            'https://esplora.example/blocks/tip/height',
            'https://esplora.example/block-height/840000',
            'https://esplora.example/block/' . $hash . '/status',
            'https://esplora.example/block/' . $hash,
        ], $this->uris($transactions));
    }

    public function test_tip_behind_target_returns_not_found_or_behind(): void
    {
        $transactions = [];
        $provider = $this->provider([new Response(200, [], '10')], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(11);

        $this->assertSame(HeaderLookupStatus::NOT_FOUND_OR_BEHIND, $result->status);
        $this->assertNull($result->header);
        $this->assertCount(1, $transactions);
    }

    public function test_not_in_best_chain_is_not_success(): void
    {
        $transactions = [];
        $hash = str_repeat('a', 64);
        $provider = $this->provider([
            new Response(200, [], '840010'),
            new Response(200, [], $hash),
            new Response(200, [], json_encode(['in_best_chain' => false], JSON_THROW_ON_ERROR)),
        ], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(840000);

        $this->assertSame(HeaderLookupStatus::NOT_FOUND_OR_BEHIND, $result->status);
        $this->assertNull($result->header);
    }

    public function test_http_error_returns_provider_error(): void
    {
        $transactions = [];
        $provider = $this->provider([new Response(429)], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(1);

        $this->assertSame(HeaderLookupStatus::PROVIDER_ERROR, $result->status);
        $this->assertStringContainsString('HTTP 429', $result->diagnostic ?? '');
    }

    public function test_malformed_json_returns_provider_error(): void
    {
        $transactions = [];
        $hash = str_repeat('a', 64);
        $provider = $this->provider([
            new Response(200, [], '840010'),
            new Response(200, [], $hash),
            new Response(200, [], '{bad'),
        ], $transactions);

        $result = $provider->getActiveChainHeaderByHeight(840000);

        $this->assertSame(HeaderLookupStatus::PROVIDER_ERROR, $result->status);
        $this->assertStringContainsString('malformed JSON', $result->diagnostic ?? '');
    }

    public function test_invalid_base_url_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('baseUrl');

        $transactions = [];
        $this->provider([], $transactions, baseUrl: 'file:///tmp/esplora');
    }

    /**
     * @param list<Response> $responses
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     */
    private function provider(
        array $responses,
        array &$transactions,
        string $baseUrl = 'https://esplora.example',
    ): EsploraHeaderProvider {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($transactions));
        $http = new Client(['handler' => $stack]);
        $factory = new HttpFactory();

        return new EsploraHeaderProvider($http, $factory, $baseUrl);
    }

    /**
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     * @return list<string>
     */
    private function uris(array $transactions): array
    {
        return array_map(
            static fn (array $transaction): string => (string) $transaction['request']->getUri(),
            $transactions,
        );
    }
}
