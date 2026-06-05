<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor\OpenTimestamps;

use Fissible\Attest\Anchor\OpenTimestamps\CalendarUnavailable;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class OpenTimestampsCalendarClientTest extends TestCase
{
    public function test_submit_posts_digest_to_calendar(): void
    {
        $commitment = str_repeat("\x11", 32);
        $transactions = [];
        $client = $this->client(
            [new Response(200, ['Content-Type' => OpenTimestampsCalendarClient::CONTENT_TYPE], $this->pendingTimestampBytes())],
            $transactions,
        );

        $timestamp = $client->submit('https://calendar.example', $commitment);

        $this->assertSame($commitment, $timestamp->message);
        $this->assertSame('POST', $transactions[0]['request']->getMethod());
        $this->assertSame('https://calendar.example/digest', (string) $transactions[0]['request']->getUri());
        $this->assertSame($commitment, (string) $transactions[0]['request']->getBody());
        $this->assertSame(OpenTimestampsCalendarClient::CONTENT_TYPE, $transactions[0]['request']->getHeaderLine('Content-Type'));
    }

    public function test_upgrade_gets_timestamp_for_commitment(): void
    {
        $commitment = str_repeat("\x22", 32);
        $transactions = [];
        $client = $this->client(
            [new Response(200, ['Content-Type' => OpenTimestampsCalendarClient::CONTENT_TYPE], $this->bitcoinTimestampBytes())],
            $transactions,
        );

        $timestamp = $client->upgrade('https://calendar.example', $commitment);

        $this->assertSame($commitment, $timestamp->message);
        $this->assertSame('GET', $transactions[0]['request']->getMethod());
        $this->assertSame(
            'https://calendar.example/timestamp/' . bin2hex($commitment),
            (string) $transactions[0]['request']->getUri(),
        );
    }

    public function test_http_error_throws_calendar_unavailable(): void
    {
        $transactions = [];
        $client = $this->client([new Response(503)], $transactions);

        $this->expectException(CalendarUnavailable::class);
        $this->expectExceptionMessage('HTTP 503');

        $client->submit('https://calendar.example', str_repeat("\x11", 32));
    }

    public function test_oversized_response_throws_calendar_unavailable(): void
    {
        $transactions = [];
        $client = $this->client([new Response(200, [], 'too-large')], $transactions, maxResponseBytes: 4);

        $this->expectException(CalendarUnavailable::class);
        $this->expectExceptionMessage('max size');

        $client->submit('https://calendar.example', str_repeat("\x11", 32));
    }

    /**
     * @param list<Response> $responses
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     */
    private function client(array $responses, array &$transactions, int $maxResponseBytes = 1048576): OpenTimestampsCalendarClient
    {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($transactions));
        $http = new Client(['handler' => $stack]);
        $factory = new HttpFactory();

        return new OpenTimestampsCalendarClient($http, $factory, $factory, $maxResponseBytes);
    }

    private function pendingTimestampBytes(): string
    {
        return OpenTimestampsCodec::encodeTimestampBytes(
            (new OpenTimestampsTimestamp(str_repeat("\x00", 32)))
                ->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example')),
        );
    }

    private function bitcoinTimestampBytes(): string
    {
        return OpenTimestampsCodec::encodeTimestampBytes(
            (new OpenTimestampsTimestamp(str_repeat("\x00", 32)))
                ->withAttestation(OpenTimestampsAttestation::bitcoin(840000)),
        );
    }
}

