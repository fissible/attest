<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final readonly class OpenTimestampsCalendarClient
{
    public const CONTENT_TYPE = 'application/vnd.opentimestamps.v1';
    public const MAX_RESPONSE_BYTES = 1048576;

    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
        private int $maxResponseBytes = self::MAX_RESPONSE_BYTES,
    ) {
        if ($maxResponseBytes < 1) {
            throw new \InvalidArgumentException('maxResponseBytes must be >= 1');
        }
    }

    /**
     * @param array<string, mixed> $guzzleOptions
     */
    public static function withGuzzle(array $guzzleOptions = []): self
    {
        if (! class_exists(Client::class) || ! class_exists(HttpFactory::class)) {
            throw new \LogicException('guzzlehttp/guzzle and guzzlehttp/psr7 are required for withGuzzle()');
        }

        $client = new Client($guzzleOptions);
        $factory = new HttpFactory();

        return new self($client, $factory, $factory);
    }

    public function submit(string $calendarBaseUrl, string $commitment): OpenTimestampsTimestamp
    {
        if (strlen($commitment) !== 32) {
            throw new \InvalidArgumentException('calendar commitment must be 32 bytes');
        }

        $url = $this->joinUrl($calendarBaseUrl, '/digest');
        $request = $this->requests
            ->createRequest('POST', $url)
            ->withHeader('Accept', self::CONTENT_TYPE)
            ->withHeader('Content-Type', self::CONTENT_TYPE)
            ->withBody($this->streams->createStream($commitment));

        return $this->sendTimestampRequest($request, $commitment);
    }

    public function upgrade(string $pendingUri, string $commitment): OpenTimestampsTimestamp
    {
        if (strlen($commitment) !== 32) {
            throw new \InvalidArgumentException('calendar commitment must be 32 bytes');
        }

        $request = $this->requests
            ->createRequest('GET', $pendingUri . '/timestamp/' . bin2hex($commitment))
            ->withHeader('Accept', self::CONTENT_TYPE);

        return $this->sendTimestampRequest($request, $commitment);
    }

    private function sendTimestampRequest(\Psr\Http\Message\RequestInterface $request, string $message): OpenTimestampsTimestamp
    {
        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new CalendarUnavailable('OpenTimestamps calendar request failed: ' . $e->getMessage(), previous: $e);
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw new CalendarUnavailable('OpenTimestamps calendar returned HTTP ' . $status);
        }

        $body = (string) $response->getBody();
        if (strlen($body) > $this->maxResponseBytes) {
            throw new CalendarUnavailable('OpenTimestamps calendar response exceeds max size');
        }

        return OpenTimestampsCodec::decodeTimestampBytes($body, $message);
    }

    private function joinUrl(string $baseUrl, string $path): string
    {
        if (! preg_match('/\Ahttps?:\/\/[A-Za-z0-9.\-_:\/]+\z/', $baseUrl)) {
            throw new \InvalidArgumentException('calendar base URL is invalid');
        }

        return rtrim($baseUrl, '/') . $path;
    }
}
