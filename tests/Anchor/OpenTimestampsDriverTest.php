<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\OpenTimestamps\CalendarUnavailable;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Merkle\MerkleTree;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class OpenTimestampsDriverTest extends TestCase
{
    public function test_anchor_submits_nonced_commitment_not_raw_root(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [new Response(200, [], $this->pendingTimestampBytes())],
            $transactions,
            calendarUrls: ['https://calendar.example'],
        );
        $target = $this->target();

        $receipt = $driver->anchor($target);
        $proof = OpenTimestampsCodec::decodeDetached($receipt->receiptBytes, $target->rootHex);
        $attestationPath = $proof->timestamp->allAttestations()[0];

        $this->assertSame(ProofState::PENDING, $receipt->state);
        $this->assertSame(str_repeat('a', 64), $proof->fileDigestHex());
        $this->assertSame(32, strlen($attestationPath->message));
        $this->assertNotSame(hex2bin($target->rootHex), $attestationPath->message);
        $this->assertSame($attestationPath->message, (string) $transactions[0]['request']->getBody());
    }

    public function test_one_success_among_failures_succeeds_when_min_calendars_is_one(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [
                new Response(500),
                new Response(200, [], $this->pendingTimestampBytes()),
            ],
            $transactions,
            calendarUrls: ['https://a.example', 'https://b.example'],
            minCalendars: 1,
        );

        $receipt = $driver->anchor($this->target());

        $this->assertSame(ProofState::PENDING, $receipt->state);
        $this->assertCount(2, $transactions);
    }

    public function test_fewer_than_min_calendars_throws(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [new Response(500), new Response(500)],
            $transactions,
            calendarUrls: ['https://a.example', 'https://b.example'],
            minCalendars: 1,
        );

        $this->expectException(CalendarUnavailable::class);

        $driver->anchor($this->target());
    }

    public function test_upgrade_transitions_pending_receipt_to_upgraded(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [new Response(200, [], $this->bitcoinTimestampBytes())],
            $transactions,
            calendarUrls: ['https://calendar.example'],
            upgradeAllowlist: ['https://calendar.example'],
        );
        $target = $this->target();
        $receipt = new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: ProofState::PENDING,
            receiptBytes: $this->pendingReceiptBytes($target),
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );

        $upgraded = $driver->upgrade($receipt);

        $this->assertSame(ProofState::UPGRADED, $upgraded->state);
        $this->assertNotSame($receipt->receiptBytes, $upgraded->receiptBytes);
        $this->assertSame($upgraded, $driver->upgrade($upgraded));
    }

    private function target(): AnchorTarget
    {
        return new AnchorTarget('chain', 1, 10, MerkleTree::ALGORITHM, str_repeat('a', 64));
    }

    /**
     * @param list<Response> $responses
     * @param list<array{request: \Psr\Http\Message\RequestInterface, response?: \Psr\Http\Message\ResponseInterface, error?: mixed}> $transactions
     * @param list<string> $calendarUrls
     * @param list<string> $upgradeAllowlist
     */
    private function driver(
        array $responses,
        array &$transactions,
        array $calendarUrls,
        int $minCalendars = 1,
        array $upgradeAllowlist = [],
    ): OpenTimestampsDriver {
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($transactions));
        $http = new Client(['handler' => $stack]);
        $factory = new HttpFactory();

        return new OpenTimestampsDriver(
            calendarClient: new OpenTimestampsCalendarClient($http, $factory, $factory),
            calendarUrls: $calendarUrls,
            minCalendars: $minCalendars,
            upgradeAllowlist: $upgradeAllowlist === [] ? $calendarUrls : $upgradeAllowlist,
        );
    }

    private function pendingReceiptBytes(AnchorTarget $target): string
    {
        $rootBytes = hex2bin($target->rootHex);
        $this->assertIsString($rootBytes);
        $timestamp = (new OpenTimestampsTimestamp($rootBytes))
            ->withAttestation(OpenTimestampsAttestation::pending('https://calendar.example'));

        return OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp));
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

