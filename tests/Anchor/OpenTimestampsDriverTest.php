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
use Fissible\Attest\Verification\Warning;
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

    // ── Calendar reachability reporting (issue #33) ──────────────────────────
    //
    // upgrade() deliberately swallows CalendarUnavailable per attestation so a
    // sweep is best-effort, but the caller must still be able to tell "calendar
    // down, try later" from "calendar up, not yet confirmed". After each
    // upgrade() the driver exposes lastUpgradeAttempt(): how many pending
    // attestations it tried, how many calendars were unreachable, and a Warning
    // per failure.

    public function test_last_upgrade_attempt_is_null_before_any_upgrade(): void
    {
        $transactions = [];
        $driver = $this->driver([], $transactions, calendarUrls: ['https://calendar.example']);

        $this->assertNull($driver->lastUpgradeAttempt());
    }

    public function test_upgrade_reports_all_calendars_unreachable_when_every_request_fails(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [new Response(503, [], 'down'), new Response(503, [], 'down')],
            $transactions,
            calendarUrls: ['https://a.example', 'https://b.example'],
        );
        $receipt = $this->pendingReceipt($this->target(), ['https://a.example', 'https://b.example']);

        $result = $driver->upgrade($receipt);
        $attempt = $driver->lastUpgradeAttempt();

        $this->assertSame(ProofState::PENDING, $result->state);
        $this->assertSame($receipt->receiptBytes, $result->receiptBytes, 'receipt must be unchanged');
        $this->assertNotNull($attempt);
        $this->assertSame(2, $attempt->attempted);
        $this->assertSame(2, $attempt->unreachable);
        $this->assertTrue($attempt->allUnreachable());
        $this->assertCount(2, $attempt->warnings);
        foreach ($attempt->warnings as $warning) {
            $this->assertInstanceOf(Warning::class, $warning);
            $this->assertSame('calendar_unavailable', $warning->code);
        }
        $this->assertSame(
            [
                ['calendar' => 'https://a.example', 'error' => 'OpenTimestamps calendar returned HTTP 503'],
                ['calendar' => 'https://b.example', 'error' => 'OpenTimestamps calendar returned HTTP 503'],
            ],
            array_map(static fn (Warning $w) => $w->context, $attempt->warnings),
        );
    }

    public function test_upgrade_reports_unreachable_calendars_nested_inside_branches(): void
    {
        // A receipt produced by anchor() carries its pending attestations inside
        // append/sha256 branches, not at the root. Reachability accounting must
        // follow the same recursion upgradeTimestamp() does.
        $transactions = [];
        $driver = $this->driver(
            [
                new Response(200, [], $this->pendingTimestampBytesFor('https://a.example')),
                new Response(200, [], $this->pendingTimestampBytesFor('https://b.example')),
                new Response(503, [], 'down'),
                new Response(503, [], 'down'),
            ],
            $transactions,
            calendarUrls: ['https://a.example', 'https://b.example'],
        );
        $receipt = $driver->anchor($this->target());
        $this->assertSame(ProofState::PENDING, $receipt->state);
        $this->assertCount(2, $transactions);

        $result = $driver->upgrade($receipt);
        $attempt = $driver->lastUpgradeAttempt();

        $this->assertCount(4, $transactions, 'both nested pending attestations must be requested');
        $this->assertSame($receipt->receiptBytes, $result->receiptBytes);
        $this->assertNotNull($attempt);
        $this->assertSame(2, $attempt->attempted);
        $this->assertSame(2, $attempt->unreachable);
        $this->assertTrue($attempt->allUnreachable());
        $this->assertSame(
            ['calendar_unavailable', 'calendar_unavailable'],
            array_map(static fn (Warning $w) => $w->code, $attempt->warnings),
        );
        $this->assertSame(
            [
                ['calendar' => 'https://a.example', 'error' => 'OpenTimestamps calendar returned HTTP 503'],
                ['calendar' => 'https://b.example', 'error' => 'OpenTimestamps calendar returned HTTP 503'],
            ],
            array_map(static fn (Warning $w) => $w->context, $attempt->warnings),
        );
    }

    public function test_upgrade_reports_partial_reachability_when_one_calendar_answers_not_yet(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [
                new Response(503, [], 'down'),
                new Response(200, [], $this->pendingTimestampBytesFor('https://b.example')),
            ],
            $transactions,
            calendarUrls: ['https://a.example', 'https://b.example'],
        );
        $receipt = $this->pendingReceipt($this->target(), ['https://a.example', 'https://b.example']);

        $result = $driver->upgrade($receipt);
        $attempt = $driver->lastUpgradeAttempt();

        $this->assertSame(ProofState::PENDING, $result->state);
        $this->assertNotNull($attempt);
        $this->assertSame(2, $attempt->attempted);
        $this->assertSame(1, $attempt->unreachable);
        $this->assertFalse($attempt->allUnreachable());
        $this->assertCount(1, $attempt->warnings);
        $this->assertSame('calendar_unavailable', $attempt->warnings[0]->code);
        $this->assertSame(
            ['calendar' => 'https://a.example', 'error' => 'OpenTimestamps calendar returned HTTP 503'],
            $attempt->warnings[0]->context,
        );
    }

    public function test_successful_upgrade_reports_no_unreachable_calendars(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [new Response(200, [], $this->bitcoinTimestampBytes())],
            $transactions,
            calendarUrls: ['https://calendar.example'],
        );

        $upgraded = $driver->upgrade($this->pendingReceipt($this->target(), ['https://calendar.example']));
        $attempt = $driver->lastUpgradeAttempt();

        $this->assertSame(ProofState::UPGRADED, $upgraded->state);
        $this->assertNotNull($attempt);
        $this->assertSame(1, $attempt->attempted);
        $this->assertSame(0, $attempt->unreachable);
        $this->assertFalse($attempt->allUnreachable());
        $this->assertSame([], $attempt->warnings);
    }

    public function test_non_allowlisted_calendars_are_not_counted_as_attempted(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [],
            $transactions,
            calendarUrls: ['https://allowed.example'],
            upgradeAllowlist: ['https://allowed.example'],
        );

        $driver->upgrade($this->pendingReceipt($this->target(), ['https://other.example']));
        $attempt = $driver->lastUpgradeAttempt();

        $this->assertNotNull($attempt);
        $this->assertSame(0, $attempt->attempted);
        $this->assertSame(0, $attempt->unreachable);
        $this->assertFalse($attempt->allUnreachable(), 'nothing attempted is not the same as unreachable');
        $this->assertSame([], $attempt->warnings);
        $this->assertCount(0, $transactions);
    }

    public function test_last_upgrade_attempt_reflects_only_the_most_recent_upgrade(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [
                new Response(503, [], 'down'),
                new Response(200, [], $this->bitcoinTimestampBytes()),
            ],
            $transactions,
            calendarUrls: ['https://calendar.example'],
        );
        $receipt = $this->pendingReceipt($this->target(), ['https://calendar.example']);

        $driver->upgrade($receipt);
        $first = $driver->lastUpgradeAttempt();
        $driver->upgrade($receipt);
        $second = $driver->lastUpgradeAttempt();

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertTrue($first->allUnreachable());
        $this->assertSame(1, $second->attempted);
        $this->assertSame(0, $second->unreachable);
        $this->assertSame([], $second->warnings);
    }

    public function test_upgrade_of_already_upgraded_receipt_reports_nothing_attempted(): void
    {
        $transactions = [];
        $driver = $this->driver(
            [new Response(200, [], $this->bitcoinTimestampBytes())],
            $transactions,
            calendarUrls: ['https://calendar.example'],
        );
        $upgraded = $driver->upgrade($this->pendingReceipt($this->target(), ['https://calendar.example']));

        $driver->upgrade($upgraded);
        $attempt = $driver->lastUpgradeAttempt();

        $this->assertNotNull($attempt);
        $this->assertSame(0, $attempt->attempted);
        $this->assertFalse($attempt->allUnreachable());
    }

    /**
     * @param list<string> $pendingUris
     */
    private function pendingReceipt(AnchorTarget $target, array $pendingUris): AnchorReceipt
    {
        $rootBytes = hex2bin($target->rootHex);
        $this->assertIsString($rootBytes);
        $timestamp = new OpenTimestampsTimestamp($rootBytes);
        foreach ($pendingUris as $uri) {
            $timestamp = $timestamp->withAttestation(OpenTimestampsAttestation::pending($uri));
        }

        return new AnchorReceipt(
            driverName: OpenTimestampsDriver::NAME,
            target: $target,
            state: ProofState::PENDING,
            receiptBytes: OpenTimestampsCodec::encodeDetached(new OpenTimestampsProof($rootBytes, $timestamp)),
            createdAtIso8601: '2026-05-25T00:00:00.000Z',
        );
    }

    private function pendingTimestampBytesFor(string $uri): string
    {
        return OpenTimestampsCodec::encodeTimestampBytes(
            (new OpenTimestampsTimestamp(str_repeat("\x00", 32)))
                ->withAttestation(OpenTimestampsAttestation::pending($uri)),
        );
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

