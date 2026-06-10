<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Anchor\AnchorDriver;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestampsDriver;

/**
 * @internal
 */
final class AnchorDriverFactory
{
    /**
     * @return list<AnchorDriver>
     */
    public static function verificationDrivers(): array
    {
        $drivers = [new NullDriver()];

        if (class_exists(\GuzzleHttp\Client::class) && class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            $drivers[] = new OpenTimestampsDriver(OpenTimestampsCalendarClient::withGuzzle());
        }

        return $drivers;
    }
}
