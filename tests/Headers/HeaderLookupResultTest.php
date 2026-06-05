<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Headers;

use Fissible\Attest\Headers\ActiveChainHeader;
use Fissible\Attest\Headers\BlockHeaderProvider;
use Fissible\Attest\Headers\HeaderLookupResult;
use Fissible\Attest\Headers\HeaderLookupStatus;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Headers\TrustLevel;
use PHPUnit\Framework\TestCase;

final class HeaderLookupResultTest extends TestCase
{
    public function test_active_header_requires_confirmations_and_lowercase_hex(): void
    {
        $header = new ActiveChainHeader(
            blockHash: str_repeat('a', 64),
            height: 840000,
            confirmations: 6,
            merkleRoot: str_repeat('b', 64),
            timeUnixSec: 1713571200,
        );
        $result = HeaderLookupResult::active('core', TrustLevel::LOCAL, $header);

        $this->assertTrue($result->isActive());
        $this->assertSame(HeaderLookupStatus::ACTIVE, $result->status);
        $this->assertSame($header, $result->header);
    }

    public function test_active_header_rejects_zero_confirmations(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('confirmations');

        new ActiveChainHeader(
            blockHash: str_repeat('a', 64),
            height: 840000,
            confirmations: 0,
            merkleRoot: str_repeat('b', 64),
            timeUnixSec: 1713571200,
        );
    }

    public function test_provider_error_redacts_credentials(): void
    {
        $result = HeaderLookupResult::providerError(
            'core',
            TrustLevel::LOCAL,
            'Failed http://user:secret@127.0.0.1:8332 with Authorization: Bearer abc123',
        );

        $this->assertSame(HeaderLookupStatus::PROVIDER_ERROR, $result->status);
        $this->assertSame(
            'Failed http://***:***@127.0.0.1:8332 with Authorization: Bearer ***',
            $result->diagnostic,
        );
    }

    public function test_provider_set_preserves_names_and_trust_levels(): void
    {
        $core = new FakeHeaderProvider('core', TrustLevel::LOCAL);
        $esplora = new FakeHeaderProvider('esplora', TrustLevel::REMOTE);
        $set = new HeaderProviderSet($core, $esplora);

        $this->assertCount(2, $set);
        $this->assertSame(['core', 'esplora'], $set->names());
        $this->assertSame([
            'core' => TrustLevel::LOCAL,
            'esplora' => TrustLevel::REMOTE,
        ], $set->trustLevelsByName());
        $this->assertSame([$core, $esplora], iterator_to_array($set, false));
    }

    public function test_provider_set_rejects_duplicate_names(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('duplicate');

        new HeaderProviderSet(
            new FakeHeaderProvider('core', TrustLevel::LOCAL),
            new FakeHeaderProvider('core', TrustLevel::REMOTE),
        );
    }
}

final readonly class FakeHeaderProvider implements BlockHeaderProvider
{
    public function __construct(
        private string $name,
        private TrustLevel $trustLevel,
    ) {
    }

    public function name(): string
    {
        return $this->name;
    }

    public function trustLevel(): TrustLevel
    {
        return $this->trustLevel;
    }

    public function getActiveChainHeaderByHeight(int $height): HeaderLookupResult
    {
        return HeaderLookupResult::notFoundOrBehind($this->name, $this->trustLevel, 'not implemented');
    }
}

