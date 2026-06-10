<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Headers\BitcoinCoreRpcHeaderProvider;
use Fissible\Attest\Headers\EsploraHeaderProvider;
use Fissible\Attest\Headers\HeaderProviderSet;

/**
 * @internal
 */
final class HeaderProviderFactory
{
    public static function build(
        ?string $bitcoinCoreRpcUrl,
        ?string $bitcoinCoreCookieFile,
        ?string $esploraUrl,
    ): HeaderProviderSet {
        $providers = [];

        if ($bitcoinCoreRpcUrl !== null) {
            if (! class_exists(\GuzzleHttp\Client::class)) {
                throw new \RuntimeException(
                    '--bitcoin-core-rpc requires a PSR-18 HTTP client. Install guzzlehttp/guzzle or wire one manually.'
                );
            }
            $http = new \GuzzleHttp\Client();
            $factory = new \GuzzleHttp\Psr7\HttpFactory();
            $providers[] = new BitcoinCoreRpcHeaderProvider(
                http: $http,
                requests: $factory,
                streams: $factory,
                rpcUrl: $bitcoinCoreRpcUrl,
                cookieFile: $bitcoinCoreCookieFile,
            );
        }

        if ($esploraUrl !== null) {
            if (! class_exists(\GuzzleHttp\Client::class)) {
                throw new \RuntimeException('--esplora-url requires a PSR-18 HTTP client. Install guzzlehttp/guzzle or wire one manually.');
            }
            $http = new \GuzzleHttp\Client();
            $factory = new \GuzzleHttp\Psr7\HttpFactory();
            $providers[] = new EsploraHeaderProvider(
                http: $http,
                requests: $factory,
                baseUrl: $esploraUrl,
            );
        }

        return new HeaderProviderSet(...$providers);
    }
}
