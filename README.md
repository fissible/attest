# fissible/attest

> Tamper-evident signed evidence chains for application events, with optional public anchoring via OpenTimestamps.

**Status:** Alpha — under active development. API will stabilize at v1.0.

**Disambiguation:** This is not artifact-provenance (Sigstore/SLSA). It proves *what your application did and when*.

## Install

```
composer require fissible/attest
```

## Integrity And Anchoring

`fissible/attest` always starts with local integrity: each envelope is Ed25519-signed, stored in canonical JSON form, and linked to the previous envelope by hash. That proves whether a local chain is internally consistent and signed by expected keys.

Public anchoring adds an external time and publication signal. Chain ranges are batched into RFC 6962-style Merkle roots, submitted to OpenTimestamps calendars, and later upgraded when a Bitcoin block-header attestation is available. Verification can then require anything from a local-only receipt through `bitcoin_verified`.

Anchoring is alpha-quality in this release line. Treat the APIs as useful for integration testing and design feedback, not yet as a long-term stable surface.

## Verifier Example

```php
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Headers\BitcoinCoreRpcHeaderProvider;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;

$store = new FileChainStore(__DIR__ . '/storage/attest');
$http = new Client();
$factory = new HttpFactory();

$verifier = new Verifier(
    store: $store,
    signatures: new SignatureVerifier([
        new TrustedKey($rawEd25519PublicKey, keyId: 'station-prod-2026-01'),
    ]),
    policy: new VerificationPolicy(
        minAnchorOutcome: AnchorOutcome::BITCOIN_VERIFIED,
    ),
    anchorDrivers: [
        new OpenTimestampsDriver(OpenTimestampsCalendarClient::withGuzzle()),
    ],
    headers: new HeaderProviderSet(
        new BitcoinCoreRpcHeaderProvider(
            http: $http,
            requests: $factory,
            streams: $factory,
            rpcUrl: 'http://127.0.0.1:8332',
            cookieFile: '/var/lib/bitcoin/.bitcoin/.cookie',
        ),
    ),
);

$result = $verifier->verifyChain('tenant:5', fromSeq: 1, toSeq: 1000);
```

Use `AnchorOutcome::REMOTE_HEADER_CONFIRMED` with `EsploraHeaderProvider` when a remote explorer is acceptable. It is convenient, but weaker than a local Bitcoin Core node because the remote service is part of the trust path.

OpenTimestamps calendars receive nonced commitments rather than raw chain roots. That protects the committed content, but submission timing and IP metadata can still link activity.

## Documentation

Full API reference: coming with v1.0.

## License

MIT
