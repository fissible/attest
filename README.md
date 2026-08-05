# fissible/attest

> Tamper-evident signed evidence chains for application events, with optional public anchoring via OpenTimestamps.

**Status:** Stable — v1.0+. The public API (types marked `@api`) follows semantic versioning; see [`STABILITY.md`](STABILITY.md). Anchoring ships `@experimental` in 1.x.

---

## What is this, in plain terms?

`fissible/attest` is a **tamper-evident logbook for the important things your software does.**

Most applications already log events — "invoice approved," "document published," "permission
granted." But ordinary logs and database rows can be quietly edited or deleted afterward, and
nobody can tell. If a row says a contract was approved at 3pm Tuesday, you're trusting that
*nobody changed it since.*

attest removes that "just trust us." Every event you record is:

- **Signed** — stamped with your application's cryptographic key, so a forged entry can be told
  apart from a real one.
- **Chained** — each entry is linked to the one before it by a fingerprint (hash). Change,
  insert, or delete any entry and the chain visibly breaks.
- **Optionally anchored in time** — a batch of entries can be "notarized" against the Bitcoin
  blockchain, so you can later prove the entries existed *before* a certain point in time, even
  to someone who has no reason to trust you.

The result is a history you can hand to an auditor, a court, a customer, or your future self and
*prove* it hasn't been tampered with.

## Why is that valuable?

Picture a dispute months from now:

> A customer insists they never approved a $50,000 contract. Your database has a row saying they
> did — but that row could have been inserted or edited at any time by anyone with database
> access, so on its own it proves nothing.

With attest, that approval was signed and chained the instant it happened. If anyone altered it,
back-dated it, or slipped in a fake one, verification fails and points at the broken entry. If
you also anchored it, you can show it existed *before* a specific Bitcoin block — so it couldn't
have been fabricated after the fact.

Typical uses: audit trails, compliance evidence, security investigations, financial and approval
workflows, and anywhere "prove this log wasn't edited" actually matters.

> **What this is not:** this is not artifact/build provenance (Sigstore, SLSA). Those prove where
> a binary came from. attest proves **what your application did, and when.**

**The boundary, up front:** signing happens inside your application, with a key your application
holds. So attest is tamper-evident against anyone who can reach the evidence store — a rogue DBA,
SQL injection, an edited backup — but *not* against an attacker who has taken over the
application itself and can therefore re-sign a rewritten history. Closing that gap takes external
key custody, public anchoring, or both. See [What this does not
prove](#what-this-does-not-prove) for the full table, and note that anchoring is experimental in
`1.x`.

## The 30-second example

Record something important when it happens:

```php
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;

// Your app's signing identity ("this entry really came from us").
$keys   = KeyPair::generate();   // save these; the public key is needed to verify later
$signer = new SodiumSigner($keys, keyId: 'app-prod-2026-01');

// Where the chain is stored, and which chain we're writing to.
$store = new FileChainStore(__DIR__ . '/storage/attest');
$chain = EvidenceChain::open($store, 'contracts', $signer);

// Record an event.
$chain->record('contract.approved', [
    'contract_id' => 'C-2026-014',
    'approved_by' => 'user:7',
    'amount'      => 50_000,
]);
```

Later — maybe months later — prove the whole history is intact and authentic:

```php
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\Verifier;

$verifier = new Verifier(
    store: $store,
    signatures: new SignatureVerifier([
        new TrustedKey($keys->publicKey, keyId: 'app-prod-2026-01'),
    ]),
);

$result = $verifier->verifyChain('contracts');

$result->isVerified();   // true only if every entry is signed by a trusted key
                         // and nothing was altered, inserted, or deleted.
```

If someone tampers with any stored entry, `isVerified()` returns `false` and
`$result->brokenAtSeq` tells you exactly which entry broke.

That's the whole idea. Everything below is detail you can read when you need it.

---

## Install

```
composer require fissible/attest
```

Requires PHP `^8.2` with the bundled `sodium` extension (used for Ed25519 signing).

`ext-zip` is **optional**, required only for portable bundles (`bundle:export`,
`bundle:verify`, and the `Bundle*` classes). Recording, verifying, and anchoring chains never
touch it. Without it, opening a bundle for read or write throws `BundleSupportUnavailable` and
the bundle CLI commands exit `1`.

Using Laravel? See [`fissible/attest-laravel`](https://github.com/fissible/attest-laravel) for
Eloquent storage, Artisan commands, queue-ready anchoring, and a JSONL importer.

## Storage adapter contract tests

Packages that provide their own storage backends should run the same contract tests as core.
The traits are shipped in `src/Testing` so adapters can depend on one canonical definition:

```php
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Testing\ChainStoreContractTests;
use PHPUnit\Framework\TestCase;

final class MyChainStoreTest extends TestCase
{
    use ChainStoreContractTests;

    protected function makeStore(): ChainStore
    {
        return new MyChainStore();
    }
}
```

Anchoring adapters can likewise use `Fissible\Attest\Testing\AnchorClaimStoreContractTests`.
Both shipped contract-test traits are stable `@api` test support.

## How it works (a layer deeper)

`fissible/attest` always starts with **local integrity**, and lets you optionally add a
**public time anchor** on top.

### Local integrity (always on)

Each event becomes an **envelope**: it is Ed25519-signed, stored in canonical JSON form, and
linked to the previous envelope by hash. That proves whether a local chain is internally
consistent and signed by the keys you expect — no network and no third party required.

### Public anchoring (optional)

Anchoring adds an external **time and publication** signal. Chain ranges are batched into RFC
6962-style Merkle roots, submitted to OpenTimestamps calendars, and later *upgraded* when a
Bitcoin block-header attestation is available.

Anchoring is **experimental** in the 1.x line: the subsystem is usable and tested, but its PHP
API may change in a minor release. It graduates to stable after live-network validation against
real OpenTimestamps calendars and Bitcoin confirmations. See [`STABILITY.md`](STABILITY.md).

### Verification levels

Verification can require anything from a local-only receipt up to a full Bitcoin-confirmed
attestation. The meaningful levels, weakest to strongest:

| Level (`AnchorOutcome`) | Meaning |
|---|---|
| `local_only` | Signed and chained; no external time proof. |
| `pending` | Submitted to a calendar; not yet confirmed. |
| `upgraded_no_headers` | Calendar attestation present; block headers not checked. |
| `remote_header_confirmed` | Confirmed via a remote explorer — the explorer is part of the trust path. |
| `bitcoin_verified` | Confirmed against a Bitcoin block header you trust (e.g. your own node). |

## What this does not prove

Local integrity defeats **database-only** tampering. It does not defeat **application
compromise**, and the difference is entirely about who holds the signing key.

Signing happens in your application process, with a key your application can reach — in
`fissible/attest-laravel`, an Ed25519 seed in app env (`ATTEST_SIGNING_KEY_SEED`). An attacker
who reaches that key can rewrite the whole chain and re-sign every envelope. Verification then
passes, because the chain really is internally consistent and really is signed by the key you
told the verifier to trust. Nothing visibly breaks.

| Attacker capability | Local integrity | + public anchoring |
|---|---|---|
| Edits or deletes stored rows (rogue DBA, SQLi, tampered backup) | detected | detected |
| Holds the signing key (app RCE, leaked env, malicious insider with deploy access) | **not detected** | back-dating detected |
| Operator colludes and rewrites the history from scratch | **not detected** | detected for anchored ranges |

The second and third rows are addressed only by anchoring, which is **experimental** in `1.x`
pending live-network validation. So the strongest claim the *stable* surface supports today is:

> Tamper-evident against anyone who can reach the evidence store but not the signing key.

That is a genuinely useful property — it covers the ordinary "someone edited the audit table"
dispute — but it is narrower than "nobody can forge this."

To extend the boundary:

- **Move key custody out of the application.** An HSM/KMS or a separate signing service with its
  own authorization means app-level RCE no longer yields the ability to re-sign history.
- **Anchor.** A public time anchor is what turns "the operator rewrote everything" from
  undetectable into detectable, because the rewritten chain cannot produce a Merkle root that
  was already published. Anchoring is experimental in `1.x`; treat a `1.x` anchoring deployment
  as validation, not as a settled interface.
- **Replicate.** Shipping bundles to a party who does not trust you, on a schedule, bounds how
  far back a rewrite can reach even without anchoring.

Also worth stating plainly: attest proves what your application *recorded*, not that the record
is true. A signed `contract.approved` envelope proves your application asserted that approval at
that point in the chain and that the assertion has not been altered since. Whether the approval
itself was legitimate is an application-level question.

## Full verifier example (anchored)

The complete shape, requiring a Bitcoin-confirmed anchor and a trusted Ed25519 key:

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
        new TrustedKey($rawEd25519PublicKey, keyId: 'app-prod-2026-01'),
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

Use `AnchorOutcome::REMOTE_HEADER_CONFIRMED` with `EsploraHeaderProvider` when a remote explorer
is acceptable. It is convenient, but weaker than a local Bitcoin Core node because the remote
service is part of the trust path.

OpenTimestamps calendars receive nonced commitments rather than raw chain roots. That protects
the committed content, but submission timing and IP metadata can still link activity.

## Handing evidence to someone else

A bundle is the rich answer — one file carrying a manifest, the chain segment, anchor proof
envelopes, OTS receipts, and claimed keys. It needs `ext-zip`.

You do not need a bundle to hand over verifiable evidence. A chain is already a flat file of
signed canonical envelopes, one per line, and verification only ever reads those bytes.

**Ship the store directory.** With `FileChainStore`, evidence is plain JSONL under the store
root. Copy the root (or just its `chains/` directory) and the recipient verifies it as-is:

```bash
rsync -a storage/attest/ /handoff/attest/

# On the recipient's machine — no bundle, no zip:
vendor/bin/attest verify \
    --storage-root /handoff/attest \
    --chain tenant:5 \
    --trusted-key prod-2026-01=<base64-public-key>
```

Same guarantees as any other verification: edit a byte and the chain breaks at the entry that
was touched, reported as `brokenAtSeq`.

One thing a hash chain cannot tell you on its own: **a truncated copy still verifies.** Drop the
last few entries and what remains is a shorter, internally consistent, correctly signed chain —
`isVerified()` is `true`. So completeness is established out of band, from the range the sender
stated: check `chainStats->envelopeCount` and the tail sequence against what you were told to
expect, or verify with an explicit `toSeq`. This is exactly what a bundle manifest carries for
you, and why one exists.

**Read the raw bytes yourself.** Stores implementing `RawChainStore` expose the stored canonical
bytes directly, which is the supported way to feed evidence into your own transport:

```php
use Fissible\Attest\Chain\FileChainStore;

$store = new FileChainStore(__DIR__ . '/storage/attest');

foreach ($store->readRawRange('tenant:5', fromSeq: 1, toSeq: 1000) as $raw) {
    // Exactly SignedEnvelope::signedCanonicalBytes(): no trailing newline,
    // no framing. Write it, post it, or stream it wherever you like.
    fwrite($out, $raw . "\n");
}
```

To verify without the CLI, hand any `ChainStore` to `StaticVerifier`:

```php
use Fissible\Attest\Verification\StaticVerifier;
use Fissible\Attest\Verification\TrustedKey;

$result = StaticVerifier::verifyChain(
    store: new FileChainStore('/handoff/attest'),
    chainId: 'tenant:5',
    trustedKeys: [new TrustedKey($publicKey, keyId: 'prod-2026-01')],
);
```

**What you give up versus a bundle**, and why bundles still exist:

| | Store directory / raw JSONL | Bundle |
|---|---|---|
| Chain integrity + signatures | yes | yes |
| Needs `ext-zip` | no | yes |
| States its own range, issuer, and note | no — out-of-band | manifest |
| Carries anchor proof envelopes and OTS receipts | no | yes |
| Carries claimed public keys | no | yes (informational only) |
| Single file | no | yes |

Anchored verification still works over a directory handoff, but you must convey the anchor proof
envelopes yourself and pass them to `Verifier` as `detachedAnchorEnvelopes` — a bundle is simply
the packaging that keeps them together.

One caveat if you are assembling a handoff by hand rather than copying a store: the filename
convention inside `chains/` is an implementation detail of `FileChainStore`, not a frozen format
(unlike the bundle layout, which *is* frozen as `fissible.attest.bundle/v1`). Copy the directory
rather than constructing filenames, and use bundles when you need to build a handoff from a
store that is not file-backed — for example the Eloquent store in
[`fissible/attest-laravel`](https://github.com/fissible/attest-laravel).

## Payload Types

Payloads passed to `record()` accept JSON-native scalars (string, int, bool, null), arrays,
objects, plus opaque binary blobs via `Fissible\Attest\Envelope\Binary`. Example:

```php
use Fissible\Attest\Envelope\Binary;

$chain->record('cms.attachment.added', [
    'name' => 'spec.pdf',
    'sha256' => 'abc...',
    'blob' => Binary::ofRaw(file_get_contents('/tmp/spec.pdf')),
]);
```

Binary blobs are stored in canonical form as `{"$binary": "<base64>"}` and round-trip stably.
The `$binary` key is reserved — a payload that uses it directly is rejected, so your data can
never be mistaken for the binary sentinel. Each blob is capped at 64KB raw; larger artifacts
must be stored externally and referenced by URL and sha256 hash.

The total signed canonical envelope size is capped at 64KB; payloads approaching that size will
be rejected at `record()` time.

## CLI

`bin/attest` is a Symfony Console application. Install globally or invoke via Composer:

```
vendor/bin/attest <command> [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `verify` | Verify a single chain segment (integrity + signatures + anchor coverage). |
| `bundle:export` | Export one or more chain segments into a portable `.attest.zip` bundle. |
| `bundle:verify` | Verify every chain segment inside an exported bundle. |
| `anchor` | Submit a chain range to an OpenTimestamps calendar and record the receipt. |
| `upgrade` | Upgrade pending OTS receipts that now have a Bitcoin block-header attestation. |

### Exit codes

| Code | Outcome | Notes |
|------|---------|-------|
| 0 | VERIFIED, or non-verification command success | `INTEGRITY_VERIFIED_UNTRUSTED` with `--allow-untrusted` also exits 0 |
| 1 | CLI / configuration / runtime error before a `VerificationOutcome` | Bad options, missing files, invalid arguments |
| 2 | `INTEGRITY_VERIFIED_UNTRUSTED` | `--allow-untrusted` downgrades to 0 |
| 3 | `ANCHOR_BELOW_MIN` | Anchor exists but is below `--min-anchor` threshold |
| 4 | `INVALID_CHAIN` / `INVALID_SIGNATURE` / `INVALID_ANCHOR` | Also: bundle export failure, calendar unavailable |
| 5 | `PROVIDER_DISAGREEMENT` | `--allow-provider-disagreement` downgrades to the strongest passing outcome |

### Examples

```bash
# Verify chain "tenant:5" sequences 1–1000 against a trusted Ed25519 key
vendor/bin/attest verify \
  --chain tenant:5 \
  --from 1 --to 1000 \
  --trusted-key /etc/attest/keys/app-prod-2026-01.pub \
  --min-anchor bitcoin_verified \
  --json

# Export two chains into a portable bundle
vendor/bin/attest bundle:export \
  --chain tenant:5 --from 1 --to 1000 \
  --chain tenant:7 --from 1 --to 500 \
  --out /tmp/export-$(date +%Y%m%d).attest.zip

# Verify all chains in a bundle
vendor/bin/attest bundle:verify \
  --bundle /tmp/export-20260605.attest.zip \
  --trusted-key /etc/attest/keys/app-prod-2026-01.pub \
  --min-anchor remote_header_confirmed \
  --json

# Submit chain range to OpenTimestamps
vendor/bin/attest anchor \
  --chain tenant:5 --from 1 --to 1000 \
  --calendar https://alice.btc.calendar.opentimestamps.org \
  --json

# Upgrade pending receipts to Bitcoin block-header attestations
vendor/bin/attest upgrade \
  --chain tenant:5 \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie /var/lib/bitcoin/.bitcoin/.cookie \
  --json
```

### JSON output schema

All commands emit a stable JSON envelope on stdout when `--json` is passed. The four schema
identifiers are pinned within the 1.x line; future additions will be additive (no removals
or renames within the same schema identifier):

- `attest.cli.result.v1` — emitted by `verify` and `bundle:verify`
- `attest.cli.export.v1` — emitted by `bundle:export`
- `attest.cli.anchor.v1` — emitted by `anchor`
- `attest.cli.upgrade.v1` — emitted by `upgrade`

### Bundles

Bundles are the one feature that needs `ext-zip`; see [Install](#install).

Bundles are ZIP containers (extension `.attest.zip`) with the following layout:

```
manifest.json
chains/{hash}.jsonl
proof_envelopes/{hash}.jsonl
receipts/{anchor_id}.ots        (optional)
keys/{fingerprint}.pub          (optional)
```

Members are stored uncompressed for byte-accounting symmetry; the reader enforces per-member
size caps, a total size cap, and a compression-ratio guard against bundles produced by other
writers.

**Trust model:** keys claimed inside the bundle are NOT trusted by themselves. Operators must
supply trusted public keys via `--trusted-key <path>` or `--trusted-key-file <path>` at
verification time.

## Stability & Versioning

From v1.0.0, `fissible/attest` follows semantic versioning. The supported public API is the set
of types marked `@api`; anything marked `@internal` (or unmarked) is implementation detail and
may change in any release. The on-disk and interchange **formats** — canonical envelope JSON, the
`{"$binary": …}` sentinel, the `fissible.attest.bundle/v1` bundle, and the `attest.cli.*.v1` JSON
schemas — are frozen within 1.x (additions are additive; removals or renames require a
format-version bump). The **CLI contract** (commands, options, exit codes, `--json` schemas) is
stable even though the PHP classes under `src/Cli/` are internal.

**Anchoring is experimental in 1.x.** The OpenTimestamps/Bitcoin anchoring subsystem
(`src/Anchor`, `src/Headers`, `src/Merkle`) is usable and tested, but its PHP API may change in a
minor release; it graduates to stable after live-network validation.

See [`STABILITY.md`](STABILITY.md) for the full surface list and policy.

## Documentation

The supported surface is the set of `@api`-annotated types in `src/` — see [`STABILITY.md`](STABILITY.md) for the full list and the wire/format stability guarantees.

## License

MIT
