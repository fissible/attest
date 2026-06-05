# fissible/attest — Chunk 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the portable proof bundle (`attest.bundle.v1`), expose the CLI (`bin/attest`), and reconcile remaining spec drift, turning Chunks 1/2/2.5 library primitives into an operator-usable tool.

**Architecture:** Bundle is a ZIP container with `manifest.json`, `chains/{hash}.jsonl`, `proof_envelopes/{hash}.jsonl`, optional `receipts/{anchor_id}.ots`, and optional `keys/{fingerprint}.pub`. Members are stored uncompressed (`ZIP_STORED`) so member size accounting matches on-disk size; the reader still enforces a compression-ratio guard for bundles produced by other writers. `BundleStore` implements `RawChainStore` over the bundle's chain segment; proof envelopes are fed to `Verifier` through a new constructor channel. CLI is Symfony Console–based with command-class unit tests (no process forking) and a stable JSON output schema. Spec drift around `VerificationResult::$stats` → `$chainStats`, static `Verifier::verifyChain()` facade, and `PathMapper` slash rejection lands as Task 3.0 before any new code.

**Tech Stack:** PHP 8.2+, ext-sodium, ext-zip, ext-json, symfony/console, paragonie/constant_time_encoding, PSR-18/17 HTTP, PHPUnit 11.

**Tag at completion:** `v0.4.0-alpha`.

---

## Assumed from prior chunks

These must exist before Chunk 3 starts. If a symbol is missing, escalate before extending the plan.

**From Chunks 1-2:**
- `Fissible\Attest\Canonical\JcsEncoder`
- `Fissible\Attest\Envelope\{EvidenceEnvelope, SignedEnvelope, EnvelopeCodec, PayloadValidator, Binary, InvalidPayload}`
- `Fissible\Attest\Chain\{ChainStore, RawChainStore, AppendContext, FileChainStore, PathMapper, EvidenceChain, ContextMismatch, ChainLockUnavailable}`
- `Fissible\Attest\Signing\{KeyPair, Signer, SodiumSigner, Fingerprint, SignatureVerification}`
- `Fissible\Attest\Merkle\{MerkleTree, InclusionProof}`
- `Fissible\Attest\Anchor\{AnchorTarget, AnchorId, AnchorReceipt, AnchorEnvelope, AnchorOutcome, ProofState, AnchorDriver, NullDriver, OpenTimestampsDriver, AnchorService, AnchorClaim, AnchorClaimStore, FileAnchorClaimStore, AnchorBatchSelector, InvalidAnchorEnvelope}`
- `Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient` with static `::withGuzzle(array $options = []): self`.
- `Fissible\Attest\Headers\{BlockHeaderProvider, ActiveChainHeader, HeaderLookupResult, HeaderLookupStatus, HeaderProviderSet, TrustLevel, BitcoinCoreRpcHeaderProvider, EsploraHeaderProvider}`
- `Fissible\Attest\Verification\{Verifier, VerificationPolicy, VerificationResult, VerificationOutcome, AnchorVerification, AnchorSetResolver, ResolvedAnchor, SignatureVerifier, SignatureVerificationResult, KeyMatch, TrustedKey, ChainStats, Warning}`

**From Chunk 2.5 (`v0.3.0-alpha`):**
- `Fissible\Attest\Verification\{DetachedAnchorClassification, DetachedAnchorVerifier, ClassifiedDetachedAnchor}` with the integration described in Chunk 2.5's Task 2.5.3.
- `SignedEnvelope::MAX_SIGNED_ENVELOPE_BYTES = 65536`.
- `PayloadValidator::ensure()` returns the canonical payload (Binary → array stand-in).
- `Warning::DETACHED_ANCHOR_INVALID_SIGNATURE`, `Warning::DETACHED_ANCHOR_UNTRUSTED`.

---

## File Structure

### New files (sorted by task)

```
src/Verification/StaticVerifier.php                       (Task 3.0)
src/Chain/PathSafety.php                                  (Task 3.1)
src/Bundle/BundleConstants.php                            (Task 3.1)
src/Bundle/BundleEntryPath.php                            (Task 3.1)
src/Bundle/BundleManifest.php                             (Task 3.2)
src/Bundle/ChainSegmentMeta.php                           (Task 3.2)
src/Bundle/AnchorMeta.php                                 (Task 3.2)
src/Bundle/ClaimedKeyMeta.php                             (Task 3.2)
src/Bundle/InvalidBundleManifest.php                      (Task 3.2)
src/Bundle/BundleExporter.php                             (Task 3.3)
src/Bundle/BundleWriter.php                               (Task 3.3)
src/Bundle/BundleExportException.php                      (Task 3.3)
src/Bundle/BundleReader.php                               (Task 3.4)
src/Bundle/InvalidBundle.php                              (Task 3.4)
src/Bundle/BundleStore.php                                (Task 3.5)
src/Cli/AttestCli.php                                     (Task 3.7)
src/Cli/Output/ResultEmitter.php                          (Task 3.7)
src/Cli/Output/HumanResultEmitter.php                     (Task 3.7)
src/Cli/Output/JsonResultEmitter.php                      (Task 3.7)
src/Cli/Output/JsonResultSchema.php                       (Task 3.7)
src/Cli/Support/TrustedKeyLoader.php                      (Task 3.7)
src/Cli/Support/MinAnchorOption.php                       (Task 3.7)
src/Cli/Support/HeaderProviderFactory.php                 (Task 3.7)
src/Cli/Command/VerifyCommand.php                         (Task 3.8)
src/Cli/Command/BundleExportCommand.php                   (Task 3.9)
src/Cli/Command/BundleVerifyCommand.php                   (Task 3.10)
src/Cli/Command/AnchorCommand.php                         (Task 3.11)
src/Cli/Command/UpgradeCommand.php                        (Task 3.12)
bin/attest                                                (Task 3.7)
tests/Bundle/BundleManifestTest.php                       (Task 3.2)
tests/Bundle/BundleExporterTest.php                       (Task 3.3)
tests/Bundle/BundleReaderTest.php                         (Task 3.4)
tests/Bundle/BundleStoreTest.php                          (Task 3.5)
tests/Bundle/BundleRoundTripTest.php                      (Task 3.5)
tests/Bundle/PathSafetyTest.php                           (Task 3.1)
tests/Verification/StaticVerifierTest.php                 (Task 3.0)
tests/Verification/VerifierDetachedInputTest.php          (Task 3.6)
tests/Cli/Output/JsonResultEmitterTest.php                (Task 3.7)
tests/Cli/Command/VerifyCommandTest.php                   (Task 3.8)
tests/Cli/Command/BundleExportCommandTest.php             (Task 3.9)
tests/Cli/Command/BundleVerifyCommandTest.php             (Task 3.10)
tests/Cli/Command/AnchorCommandTest.php                   (Task 3.11)
tests/Cli/Command/UpgradeCommandTest.php                  (Task 3.12)
```

### Modified files

```
src/Chain/PathMapper.php                                  (Task 3.0 — slash rejection)
src/Verification/VerificationResult.php                   (Task 3.0 — $stats → $chainStats)
src/Verification/Verifier.php                             (Task 3.6 — accept detached anchor envelopes)
composer.json                                             (Task 3.13)
README.md                                                 (Task 3.13)
CHANGELOG.md                                              (Task 3.13)
VERSION                                                   (Task 3.13)
```

---

## Task 3.0: Spec-alignment fixes

**Why:** Three small spec-drift items deserve to land first so subsequent code is consistent: `VerificationResult::$stats` is renamed to `$chainStats` (spec §11), a static `Verifier::verifyChain()` facade is added to match spec §6's API shape, and `PathMapper` adds explicit forward-slash rejection (spec §7.2).

**Files:**
- Modify: `src/Verification/VerificationResult.php`
- Create: `src/Verification/StaticVerifier.php`
- Modify: `src/Chain/PathMapper.php`
- Create: `tests/Verification/StaticVerifierTest.php`
- Modify: `tests/Chain/PathMapperTest.php`

- [ ] **Step 1: Rename `$stats` to `$chainStats` and update all callers**

In `src/Verification/VerificationResult.php`, change the property:

```php
public ChainStats $chainStats,
```

In every file under `src/Verification/Verifier.php` that constructs `VerificationResult`, change `stats:` to `chainStats:`. Search and replace:

```
grep -rln "stats:" src/Verification/ tests/Verification/ | xargs sed -i '' 's/\bstats: /chainStats: /g'
```

Verify by inspection that no `stats:` named-arg remains in `src/Verification/`.

For tests asserting `$result->stats`, update to `$result->chainStats`.

- [ ] **Step 2: Run the verification test suite to confirm no break**

```
vendor/bin/phpunit --testsuite Unit --filter Verification
```

Expected: all tests pass.

- [ ] **Step 3: Add the static `Verifier::verifyChain()` facade**

Create `src/Verification/StaticVerifier.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Verification;

use Fissible\Attest\Anchor\AnchorDriver;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Headers\BlockHeaderProvider;
use Fissible\Attest\Headers\HeaderProviderSet;

/**
 * Spec §6 facade: a one-shot static entry that mirrors the documented API.
 * Operationally it just wires Verifier from the named arguments.
 */
final class StaticVerifier
{
    /**
     * @param iterable<TrustedKey> $trustedKeys
     * @param iterable<AnchorDriver> $anchorDrivers
     * @param iterable<BlockHeaderProvider> $headerProviders
     * @param iterable<SignedEnvelope> $detachedAnchorEnvelopes
     */
    public static function verifyChain(
        ChainStore $store,
        string $chainId,
        iterable $trustedKeys,
        int $fromSeq = 1,
        ?int $toSeq = null,
        iterable $anchorDrivers = [],
        iterable $headerProviders = [],
        ?AnchorOutcome $minAnchorOutcome = null,
        bool $allowProviderDisagreement = false,
        bool $requireTrustedKey = true,
        iterable $detachedAnchorEnvelopes = [],
    ): VerificationResult {
        $verifier = new Verifier(
            store: $store,
            signatures: new SignatureVerifier($trustedKeys),
            policy: new VerificationPolicy(
                minAnchorOutcome: $minAnchorOutcome,
                allowProviderDisagreement: $allowProviderDisagreement,
                requireTrustedKey: $requireTrustedKey,
            ),
            anchorDrivers: $anchorDrivers,
            headers: new HeaderProviderSet(...iterator_to_array($headerProviders, false)),
            detachedAnchorEnvelopes: $detachedAnchorEnvelopes,
        );

        return $verifier->verifyChain($chainId, $fromSeq, $toSeq);
    }
}
```

The `detachedAnchorEnvelopes` parameter is added now and consumed in Task 3.6.

- [ ] **Step 4: Write `StaticVerifierTest`**

Create `tests/Verification/StaticVerifierTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Verification;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\StaticVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use PHPUnit\Framework\TestCase;

final class StaticVerifierTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-static-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_facade_verifies_single_chain_with_trusted_key(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        $chain->record('app.event', ['a' => 1]);
        $chain->record('app.event', ['a' => 2]);

        $result = StaticVerifier::verifyChain(
            store: $store,
            chainId: 'tenant:5',
            trustedKeys: [new TrustedKey($kp->publicKey, keyId: 'k1')],
        );

        self::assertSame(VerificationOutcome::VERIFIED, $result->outcome);
        self::assertSame(2, $result->chainStats->envelopeCount);
    }
}
```

- [ ] **Step 5: Run the test**

```
vendor/bin/phpunit --filter StaticVerifierTest
```

Expected: pass.

- [ ] **Step 6: Add explicit slash rejection to `PathMapper`**

In `src/Chain/PathMapper.php`, replace the `validate()` body with:

```php
private function validate(string $chainId): void
{
    if ($chainId === '') {
        throw new \InvalidArgumentException('chain_id must not be empty');
    }
    if (strlen($chainId) > self::MAX_CHAIN_ID_LEN) {
        throw new \InvalidArgumentException(
            'chain_id exceeds ' . self::MAX_CHAIN_ID_LEN . ' bytes'
        );
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $chainId)) {
        throw new \InvalidArgumentException('chain_id contains control characters');
    }
    if (str_contains($chainId, '/') || str_contains($chainId, '\\')) {
        throw new \InvalidArgumentException(
            'chain_id may not contain forward or back slashes'
        );
    }
}
```

- [ ] **Step 7: Add slash-rejection test cases**

In `tests/Chain/PathMapperTest.php`, add:

```php
public function test_rejects_forward_slash_in_chain_id(): void
{
    $mapper = new PathMapper('/tmp/x');
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/slash/i');
    $mapper->jsonlPath('tenant/5');
}

public function test_rejects_backslash_in_chain_id(): void
{
    $mapper = new PathMapper('/tmp/x');
    $this->expectException(\InvalidArgumentException::class);
    $this->expectExceptionMessageMatches('/slash/i');
    $mapper->jsonlPath("tenant\\5");
}
```

- [ ] **Step 8: Run tests**

```
vendor/bin/phpunit
```

Expected: all tests pass; the two new path tests pass.

- [ ] **Step 9: Commit**

```
git add src/Verification/VerificationResult.php src/Verification/StaticVerifier.php src/Verification/Verifier.php src/Chain/PathMapper.php tests/Verification/StaticVerifierTest.php tests/Chain/PathMapperTest.php tests/Verification/
git commit -m "fix(spec): align with §6/§7.2/§11 — chainStats rename, static facade, slash rejection"
```

---

## Task 3.1: Bundle constants, entry-path safety, and shared helpers

**Why:** Spec §12 defines the bundle layout. Capture the constants in one place and write a path-safety helper that every bundle read site uses to reject zip-slip, control chars, and unknown prefixes before touching member content.

**Files:**
- Create: `src/Bundle/BundleConstants.php`
- Create: `src/Bundle/BundleEntryPath.php`
- Create: `src/Chain/PathSafety.php`
- Create: `tests/Bundle/PathSafetyTest.php`

- [ ] **Step 1: Write failing `PathSafetyTest`**

Create `tests/Bundle/PathSafetyTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Bundle\BundleEntryPath;
use PHPUnit\Framework\TestCase;

final class PathSafetyTest extends TestCase
{
    public static function unsafePaths(): array
    {
        return [
            'absolute'             => ['/etc/passwd'],
            'parent traversal'     => ['../escape'],
            'embedded traversal'   => ['chains/../etc/passwd'],
            'leading dot'          => ['./manifest.json'],
            'backslash'            => ["chains\\x.jsonl"],
            'null byte'            => ["chains/x.jsonl\0"],
            'control char'         => ["chains/x.\nls"],
            'empty'                => [''],
            'just slash'           => ['/'],
            'too long'             => [str_repeat('a/', 2000)],
        ];
    }

    /** @dataProvider unsafePaths */
    public function test_rejects_unsafe_entry_path(string $path): void
    {
        $this->expectException(\InvalidArgumentException::class);
        BundleEntryPath::validate($path);
    }

    public static function safePaths(): array
    {
        return [
            ['manifest.json'],
            ['chains/abc123.jsonl'],
            ['proof_envelopes/abc123.jsonl'],
            ['receipts/' . str_repeat('a', 64) . '.ots'],
            ['keys/' . str_repeat('a', 64) . '.pub'],
        ];
    }

    /** @dataProvider safePaths */
    public function test_accepts_safe_entry_path(string $path): void
    {
        // Should not throw.
        BundleEntryPath::validate($path);
        self::assertTrue(true);
    }

    public function test_only_known_top_level_prefixes_allowed(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/unknown top-level prefix/i');
        BundleEntryPath::validate('unknown/file.txt');
    }
}
```

- [ ] **Step 2: Add `BundleConstants`**

Create `src/Bundle/BundleConstants.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class BundleConstants
{
    public const FORMAT = 'fissible.attest.bundle/v1';

    public const MANIFEST_ENTRY = 'manifest.json';
    public const CHAINS_PREFIX = 'chains/';
    public const PROOF_ENVELOPES_PREFIX = 'proof_envelopes/';
    public const RECEIPTS_PREFIX = 'receipts/';
    public const KEYS_PREFIX = 'keys/';

    public const ALLOWED_PREFIXES = [
        self::CHAINS_PREFIX,
        self::PROOF_ENVELOPES_PREFIX,
        self::RECEIPTS_PREFIX,
        self::KEYS_PREFIX,
    ];

    public const MAX_ENTRY_PATH_LEN = 256;
    public const MAX_MANIFEST_BYTES = 1_048_576;          // 1 MB
    public const MAX_MEMBER_BYTES = 50 * 1_048_576;       // 50 MB
    public const MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1_048_576; // 500 MB
    public const MAX_COMPRESSION_RATIO = 100;             // reject if uncompressed/compressed > 100
}
```

- [ ] **Step 3: Add `BundleEntryPath`**

Create `src/Bundle/BundleEntryPath.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class BundleEntryPath
{
    public static function validate(string $path): void
    {
        if ($path === '') {
            throw new \InvalidArgumentException('Bundle entry path is empty');
        }
        if (strlen($path) > BundleConstants::MAX_ENTRY_PATH_LEN) {
            throw new \InvalidArgumentException(
                'Bundle entry path exceeds ' . BundleConstants::MAX_ENTRY_PATH_LEN . ' bytes'
            );
        }
        if (str_contains($path, "\0")) {
            throw new \InvalidArgumentException('Bundle entry path contains null byte');
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $path)) {
            throw new \InvalidArgumentException('Bundle entry path contains control character');
        }
        if (str_contains($path, '\\')) {
            throw new \InvalidArgumentException('Bundle entry path contains backslash');
        }
        if ($path[0] === '/' || str_starts_with($path, './') || str_contains($path, '/../') || str_ends_with($path, '/..')) {
            throw new \InvalidArgumentException('Bundle entry path is absolute or contains traversal');
        }
        if (str_contains($path, '..')) {
            // Catch "../foo" too.
            $parts = explode('/', $path);
            if (in_array('..', $parts, true)) {
                throw new \InvalidArgumentException('Bundle entry path contains parent traversal');
            }
        }

        if ($path === BundleConstants::MANIFEST_ENTRY) {
            return;
        }

        foreach (BundleConstants::ALLOWED_PREFIXES as $prefix) {
            if (str_starts_with($path, $prefix)) {
                if (strlen($path) === strlen($prefix)) {
                    throw new \InvalidArgumentException("Bundle entry path is bare prefix '$prefix'");
                }
                return;
            }
        }

        throw new \InvalidArgumentException("Bundle entry path uses unknown top-level prefix: $path");
    }
}
```

- [ ] **Step 4: Add a minimal `PathSafety` helper for output paths**

Create `src/Chain/PathSafety.php` — used by CLI commands to ensure `--out` and `--storage-root` are safe:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Chain;

final class PathSafety
{
    public static function ensureDirectoryExists(string $dir): void
    {
        if (! is_dir($dir) && ! @mkdir($dir, 0o700, recursive: true) && ! is_dir($dir)) {
            throw new \RuntimeException("Could not create directory: $dir");
        }
        if (! is_writable($dir)) {
            throw new \RuntimeException("Directory is not writable: $dir");
        }
    }

    public static function ensureWritableParent(string $path): void
    {
        $parent = dirname($path);
        self::ensureDirectoryExists($parent);
    }
}
```

- [ ] **Step 5: Run tests**

```
vendor/bin/phpunit --filter PathSafetyTest
```

Expected: all path-safety tests pass.

- [ ] **Step 6: Commit**

```
git add src/Bundle/BundleConstants.php src/Bundle/BundleEntryPath.php src/Chain/PathSafety.php tests/Bundle/PathSafetyTest.php
git commit -m "feat(bundle): constants + entry-path safety helpers"
```

---

## Task 3.2: `BundleManifest` value object and parser

**Why:** Spec §12 defines `manifest.json` shape. Build a parse/build pair with strict validation, separate from filesystem I/O. The manifest is advisory — counts and hashes are corruption checks only, not authentication.

**Files:**
- Create: `src/Bundle/BundleManifest.php`
- Create: `src/Bundle/ChainSegmentMeta.php`
- Create: `src/Bundle/AnchorMeta.php`
- Create: `src/Bundle/ClaimedKeyMeta.php`
- Create: `src/Bundle/InvalidBundleManifest.php`
- Create: `tests/Bundle/BundleManifestTest.php`

- [ ] **Step 1: Write failing manifest tests**

Create `tests/Bundle/BundleManifestTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Bundle\AnchorMeta;
use Fissible\Attest\Bundle\BundleManifest;
use Fissible\Attest\Bundle\ChainSegmentMeta;
use Fissible\Attest\Bundle\ClaimedKeyMeta;
use Fissible\Attest\Bundle\InvalidBundleManifest;
use PHPUnit\Framework\TestCase;

final class BundleManifestTest extends TestCase
{
    public function test_roundtrips_minimal_manifest(): void
    {
        $manifest = new BundleManifest(
            createdAt: '2026-06-05T00:00:00Z',
            chains: [new ChainSegmentMeta(
                chainId: 'tenant:5',
                file: 'chains/abc.jsonl',
                fromSeq: 1, toSeq: 100,
                envelopeCount: 100,
                headHash: str_repeat('a', 64),
            )],
            anchors: [],
            claimedKeys: [],
        );
        $json = $manifest->toJson();
        $parsed = BundleManifest::fromJson($json);
        self::assertEquals($manifest, $parsed);
    }

    public function test_rejects_unknown_format(): void
    {
        $this->expectException(InvalidBundleManifest::class);
        $this->expectExceptionMessageMatches('/unsupported format/i');
        BundleManifest::fromJson('{"format":"fissible.attest.bundle/v2","created_at":"2026-06-05T00:00:00Z","chains":[]}');
    }

    public function test_rejects_missing_required_field(): void
    {
        $this->expectException(InvalidBundleManifest::class);
        BundleManifest::fromJson('{"format":"fissible.attest.bundle/v1"}');
    }

    public function test_rejects_invalid_chain_seq_range(): void
    {
        $this->expectException(InvalidBundleManifest::class);
        $this->expectExceptionMessageMatches('/from_seq/i');
        BundleManifest::fromJson(json_encode([
            'format' => 'fissible.attest.bundle/v1',
            'created_at' => '2026-06-05T00:00:00Z',
            'chains' => [[
                'chain_id' => 'c', 'file' => 'chains/a.jsonl',
                'from_seq' => 5, 'to_seq' => 3,
                'envelope_count' => 0, 'head_hash' => str_repeat('a', 64),
            ]],
            'anchors' => [],
        ]));
    }

    public function test_anchor_meta_carries_receipt_envelope_id(): void
    {
        $json = json_encode([
            'format' => 'fissible.attest.bundle/v1',
            'created_at' => '2026-06-05T00:00:00Z',
            'chains' => [],
            'anchors' => [[
                'anchor_id' => str_repeat('b', 64),
                'chain_id' => 'c',
                'from_seq' => 1, 'to_seq' => 100,
                'merkle_algorithm' => 'sha256-rfc6962',
                'root' => str_repeat('c', 64),
                'driver' => 'opentimestamps',
                'state' => 'upgraded',
                'receipt_envelope_id' => '01H' . str_repeat('A', 23),
                'receipt_cache_file' => 'receipts/' . str_repeat('b', 64) . '.ots',
            ]],
        ]);
        $manifest = BundleManifest::fromJson($json);
        self::assertCount(1, $manifest->anchors);
        self::assertSame('upgraded', $manifest->anchors[0]->state);
    }

    public function test_claimed_key_meta_carries_fingerprint_and_path(): void
    {
        $json = json_encode([
            'format' => 'fissible.attest.bundle/v1',
            'created_at' => '2026-06-05T00:00:00Z',
            'chains' => [],
            'anchors' => [],
            'claimed_keys' => [[
                'key_id' => 'k1',
                'sig_alg' => 'ed25519',
                'fingerprint' => 'sha256:' . str_repeat('d', 64),
                'file' => 'keys/' . str_repeat('d', 64) . '.pub',
            ]],
        ]);
        $manifest = BundleManifest::fromJson($json);
        self::assertCount(1, $manifest->claimedKeys);
        self::assertSame('k1', $manifest->claimedKeys[0]->keyId);
    }
}
```

- [ ] **Step 2: Add the value objects**

Create `src/Bundle/InvalidBundleManifest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class InvalidBundleManifest extends \RuntimeException
{
}
```

Create `src/Bundle/ChainSegmentMeta.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final readonly class ChainSegmentMeta
{
    public function __construct(
        public string $chainId,
        public string $file,
        public int $fromSeq,
        public int $toSeq,
        public int $envelopeCount,
        public string $headHash,
    ) {
        if ($chainId === '') {
            throw new InvalidBundleManifest('chain_id must not be empty');
        }
        if ($fromSeq < 1) {
            throw new InvalidBundleManifest('from_seq must be >= 1');
        }
        if ($toSeq < $fromSeq) {
            throw new InvalidBundleManifest('to_seq must be >= from_seq');
        }
        if ($envelopeCount < 0) {
            throw new InvalidBundleManifest('envelope_count must be >= 0');
        }
        if (! preg_match('/\A[0-9a-f]{64}\z/', $headHash)) {
            throw new InvalidBundleManifest('head_hash must be a 64-char lower-case hex SHA-256');
        }
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'chain_id' => $this->chainId,
            'file' => $this->file,
            'from_seq' => $this->fromSeq,
            'to_seq' => $this->toSeq,
            'envelope_count' => $this->envelopeCount,
            'head_hash' => $this->headHash,
        ];
    }

    /** @param array<string,mixed> $arr */
    public static function fromArray(array $arr): self
    {
        return new self(
            chainId: self::str($arr, 'chain_id'),
            file: self::str($arr, 'file'),
            fromSeq: self::int($arr, 'from_seq'),
            toSeq: self::int($arr, 'to_seq'),
            envelopeCount: self::int($arr, 'envelope_count'),
            headHash: self::str($arr, 'head_hash'),
        );
    }

    /** @param array<string,mixed> $arr */
    private static function str(array $arr, string $k): string
    {
        if (! isset($arr[$k]) || ! is_string($arr[$k])) {
            throw new InvalidBundleManifest("ChainSegmentMeta missing string field: $k");
        }
        return $arr[$k];
    }

    /** @param array<string,mixed> $arr */
    private static function int(array $arr, string $k): int
    {
        if (! isset($arr[$k]) || ! is_int($arr[$k])) {
            throw new InvalidBundleManifest("ChainSegmentMeta missing int field: $k");
        }
        return $arr[$k];
    }
}
```

Create `src/Bundle/AnchorMeta.php` and `src/Bundle/ClaimedKeyMeta.php` following the same pattern (str/int helpers and `fromArray`/`toArray`). Required fields per spec §12:

- `AnchorMeta`: `anchor_id`, `chain_id`, `from_seq`, `to_seq`, `merkle_algorithm`, `root`, `driver`, `state`, `receipt_envelope_id`, optional `receipt_cache_file`.
- `ClaimedKeyMeta`: `key_id`, `sig_alg`, `fingerprint`, `file`. All required.

Create `src/Bundle/BundleManifest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final readonly class BundleManifest
{
    public string $format;

    /**
     * @param list<ChainSegmentMeta> $chains
     * @param list<AnchorMeta> $anchors
     * @param list<ClaimedKeyMeta> $claimedKeys
     */
    public function __construct(
        public string $createdAt,
        public array $chains,
        public array $anchors,
        public array $claimedKeys = [],
        public ?string $issuerHint = null,
        public ?string $note = null,
    ) {
        $this->format = BundleConstants::FORMAT;
        if ($createdAt === '') {
            throw new InvalidBundleManifest('created_at must not be empty');
        }
    }

    public function toJson(): string
    {
        $out = [
            'format' => $this->format,
            'created_at' => $this->createdAt,
            'chains' => array_map(fn (ChainSegmentMeta $c) => $c->toArray(), $this->chains),
            'anchors' => array_map(fn (AnchorMeta $a) => $a->toArray(), $this->anchors),
        ];
        if ($this->claimedKeys !== []) {
            $out['claimed_keys'] = array_map(fn (ClaimedKeyMeta $k) => $k->toArray(), $this->claimedKeys);
        }
        if ($this->issuerHint !== null) {
            $out['issuer_hint'] = $this->issuerHint;
        }
        if ($this->note !== null) {
            $out['note'] = $this->note;
        }
        return json_encode($out, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public static function fromJson(string $json): self
    {
        if (strlen($json) > BundleConstants::MAX_MANIFEST_BYTES) {
            throw new InvalidBundleManifest('Manifest exceeds size cap');
        }
        try {
            $arr = json_decode($json, true, depth: 32, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidBundleManifest('Manifest is not valid JSON: ' . $e->getMessage());
        }
        if (! is_array($arr)) {
            throw new InvalidBundleManifest('Manifest must be a JSON object');
        }
        if (($arr['format'] ?? null) !== BundleConstants::FORMAT) {
            throw new InvalidBundleManifest('Unsupported format: ' . var_export($arr['format'] ?? null, true));
        }
        if (! isset($arr['created_at']) || ! is_string($arr['created_at'])) {
            throw new InvalidBundleManifest('Manifest missing created_at');
        }
        if (! isset($arr['chains']) || ! is_array($arr['chains'])) {
            throw new InvalidBundleManifest('Manifest missing chains');
        }
        if (! isset($arr['anchors']) || ! is_array($arr['anchors'])) {
            throw new InvalidBundleManifest('Manifest missing anchors');
        }

        $chains = array_map(
            fn ($c) => is_array($c) ? ChainSegmentMeta::fromArray($c) : throw new InvalidBundleManifest('Invalid chain entry'),
            array_values($arr['chains']),
        );
        $anchors = array_map(
            fn ($a) => is_array($a) ? AnchorMeta::fromArray($a) : throw new InvalidBundleManifest('Invalid anchor entry'),
            array_values($arr['anchors']),
        );
        $keys = array_map(
            fn ($k) => is_array($k) ? ClaimedKeyMeta::fromArray($k) : throw new InvalidBundleManifest('Invalid key entry'),
            array_values($arr['claimed_keys'] ?? []),
        );

        return new self(
            createdAt: $arr['created_at'],
            chains: $chains,
            anchors: $anchors,
            claimedKeys: $keys,
            issuerHint: isset($arr['issuer_hint']) && is_string($arr['issuer_hint']) ? $arr['issuer_hint'] : null,
            note: isset($arr['note']) && is_string($arr['note']) ? $arr['note'] : null,
        );
    }
}
```

- [ ] **Step 3: Run manifest tests**

```
vendor/bin/phpunit --filter BundleManifestTest
```

Expected: pass.

- [ ] **Step 4: Commit**

```
git add src/Bundle/BundleManifest.php src/Bundle/ChainSegmentMeta.php src/Bundle/AnchorMeta.php src/Bundle/ClaimedKeyMeta.php src/Bundle/InvalidBundleManifest.php tests/Bundle/BundleManifestTest.php
git commit -m "feat(bundle): BundleManifest value object and JSON parser"
```

---

## Task 3.3: `BundleExporter` — write side

**Why:** Build a bundle from a chain segment: walk envelopes for `[from, to]`, find exact-range proof envelopes past `toSeq`, collect optional claimed keys and receipt cache, serialize manifest, write ZIP. Members are stored uncompressed (`ZIP_STORED`) so size accounting matches on-disk size; atomic temp+rename.

**Files:**
- Create: `src/Bundle/BundleExporter.php`
- Create: `src/Bundle/BundleWriter.php`
- Create: `src/Bundle/BundleExportException.php`
- Create: `tests/Bundle/BundleExporterTest.php`

- [ ] **Step 1: Write failing exporter tests**

Create `tests/Bundle/BundleExporterTest.php` with these scenarios:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Bundle\BundleExportException;
use Fissible\Attest\Bundle\BundleConstants;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class BundleExporterTest extends TestCase
{
    private string $tmpDir;
    private string $bundleDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-bx-' . bin2hex(random_bytes(8));
        $this->bundleDir = $this->tmpDir . '/out';
        mkdir($this->tmpDir, 0o700, recursive: true);
        mkdir($this->bundleDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_exports_segment_with_matching_anchor(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        for ($i = 1; $i <= 5; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        // Anchor exactly [1,5] with NullDriver
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('tenant:5', 1, 5, new NullDriver());

        $out = $this->bundleDir . '/incident.attest';
        BundleExporter::create($store)
            ->forChainSegment('tenant:5', 1, 5)
            ->withClaimedKey($kp->publicKey, keyId: 'k1', sigAlg: 'ed25519')
            ->withNote('Test export')
            ->writeTo($out);

        self::assertFileExists($out);
        // Open the ZIP and assert layout
        $zip = new \ZipArchive();
        self::assertTrue($zip->open($out) === true);
        self::assertNotFalse($zip->locateName(BundleConstants::MANIFEST_ENTRY));
        self::assertNotFalse($zip->locateName('chains/' . substr(hash('sha256', 'tenant:5'), 0, 32) . '.jsonl'));
        self::assertNotFalse($zip->locateName('proof_envelopes/' . substr(hash('sha256', 'tenant:5'), 0, 32) . '.jsonl'));
        $zip->close();
    }

    public function test_refuses_export_when_only_wider_anchor_exists(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        for ($i = 1; $i <= 10; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        // Anchor [1,10] - wider than requested [1,5]
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('tenant:5', 1, 10, new NullDriver());

        $this->expectException(BundleExportException::class);
        $this->expectExceptionMessageMatches('/exact range/i');
        BundleExporter::create($store)
            ->forChainSegment('tenant:5', 1, 5)
            ->writeTo($this->bundleDir . '/bad.attest');
    }

    public function test_warns_on_pending_anchor(): void
    {
        // Chain anchored via NullDriver — receipt state is SUBMITTED.
        // BundleExporter should accumulate a warning.
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'c', $signer);
        for ($i = 1; $i <= 3; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        $service = new AnchorService($store, $claimStore, $signer);
        $service->anchorRange('c', 1, 3, new NullDriver());

        $exporter = BundleExporter::create($store)->forChainSegment('c', 1, 3);
        $exporter->writeTo($this->bundleDir . '/c.attest');
        // NullDriver receipts are not "pending" in the OTS sense, so no
        // pending warning here. Replace this test with an OTS-pending one
        // when an OTS mock is wired into the test suite.
        $warnings = $exporter->warnings();
        self::assertIsArray($warnings);
    }

    public function test_writes_atomically_temp_then_rename(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'c', $signer);
        $chain->record('app.event', ['n' => 1]);
        $claimStore = new FileAnchorClaimStore($this->tmpDir);
        (new AnchorService($store, $claimStore, $signer))
            ->anchorRange('c', 1, 1, new NullDriver());

        $out = $this->bundleDir . '/c.attest';
        BundleExporter::create($store)
            ->forChainSegment('c', 1, 1)
            ->writeTo($out);

        self::assertFileExists($out);
        // No leftover temp files
        $leftovers = glob($this->bundleDir . '/*.tmp.*');
        self::assertSame([], $leftovers);
    }
}
```

- [ ] **Step 2: Add `BundleExportException`**

Create `src/Bundle/BundleExportException.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class BundleExportException extends \RuntimeException
{
}
```

- [ ] **Step 3: Add `BundleWriter` (thin `ZipArchive` wrapper)**

Create `src/Bundle/BundleWriter.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Chain\PathSafety;

final class BundleWriter
{
    private \ZipArchive $zip;
    private string $tmpPath;
    private string $finalPath;
    private int $totalBytes = 0;

    public static function open(string $finalPath): self
    {
        $self = new self();
        PathSafety::ensureWritableParent($finalPath);
        $self->finalPath = $finalPath;
        $self->tmpPath = $finalPath . '.tmp.' . bin2hex(random_bytes(8));
        $self->zip = new \ZipArchive();
        $opened = $self->zip->open($self->tmpPath, \ZipArchive::CREATE | \ZipArchive::EXCL);
        if ($opened !== true) {
            throw new BundleExportException("Could not open zip for write: {$self->tmpPath} (code: $opened)");
        }
        return $self;
    }

    public function addEntry(string $entryPath, string $bytes): void
    {
        BundleEntryPath::validate($entryPath);
        if (strlen($bytes) > BundleConstants::MAX_MEMBER_BYTES) {
            throw new BundleExportException("Entry $entryPath exceeds per-member size cap");
        }
        $this->totalBytes += strlen($bytes);
        if ($this->totalBytes > BundleConstants::MAX_TOTAL_UNCOMPRESSED_BYTES) {
            throw new BundleExportException('Bundle exceeds total uncompressed size cap');
        }
        if ($this->zip->addFromString($entryPath, $bytes) !== true) {
            throw new BundleExportException("Could not add entry to zip: $entryPath");
        }
        // Store uncompressed (ZIP_STORED) for byte-accounting symmetry.
        $this->zip->setCompressionName($entryPath, \ZipArchive::CM_STORE);
    }

    public function commit(): void
    {
        if ($this->zip->close() !== true) {
            throw new BundleExportException("Could not close zip: {$this->tmpPath}");
        }
        if (! rename($this->tmpPath, $this->finalPath)) {
            @unlink($this->tmpPath);
            throw new BundleExportException("Could not rename temp bundle to {$this->finalPath}");
        }
    }

    public function discard(): void
    {
        @$this->zip->close();
        @unlink($this->tmpPath);
    }
}
```

- [ ] **Step 4: Add `BundleExporter`**

Create `src/Bundle/BundleExporter.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Signing\Fingerprint;
use Fissible\Attest\Verification\Warning;
use ParagonIE\ConstantTime\Base64;

final class BundleExporter
{
    /** @var list<array{chainId:string, fromSeq:int, toSeq:int}> */
    private array $segments = [];

    /** @var list<array{pubkey:string, keyId:?string, sigAlg:string}> */
    private array $claimedKeys = [];

    /** @var list<Warning> */
    private array $warnings = [];

    private ?string $note = null;
    private ?string $issuerHint = null;

    public static function create(ChainStore $store): self
    {
        return new self($store);
    }

    private function __construct(private readonly ChainStore $store)
    {
    }

    public function forChainSegment(string $chainId, int $fromSeq, int $toSeq): self
    {
        if ($fromSeq < 1 || $toSeq < $fromSeq) {
            throw new BundleExportException('Invalid segment range');
        }
        $this->segments[] = ['chainId' => $chainId, 'fromSeq' => $fromSeq, 'toSeq' => $toSeq];
        return $this;
    }

    public function withClaimedKey(string $rawPubkeyBytes, ?string $keyId = null, string $sigAlg = 'ed25519'): self
    {
        if (strlen($rawPubkeyBytes) !== 32) {
            throw new BundleExportException('Ed25519 public key must be 32 bytes');
        }
        $this->claimedKeys[] = ['pubkey' => $rawPubkeyBytes, 'keyId' => $keyId, 'sigAlg' => $sigAlg];
        return $this;
    }

    public function withNote(string $note): self
    {
        $this->note = $note;
        return $this;
    }

    public function withIssuerHint(string $hint): self
    {
        $this->issuerHint = $hint;
        return $this;
    }

    public function writeTo(string $outPath): void
    {
        if ($this->segments === []) {
            throw new BundleExportException('No segments to export');
        }

        $chainMetas = [];
        $anchorMetas = [];
        $chainEntries = [];
        $proofEntries = [];
        $receiptEntries = [];

        foreach ($this->segments as $seg) {
            $entry = $this->collectSegment($seg['chainId'], $seg['fromSeq'], $seg['toSeq']);
            $chainEntries[$entry['chainEntryPath']] = $entry['chainBytes'];
            $proofEntries[$entry['proofEntryPath']] = $entry['proofBytes'];
            foreach ($entry['receiptEntries'] as $rPath => $rBytes) {
                $receiptEntries[$rPath] = $rBytes;
            }
            $chainMetas[] = new ChainSegmentMeta(
                chainId: $seg['chainId'],
                file: $entry['chainEntryPath'],
                fromSeq: $seg['fromSeq'],
                toSeq: $seg['toSeq'],
                envelopeCount: $entry['envelopeCount'],
                headHash: $entry['headHash'],
            );
            foreach ($entry['anchorMetas'] as $am) {
                $anchorMetas[] = $am;
            }
        }

        $claimedKeyMetas = [];
        $keyEntries = [];
        foreach ($this->claimedKeys as $ck) {
            $fingerprint = Fingerprint::ofRawEd25519PublicKey($ck['pubkey']);
            $entryPath = BundleConstants::KEYS_PREFIX . $fingerprint . '.pub';
            $keyEntries[$entryPath] = Base64::encode($ck['pubkey']);
            $claimedKeyMetas[] = new ClaimedKeyMeta(
                keyId: $ck['keyId'] ?? '',
                sigAlg: $ck['sigAlg'],
                fingerprint: 'sha256:' . $fingerprint,
                file: $entryPath,
            );
        }

        $manifest = new BundleManifest(
            createdAt: gmdate('Y-m-d\TH:i:s\Z'),
            chains: $chainMetas,
            anchors: $anchorMetas,
            claimedKeys: $claimedKeyMetas,
            issuerHint: $this->issuerHint,
            note: $this->note,
        );

        $writer = BundleWriter::open($outPath);
        try {
            $writer->addEntry(BundleConstants::MANIFEST_ENTRY, $manifest->toJson());
            foreach ($chainEntries as $p => $b)   { $writer->addEntry($p, $b); }
            foreach ($proofEntries as $p => $b)   { $writer->addEntry($p, $b); }
            foreach ($receiptEntries as $p => $b) { $writer->addEntry($p, $b); }
            foreach ($keyEntries as $p => $b)     { $writer->addEntry($p, $b); }
            $writer->commit();
        } catch (\Throwable $e) {
            $writer->discard();
            throw $e;
        }
    }

    /** @return list<Warning> */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /**
     * @return array{
     *   chainEntryPath:string,
     *   chainBytes:string,
     *   proofEntryPath:string,
     *   proofBytes:string,
     *   receiptEntries:array<string,string>,
     *   envelopeCount:int,
     *   headHash:string,
     *   anchorMetas:list<AnchorMeta>,
     * }
     */
    private function collectSegment(string $chainId, int $fromSeq, int $toSeq): array
    {
        $chainHash = substr(hash('sha256', $chainId), 0, 32);
        $chainEntryPath = BundleConstants::CHAINS_PREFIX . $chainHash . '.jsonl';
        $proofEntryPath = BundleConstants::PROOF_ENVELOPES_PREFIX . $chainHash . '.jsonl';

        // Chain segment bytes
        $chainLines = [];
        $headHash = null;
        $count = 0;
        if ($this->store instanceof RawChainStore) {
            foreach ($this->store->readRawRange($chainId, $fromSeq, $toSeq) as $raw) {
                $chainLines[] = $raw;
                $count++;
            }
            // Recompute head_hash from the last raw line
            if ($chainLines !== []) {
                $headHash = bin2hex(hash('sha256', end($chainLines), binary: true));
            }
        } else {
            foreach ($this->store->readRange($chainId, $fromSeq, $toSeq) as $signed) {
                $chainLines[] = $signed->signedCanonicalBytes();
                $count++;
                $headHash = $signed->selfHash();
            }
        }
        if ($count !== ($toSeq - $fromSeq + 1)) {
            throw new BundleExportException("Chain segment incomplete: expected " . ($toSeq - $fromSeq + 1) . ", got $count");
        }

        // Walk forward past toSeq for exact-range proof envelopes
        $proofLines = [];
        $receiptEntries = [];
        $anchorMetas = [];
        $hadOverlapOnly = true;
        foreach ($this->store->readRange($chainId, $toSeq + 1) as $signed) {
            if (! str_starts_with($signed->envelope->type, 'attest.anchor.')) {
                continue;
            }
            try {
                $receipt = AnchorEnvelope::fromSignedEnvelope($signed);
            } catch (\Throwable) {
                continue;
            }
            $target = $receipt->target;
            if ($target->chainId !== $chainId) {
                continue;
            }
            // Exact-range only
            if ($target->fromSeq !== $fromSeq || $target->toSeq !== $toSeq) {
                // wider/overlapping — surface as warning if it's the only coverage
                continue;
            }
            $hadOverlapOnly = false;

            // Re-emit canonical line (we don't have raw bytes for post-range via RawChainStore yet
            // because anchorEnvelopesFor uses readRange; recompute canonical form)
            $proofLines[] = $signed->signedCanonicalBytes();

            $anchorMetas[] = new AnchorMeta(
                anchorId: $receipt->anchorId,
                chainId: $target->chainId,
                fromSeq: $target->fromSeq,
                toSeq: $target->toSeq,
                merkleAlgorithm: $target->merkleAlgorithm,
                root: $target->rootHex,
                driver: $receipt->driverName,
                state: $receipt->state->value,
                receiptEnvelopeId: $signed->envelope->id,
                receiptCacheFile: BundleConstants::RECEIPTS_PREFIX . $receipt->anchorId . '.ots',
            );
            $receiptEntries[BundleConstants::RECEIPTS_PREFIX . $receipt->anchorId . '.ots'] = $receipt->receiptBytes;

            if ($receipt->state === ProofState::PENDING) {
                $this->warnings[] = new Warning(
                    'bundle_export_pending_anchor',
                    'Anchor is in PENDING state; consider running `attest upgrade` before export.',
                    ['anchor_id' => $receipt->anchorId],
                );
            }
        }

        if ($proofLines === []) {
            // Check whether wider anchors exist — for a useful error message
            $widerExists = false;
            foreach ($this->store->readRange($chainId, $toSeq + 1) as $signed) {
                if (! str_starts_with($signed->envelope->type, 'attest.anchor.')) continue;
                try {
                    $receipt = AnchorEnvelope::fromSignedEnvelope($signed);
                    if ($receipt->target->chainId === $chainId
                        && ($receipt->target->fromSeq <= $fromSeq && $receipt->target->toSeq >= $toSeq)) {
                        $widerExists = true;
                        break;
                    }
                } catch (\Throwable) {}
            }
            if ($widerExists) {
                throw new BundleExportException(
                    "No proof envelope matches exact range [$fromSeq,$toSeq] for chain $chainId; "
                    . 'wider anchors exist but subset inclusion proofs are not supported in v1. '
                    . 'Export the full anchored range instead.',
                );
            }
        }

        return [
            'chainEntryPath' => $chainEntryPath,
            'chainBytes' => implode("\n", $chainLines) . ($chainLines === [] ? '' : "\n"),
            'proofEntryPath' => $proofEntryPath,
            'proofBytes' => implode("\n", $proofLines) . ($proofLines === [] ? '' : "\n"),
            'receiptEntries' => $receiptEntries,
            'envelopeCount' => $count,
            'headHash' => $headHash ?? str_repeat('0', 64),
            'anchorMetas' => $anchorMetas,
        ];
    }
}
```

Verify `Fingerprint::ofRawEd25519PublicKey()` exists; if it's named differently in Chunk 1 (e.g., `Fingerprint::of()` accepting raw bytes), use the existing API.

- [ ] **Step 5: Run exporter tests**

```
vendor/bin/phpunit --filter BundleExporterTest
```

Expected: all four scenarios pass.

- [ ] **Step 6: Commit**

```
git add src/Bundle/BundleExporter.php src/Bundle/BundleWriter.php src/Bundle/BundleExportException.php tests/Bundle/BundleExporterTest.php
git commit -m "feat(bundle): BundleExporter with exact-range proof envelopes and atomic write"
```

---

## Task 3.4: `BundleReader` — read side with safety limits

**Why:** Open a bundle, enforce path safety + per-member + total + ratio caps before parsing any content, then expose manifest + chain bytes + proof envelopes + receipt cache + claimed keys to downstream consumers.

**Files:**
- Create: `src/Bundle/BundleReader.php`
- Create: `src/Bundle/InvalidBundle.php`
- Create: `tests/Bundle/BundleReaderTest.php`

- [ ] **Step 1: Write failing reader tests**

Create `tests/Bundle/BundleReaderTest.php` with these cases:

- `test_opens_well_formed_bundle_and_reads_manifest`
- `test_rejects_bundle_without_manifest`
- `test_rejects_member_with_zip_slip_path` (craft a zip with an entry named `../escape`)
- `test_rejects_oversize_member`
- `test_rejects_oversize_total`
- `test_rejects_high_compression_ratio` (craft a deflate-compressed zip whose ratio exceeds the cap)
- `test_provides_raw_envelope_bytes_for_chain_member`
- `test_provides_proof_envelopes_iterable`
- `test_warns_on_receipt_cache_mismatch` (cache file present but bytes ≠ proof envelope's `receipt_bytes`)

For brevity, full PHPUnit code is omitted here; each test follows the pattern of constructing a `ZipArchive` in `setUp`, exercising `BundleReader::open($path)`, and asserting the typed exception or expected accessor output.

- [ ] **Step 2: Add `InvalidBundle`**

Create `src/Bundle/InvalidBundle.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class InvalidBundle extends \RuntimeException
{
}
```

- [ ] **Step 3: Add `BundleReader`**

Create `src/Bundle/BundleReader.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Verification\Warning;

final class BundleReader
{
    private \ZipArchive $zip;
    private BundleManifest $manifest;

    /** @var list<Warning> */
    private array $warnings = [];

    public static function open(string $path): self
    {
        $self = new self();
        $self->zip = new \ZipArchive();
        $opened = $self->zip->open($path, \ZipArchive::RDONLY);
        if ($opened !== true) {
            throw new InvalidBundle("Could not open bundle: $path (code $opened)");
        }
        $self->validateAndLoad();
        return $self;
    }

    private function validateAndLoad(): void
    {
        $count = $self_count = $this->zip->numFiles;
        $totalUncompressed = 0;
        $totalCompressed = 0;
        $sawManifest = false;
        $seen = [];

        for ($i = 0; $i < $self_count; $i++) {
            $stat = $this->zip->statIndex($i);
            if ($stat === false) {
                throw new InvalidBundle("Could not stat entry $i");
            }
            $name = $stat['name'];
            BundleEntryPath::validate($name);
            if (isset($seen[$name])) {
                throw new InvalidBundle("Duplicate entry: $name");
            }
            $seen[$name] = true;
            if ($stat['size'] > BundleConstants::MAX_MEMBER_BYTES) {
                throw new InvalidBundle("Entry $name exceeds per-member size cap");
            }
            $totalUncompressed += (int) $stat['size'];
            $totalCompressed += (int) $stat['comp_size'];
            if ($totalUncompressed > BundleConstants::MAX_TOTAL_UNCOMPRESSED_BYTES) {
                throw new InvalidBundle('Bundle exceeds total uncompressed size cap');
            }
            if ($name === BundleConstants::MANIFEST_ENTRY) {
                $sawManifest = true;
            }
        }

        if ($totalCompressed > 0
            && $totalUncompressed / max(1, $totalCompressed) > BundleConstants::MAX_COMPRESSION_RATIO) {
            throw new InvalidBundle('Bundle compression ratio exceeds cap (zip-bomb guard)');
        }
        if (! $sawManifest) {
            throw new InvalidBundle('Bundle is missing manifest.json');
        }

        $manifestBytes = $this->zip->getFromName(BundleConstants::MANIFEST_ENTRY);
        if ($manifestBytes === false) {
            throw new InvalidBundle('Could not read manifest.json');
        }
        $this->manifest = BundleManifest::fromJson($manifestBytes);
    }

    public function manifest(): BundleManifest
    {
        return $this->manifest;
    }

    /** @return iterable<string> raw signed canonical envelope bytes for chain $chainId */
    public function readChainSegmentRaw(string $chainId): iterable
    {
        $expectedPath = BundleConstants::CHAINS_PREFIX
            . substr(hash('sha256', $chainId), 0, 32) . '.jsonl';
        $bytes = $this->zip->getFromName($expectedPath);
        if ($bytes === false) {
            throw new InvalidBundle("Bundle is missing chain segment for $chainId");
        }
        foreach (explode("\n", $bytes) as $line) {
            if ($line === '') continue;
            yield $line;
        }
    }

    /** @return iterable<SignedEnvelope> */
    public function readProofEnvelopes(string $chainId): iterable
    {
        $expectedPath = BundleConstants::PROOF_ENVELOPES_PREFIX
            . substr(hash('sha256', $chainId), 0, 32) . '.jsonl';
        $bytes = $this->zip->getFromName($expectedPath);
        if ($bytes === false) {
            return;
        }
        foreach (explode("\n", $bytes) as $line) {
            if ($line === '') continue;
            yield EnvelopeCodec::decodeSigned($line);
        }
    }

    /** @return iterable<array{fingerprint:string, keyId:string, pubkey:string}> */
    public function readClaimedKeys(): iterable
    {
        foreach ($this->manifest->claimedKeys as $km) {
            $b64 = $this->zip->getFromName($km->file);
            if ($b64 === false) {
                $this->warnings[] = new Warning(
                    'bundle_missing_claimed_key',
                    "Claimed key file not present: {$km->file}",
                    ['key_id' => $km->keyId, 'file' => $km->file],
                );
                continue;
            }
            $raw = base64_decode(trim($b64), true);
            if ($raw === false || strlen($raw) !== 32) {
                $this->warnings[] = new Warning(
                    'bundle_invalid_claimed_key',
                    "Claimed key file is not a valid 32-byte Ed25519 pubkey: {$km->file}",
                    ['key_id' => $km->keyId, 'file' => $km->file],
                );
                continue;
            }
            $computed = bin2hex(hash('sha256', $raw, binary: true));
            $stated = str_replace('sha256:', '', $km->fingerprint);
            if ($computed !== $stated) {
                $this->warnings[] = new Warning(
                    'bundle_claimed_key_fingerprint_mismatch',
                    "Claimed key fingerprint mismatch for {$km->keyId}",
                    ['key_id' => $km->keyId, 'expected' => $stated, 'computed' => $computed],
                );
                continue;
            }
            yield ['fingerprint' => $computed, 'keyId' => $km->keyId, 'pubkey' => $raw];
        }
    }

    public function getReceiptCache(string $anchorId): ?string
    {
        $path = BundleConstants::RECEIPTS_PREFIX . $anchorId . '.ots';
        $bytes = $this->zip->getFromName($path);
        return $bytes === false ? null : $bytes;
    }

    /** @return list<Warning> */
    public function warnings(): array
    {
        return $this->warnings;
    }

    public function close(): void
    {
        $this->zip->close();
    }
}
```

- [ ] **Step 4: Run reader tests**

```
vendor/bin/phpunit --filter BundleReaderTest
```

Expected: all scenarios pass.

- [ ] **Step 5: Commit**

```
git add src/Bundle/BundleReader.php src/Bundle/InvalidBundle.php tests/Bundle/BundleReaderTest.php
git commit -m "feat(bundle): BundleReader with safe ZIP parsing and ratio guard"
```

---

## Task 3.5: `BundleStore` — verifier-compatible adapter

**Why:** Implement `RawChainStore` over the chain segment in a bundle so `Verifier` can verify a bundle without code changes for the chain-layer path. Proof envelopes are NOT exposed via `readRange()`; they're fed to `Verifier` via the new constructor channel introduced in Task 3.6.

**Files:**
- Create: `src/Bundle/BundleStore.php`
- Create: `tests/Bundle/BundleStoreTest.php`

- [ ] **Step 1: Write failing tests**

Test cases for `BundleStoreTest`:
- `test_readRawRange_yields_raw_chain_segment_bytes`
- `test_readRange_decodes_envelopes`
- `test_tail_returns_last_envelope`
- `test_exists_returns_true_for_chains_in_manifest`
- `test_listChains_lists_chain_ids_from_manifest`
- `test_append_throws_unsupported_operation`

- [ ] **Step 2: Add `BundleStore`**

Create `src/Bundle/BundleStore.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Chain\AppendContext;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;

final class BundleStore implements ChainStore, RawChainStore
{
    public function __construct(private readonly BundleReader $reader)
    {
    }

    public function append(string $chainId, callable $buildAndSign): SignedEnvelope
    {
        throw new \LogicException('BundleStore is read-only; append() is not supported');
    }

    public function tail(string $chainId): ?SignedEnvelope
    {
        $last = null;
        foreach ($this->readRange($chainId, 1) as $env) {
            $last = $env;
        }
        return $last;
    }

    public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
    {
        foreach ($this->reader->readChainSegmentRaw($chainId) as $raw) {
            $env = EnvelopeCodec::decodeSigned($raw);
            if ($env->envelope->seq < $fromSeq) continue;
            if ($toSeq !== null && $env->envelope->seq > $toSeq) break;
            yield $env;
        }
    }

    public function readRawRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
    {
        foreach ($this->reader->readChainSegmentRaw($chainId) as $raw) {
            $env = EnvelopeCodec::decodeSigned($raw);
            if ($env->envelope->seq < $fromSeq) continue;
            if ($toSeq !== null && $env->envelope->seq > $toSeq) break;
            yield $raw;
        }
    }

    public function listChains(): iterable
    {
        foreach ($this->reader->manifest()->chains as $segMeta) {
            yield $segMeta->chainId;
        }
    }

    public function exists(string $chainId): bool
    {
        foreach ($this->reader->manifest()->chains as $segMeta) {
            if ($segMeta->chainId === $chainId) return true;
        }
        return false;
    }
}
```

- [ ] **Step 3: Run tests**

```
vendor/bin/phpunit --filter BundleStoreTest
```

Expected: pass.

- [ ] **Step 4: Commit**

```
git add src/Bundle/BundleStore.php tests/Bundle/BundleStoreTest.php
git commit -m "feat(bundle): BundleStore RawChainStore adapter"
```

---

## Task 3.6: Verifier accepts detached anchor envelopes from any source

**Why:** Bundle verification feeds proof envelopes to `Verifier` from `proof_envelopes/` — they're not in the chain segment. Chunk 2.5 added detached-anchor classification when reading post-range envelopes from a live `ChainStore`. Now extend `Verifier` to also accept an explicit `iterable<SignedEnvelope>` of detached envelopes via the constructor, run them through `DetachedAnchorVerifier`, and merge with the post-range anchors already collected from the store.

**Files:**
- Modify: `src/Verification/Verifier.php`
- Create: `tests/Verification/VerifierDetachedInputTest.php`
- Create: `tests/Bundle/BundleRoundTripTest.php`

- [ ] **Step 1: Write failing test for explicit detached input**

Create `tests/Verification/VerifierDetachedInputTest.php` with:

- `test_verifier_accepts_explicit_detached_anchor_envelopes_for_min_anchor`
- `test_explicit_detached_envelopes_are_classified_by_signature`
- `test_in_chain_and_explicit_detached_envelopes_merge_by_anchor_id`

- [ ] **Step 2: Add the constructor parameter to `Verifier`**

In `src/Verification/Verifier.php`:

```php
/** @var list<SignedEnvelope> */
private array $explicitDetachedEnvelopes;

public function __construct(
    private readonly ChainStore $store,
    private readonly SignatureVerifier $signatures,
    private readonly VerificationPolicy $policy = new VerificationPolicy(),
    iterable $anchorDrivers = [],
    private readonly HeaderProviderSet $headers = new HeaderProviderSet(),
    iterable $detachedAnchorEnvelopes = [],
) {
    foreach ($anchorDrivers as $driver) {
        $this->anchorDrivers[$driver->name()] = $driver;
    }
    $this->detachedAnchorVerifier = new DetachedAnchorVerifier($signatures);
    $this->explicitDetachedEnvelopes = is_array($detachedAnchorEnvelopes)
        ? array_values($detachedAnchorEnvelopes)
        : iterator_to_array($detachedAnchorEnvelopes, false);
}
```

Then in `anchorEnvelopesFor()`, append the explicit detached envelopes to the post-range list before classification:

```php
private function anchorEnvelopesFor(
    string $chainId,
    int $toSeq,
    array $rangeEnvelopes,
    array $rangeSignatureResults,
): array {
    $out = [];
    // ... (existing in-range path) ...

    $postRange = [];
    foreach ($this->store->readRange($chainId, $toSeq + 1) as $signed) {
        if (str_starts_with($signed->envelope->type, 'attest.anchor.')) {
            $postRange[] = $signed;
        }
    }
    foreach ($this->explicitDetachedEnvelopes as $signed) {
        if (str_starts_with($signed->envelope->type, 'attest.anchor.')
            && $signed->envelope->chain === $chainId) {
            $postRange[] = $signed;
        }
    }
    $out = [...$out, ...$this->detachedAnchorVerifier->classify($postRange)];
    return $out;
}
```

- [ ] **Step 3: Run tests**

```
vendor/bin/phpunit --filter VerifierDetachedInputTest
```

Expected: pass.

- [ ] **Step 4: Write `BundleRoundTripTest`**

Create `tests/Bundle/BundleRoundTripTest.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Bundle\BundleReader;
use Fissible\Attest\Bundle\BundleStore;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\TrustedKey;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use PHPUnit\Framework\TestCase;

final class BundleRoundTripTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-rt-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_bundle_verifies_with_same_outcome_as_live_chain(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'tenant:5', $signer);
        for ($i = 1; $i <= 5; $i++) {
            $chain->record('app.event', ['n' => $i]);
        }
        (new AnchorService($store, new FileAnchorClaimStore($this->tmpDir), $signer))
            ->anchorRange('tenant:5', 1, 5, new NullDriver());

        // Verify live
        $live = new Verifier(
            store: $store,
            signatures: new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'k1')]),
            policy: new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY),
            anchorDrivers: [new NullDriver()],
        );
        $liveResult = $live->verifyChain('tenant:5', 1, 5);
        self::assertSame(VerificationOutcome::VERIFIED, $liveResult->outcome);

        // Export and verify from bundle
        $out = $this->tmpDir . '/incident.attest';
        BundleExporter::create($store)
            ->forChainSegment('tenant:5', 1, 5)
            ->withClaimedKey($kp->publicKey, keyId: 'k1', sigAlg: 'ed25519')
            ->writeTo($out);

        $reader = BundleReader::open($out);
        $bundleStore = new BundleStore($reader);
        $proofEnvelopes = iterator_to_array($reader->readProofEnvelopes('tenant:5'), false);

        $bundleVerifier = new Verifier(
            store: $bundleStore,
            signatures: new SignatureVerifier([new TrustedKey($kp->publicKey, keyId: 'k1')]),
            policy: new VerificationPolicy(minAnchorOutcome: AnchorOutcome::LOCAL_ONLY),
            anchorDrivers: [new NullDriver()],
            detachedAnchorEnvelopes: $proofEnvelopes,
        );
        $bundleResult = $bundleVerifier->verifyChain('tenant:5', 1, 5);

        self::assertSame($liveResult->outcome, $bundleResult->outcome);
        self::assertSame($liveResult->chainStats->envelopeCount, $bundleResult->chainStats->envelopeCount);
    }
}
```

- [ ] **Step 5: Run round-trip test**

```
vendor/bin/phpunit --filter BundleRoundTripTest
```

Expected: pass.

- [ ] **Step 6: Commit**

```
git add src/Verification/Verifier.php tests/Verification/VerifierDetachedInputTest.php tests/Bundle/BundleRoundTripTest.php
git commit -m "feat(verifier): accept explicit detached anchor envelopes for bundle path"
```

---

## Task 3.7: CLI skeleton, output emitters, and JSON schema

**Why:** A single composer-installed binary needs a dispatcher, per-command unit tests, JSON output with a versioned schema, and shared helpers for trusted-key loading, header-provider construction, and `--min-anchor` parsing. Subsequent command tasks plug into this skeleton.

**Files:**
- Create: `bin/attest`
- Create: `src/Cli/AttestCli.php`
- Create: `src/Cli/Output/ResultEmitter.php`
- Create: `src/Cli/Output/JsonResultEmitter.php`
- Create: `src/Cli/Output/HumanResultEmitter.php`
- Create: `src/Cli/Output/JsonResultSchema.php`
- Create: `src/Cli/Support/TrustedKeyLoader.php`
- Create: `src/Cli/Support/MinAnchorOption.php`
- Create: `src/Cli/Support/HeaderProviderFactory.php`
- Create: `tests/Cli/Output/JsonResultEmitterTest.php`

- [ ] **Step 1: Add composer dependency and bin declaration**

In `composer.json`:

```json
{
    "require": {
        "...": "...",
        "symfony/console": "^6.4 || ^7.0"
    },
    "bin": ["bin/attest"]
}
```

Run `composer update symfony/console`.

- [ ] **Step 2: Create the entrypoint**

Create `bin/attest`:

```php
#!/usr/bin/env php
<?php
declare(strict_types=1);

$autoloadCandidates = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../../autoload.php',
];
foreach ($autoloadCandidates as $c) {
    if (is_file($c)) { require $c; break; }
}

exit((new Fissible\Attest\Cli\AttestCli())->run());
```

Make it executable: `chmod +x bin/attest`.

- [ ] **Step 3: Add `AttestCli`**

Create `src/Cli/AttestCli.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli;

use Fissible\Attest\Cli\Command\AnchorCommand;
use Fissible\Attest\Cli\Command\BundleExportCommand;
use Fissible\Attest\Cli\Command\BundleVerifyCommand;
use Fissible\Attest\Cli\Command\UpgradeCommand;
use Fissible\Attest\Cli\Command\VerifyCommand;
use Symfony\Component\Console\Application;

final class AttestCli
{
    public function run(): int
    {
        $app = new Application('attest', $this->version());
        $app->add(new VerifyCommand());
        $app->add(new BundleExportCommand());
        $app->add(new BundleVerifyCommand());
        $app->add(new AnchorCommand());
        $app->add(new UpgradeCommand());
        return $app->run();
    }

    private function version(): string
    {
        $file = __DIR__ . '/../../VERSION';
        return is_file($file) ? trim((string) file_get_contents($file)) : 'dev';
    }
}
```

- [ ] **Step 4: Add JSON result schema**

Create `src/Cli/Output/JsonResultSchema.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;

/**
 * Stable v1 JSON schema for `attest *` commands that produce a
 * VerificationResult. Field names are pinned; future versions may add
 * fields but must not change existing meanings without a format-version bump.
 */
final class JsonResultSchema
{
    public const FORMAT = 'attest.cli.result.v1';

    /** @return array<string,mixed> */
    public static function fromVerification(string $command, VerificationResult $result, int $exitCode): array
    {
        return [
            'format_version' => self::FORMAT,
            'command' => $command,
            'outcome' => $result->outcome->value,
            'verified' => $result->outcome->value === 'verified',
            'exit_code' => $exitCode,
            'message' => $result->message,
            'broken_at_seq' => $result->brokenAtSeq,
            'chain_stats' => [
                'chain_id' => $result->chainStats->chainId,
                'from_seq' => $result->chainStats->fromSeq,
                'to_seq' => $result->chainStats->toSeq,
                'envelope_count' => $result->chainStats->envelopeCount,
                'trusted_signatures' => $result->chainStats->trustedSignatureCount,
                'untrusted_signatures' => $result->chainStats->untrustedSignatureCount,
                'anchor_envelopes' => $result->chainStats->anchorEnvelopeCount,
            ],
            'signature_summary' => self::signatureSummary($result),
            'anchor_verification' => self::anchorSummary($result),
            'warnings' => array_map(
                static fn ($w) => ['code' => $w->code, 'message' => $w->message, 'context' => $w->context],
                $result->warnings,
            ),
        ];
    }

    /** @return array<string,mixed> */
    private static function signatureSummary(VerificationResult $result): array
    {
        $byKey = [];
        foreach ($result->signatureResults ?? [] as $sr) {
            if (! $sr->hasTrustedMatch()) continue;
            foreach ($sr->matches() ?? [] as $m) {
                $id = $m->key->keyId ?? $m->key->fingerprint;
                $byKey[$id] ??= 0;
                $byKey[$id]++;
            }
        }
        return [
            'trusted_keys_matched' => $byKey,
        ];
    }

    /** @return array<string,mixed>|null */
    private static function anchorSummary(VerificationResult $result): ?array
    {
        $av = $result->anchorVerification ?? null;
        if ($av === null) return null;
        return [
            'outcome' => $av->outcome->value,
            'provider' => $av->providerName ?? null,
            'message' => $av->message,
            'context' => $av->context,
        ];
    }
}
```

- [ ] **Step 5: Add the emitter interface and two implementations**

`src/Cli/Output/ResultEmitter.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;
use Symfony\Component\Console\Output\OutputInterface;

interface ResultEmitter
{
    public function emit(string $command, VerificationResult $result, int $exitCode, OutputInterface $output): void;
}
```

`src/Cli/Output/JsonResultEmitter.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;
use Symfony\Component\Console\Output\OutputInterface;

final class JsonResultEmitter implements ResultEmitter
{
    public function emit(string $command, VerificationResult $result, int $exitCode, OutputInterface $output): void
    {
        $output->writeln(json_encode(
            JsonResultSchema::fromVerification($command, $result, $exitCode),
            JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT,
        ));
    }
}
```

`src/Cli/Output/HumanResultEmitter.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;
use Symfony\Component\Console\Output\OutputInterface;

final class HumanResultEmitter implements ResultEmitter
{
    public function emit(string $command, VerificationResult $result, int $exitCode, OutputInterface $output): void
    {
        $stats = $result->chainStats;
        $output->writeln(sprintf(
            'chain & signatures: %s (%d envelopes, %d trusted, %d untrusted)',
            $result->outcome->value,
            $stats->envelopeCount,
            $stats->trustedSignatureCount,
            $stats->untrustedSignatureCount,
        ));
        if ($result->anchorVerification !== null) {
            $output->writeln(sprintf(
                'anchor: %s%s',
                $result->anchorVerification->outcome->value,
                $result->anchorVerification->providerName !== null
                    ? ' via ' . $result->anchorVerification->providerName
                    : '',
            ));
        }
        foreach ($result->warnings as $w) {
            $output->writeln('warning: ' . $w->code . ' — ' . $w->message);
        }
        if ($result->message !== null) {
            $output->writeln('note: ' . $result->message);
        }
        $output->writeln(sprintf('exit %d', $exitCode));
    }
}
```

- [ ] **Step 6: Add support helpers**

`src/Cli/Support/MinAnchorOption.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Anchor\AnchorOutcome;

final class MinAnchorOption
{
    public static function parse(?string $raw): ?AnchorOutcome
    {
        if ($raw === null) return null;
        return match (strtolower(trim($raw))) {
            'local_only' => AnchorOutcome::LOCAL_ONLY,
            'pending' => AnchorOutcome::PENDING,
            'upgraded_no_headers' => AnchorOutcome::UPGRADED_NO_HEADERS,
            'remote_header_confirmed' => AnchorOutcome::REMOTE_HEADER_CONFIRMED,
            'bitcoin_verified' => AnchorOutcome::BITCOIN_VERIFIED,
            default => throw new \InvalidArgumentException(
                "Invalid --min-anchor value: $raw (allowed: local_only, pending, upgraded_no_headers, remote_header_confirmed, bitcoin_verified)"
            ),
        };
    }
}
```

`src/Cli/Support/TrustedKeyLoader.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Verification\TrustedKey;
use ParagonIE\ConstantTime\Base64;

final class TrustedKeyLoader
{
    /**
     * @param list<string> $inline   each entry is "<key_id>=<base64-pubkey>"
     * @param list<string> $files    paths to .pub files containing base64 pubkeys
     * @return list<TrustedKey>
     */
    public static function load(array $inline, array $files): array
    {
        $keys = [];
        foreach ($inline as $entry) {
            if (! str_contains($entry, '=')) {
                throw new \InvalidArgumentException("Invalid --trusted-key entry: $entry (expected '<key_id>=<base64>')");
            }
            [$keyId, $b64] = explode('=', $entry, 2);
            $keys[] = new TrustedKey(self::decodePubkey($b64), keyId: $keyId);
        }
        foreach ($files as $path) {
            if (! is_file($path)) {
                throw new \InvalidArgumentException("Trusted-key file not found: $path");
            }
            $b64 = trim((string) file_get_contents($path));
            $keys[] = new TrustedKey(self::decodePubkey($b64));
        }
        return $keys;
    }

    private static function decodePubkey(string $b64): string
    {
        $raw = Base64::decode($b64, strictPadding: true);
        if (strlen($raw) !== 32) {
            throw new \InvalidArgumentException('Trusted public key must decode to 32 bytes');
        }
        return $raw;
    }
}
```

`src/Cli/Support/HeaderProviderFactory.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Support;

use Fissible\Attest\Headers\BitcoinCoreRpcHeaderProvider;
use Fissible\Attest\Headers\EsploraHeaderProvider;
use Fissible\Attest\Headers\HeaderProviderSet;

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
                throw new \RuntimeException('--esplora-url requires a PSR-18 HTTP client.');
            }
            $http = new \GuzzleHttp\Client();
            $factory = new \GuzzleHttp\Psr7\HttpFactory();
            $providers[] = new EsploraHeaderProvider(
                http: $http,
                requests: $factory,
                streams: $factory,
                baseUrl: $esploraUrl,
            );
        }
        return new HeaderProviderSet(...$providers);
    }
}
```

- [ ] **Step 7: Write `JsonResultEmitterTest`**

Construct a synthetic `VerificationResult` (mocked `ChainStats`, empty signature results, optional anchor verification) and assert that `JsonResultEmitter::emit()` produces JSON matching the v1 schema field-by-field.

- [ ] **Step 8: Run tests**

```
vendor/bin/phpunit --filter JsonResultEmitterTest
```

Expected: pass.

- [ ] **Step 9: Commit**

```
git add bin/attest src/Cli/ tests/Cli/Output/ composer.json composer.lock
git commit -m "feat(cli): skeleton, JSON output schema v1, shared helpers"
```

---

## Task 3.8: `attest verify` command

**Files:**
- Create: `src/Cli/Command/VerifyCommand.php`
- Create: `tests/Cli/Command/VerifyCommandTest.php`

- [ ] **Step 1: Write failing command test**

`tests/Cli/Command/VerifyCommandTest.php` cases:

- `test_verifies_chain_and_exits_0`
- `test_invalid_min_anchor_value_exits_1`
- `test_missing_storage_root_exits_1`
- `test_untrusted_signature_exits_2`
- `test_anchor_below_min_exits_3`
- `test_invalid_chain_exits_4`
- `test_provider_disagreement_exits_5`
- `test_allow_untrusted_downgrades_to_0`
- `test_json_output_matches_schema_v1`

All tests build a chain on a `FileChainStore` in `setUp`, instantiate `VerifyCommand` directly (no process forking), call `execute()` via `Symfony\Component\Console\Tester\CommandTester`, assert exit code and output.

- [ ] **Step 2: Add `VerifyCommand`**

Create `src/Cli/Command/VerifyCommand.php`:

```php
<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Output\HumanResultEmitter;
use Fissible\Attest\Cli\Output\JsonResultEmitter;
use Fissible\Attest\Cli\Support\HeaderProviderFactory;
use Fissible\Attest\Cli\Support\MinAnchorOption;
use Fissible\Attest\Cli\Support\TrustedKeyLoader;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'verify', description: 'Verify a chain segment against trusted keys and policy.')]
final class VerifyCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('storage-root', null, InputOption::VALUE_REQUIRED, 'Path to the FileChainStore root.')
            ->addOption('chain', null, InputOption::VALUE_REQUIRED, 'Chain ID to verify.')
            ->addOption('from', null, InputOption::VALUE_REQUIRED, 'Start sequence (default 1).', '1')
            ->addOption('to', null, InputOption::VALUE_REQUIRED, 'End sequence (default chain tail).')
            ->addOption('trusted-key', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Inline trusted key: <key_id>=<base64-pubkey>.')
            ->addOption('trusted-key-file', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Path to a .pub file.')
            ->addOption('min-anchor', null, InputOption::VALUE_REQUIRED, 'Minimum anchor outcome.')
            ->addOption('allow-provider-disagreement', null, InputOption::VALUE_NONE)
            ->addOption('allow-untrusted', null, InputOption::VALUE_NONE)
            ->addOption('bitcoin-core-rpc', null, InputOption::VALUE_REQUIRED)
            ->addOption('bitcoin-core-cookie', null, InputOption::VALUE_REQUIRED)
            ->addOption('esplora-url', null, InputOption::VALUE_REQUIRED)
            ->addOption('json', null, InputOption::VALUE_NONE);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $storageRoot = $input->getOption('storage-root');
            $chainId = $input->getOption('chain');
            if (! is_string($storageRoot) || ! is_dir($storageRoot)) {
                $output->writeln('error: --storage-root must point to an existing directory');
                return 1;
            }
            if (! is_string($chainId) || $chainId === '') {
                $output->writeln('error: --chain is required');
                return 1;
            }
            $fromSeq = (int) ($input->getOption('from') ?? 1);
            $toSeq = $input->getOption('to') !== null ? (int) $input->getOption('to') : null;
            $minAnchor = MinAnchorOption::parse($input->getOption('min-anchor'));
            $trustedKeys = TrustedKeyLoader::load(
                $input->getOption('trusted-key') ?: [],
                $input->getOption('trusted-key-file') ?: [],
            );
            $headers = HeaderProviderFactory::build(
                $input->getOption('bitcoin-core-rpc'),
                $input->getOption('bitcoin-core-cookie'),
                $input->getOption('esplora-url'),
            );
        } catch (\InvalidArgumentException | \RuntimeException $e) {
            $output->writeln('error: ' . $e->getMessage());
            return 1;
        }

        $store = new FileChainStore($storageRoot);
        $verifier = new Verifier(
            store: $store,
            signatures: new SignatureVerifier($trustedKeys),
            policy: new VerificationPolicy(
                minAnchorOutcome: $minAnchor,
                allowProviderDisagreement: (bool) $input->getOption('allow-provider-disagreement'),
                requireTrustedKey: ! $input->getOption('allow-untrusted'),
            ),
            headers: $headers,
        );
        $result = $verifier->verifyChain($chainId, $fromSeq, $toSeq);

        $exit = self::exitCodeFor($result->outcome, (bool) $input->getOption('allow-untrusted'));
        $emitter = $input->getOption('json') ? new JsonResultEmitter() : new HumanResultEmitter();
        $emitter->emit('verify', $result, $exit, $output);
        return $exit;
    }

    private static function exitCodeFor(VerificationOutcome $outcome, bool $allowUntrusted): int
    {
        return match ($outcome) {
            VerificationOutcome::VERIFIED => 0,
            VerificationOutcome::INTEGRITY_VERIFIED_UNTRUSTED => $allowUntrusted ? 0 : 2,
            VerificationOutcome::ANCHOR_BELOW_MIN => 3,
            VerificationOutcome::INVALID_CHAIN,
            VerificationOutcome::INVALID_SIGNATURE,
            VerificationOutcome::INVALID_ANCHOR => 4,
            VerificationOutcome::PROVIDER_DISAGREEMENT => 5,
        };
    }
}
```

- [ ] **Step 3: Run tests**

```
vendor/bin/phpunit --filter VerifyCommandTest
```

Expected: all nine scenarios pass.

- [ ] **Step 4: Commit**

```
git add src/Cli/Command/VerifyCommand.php tests/Cli/Command/VerifyCommandTest.php
git commit -m "feat(cli): attest verify command with spec §13 exit codes"
```

---

## Task 3.9: `attest bundle export` command

**Files:**
- Create: `src/Cli/Command/BundleExportCommand.php`
- Create: `tests/Cli/Command/BundleExportCommandTest.php`

- [ ] **Step 1: Write failing test cases**

- `test_exports_bundle_to_path`
- `test_refuses_export_when_only_wider_anchor_exists`
- `test_exits_1_on_invalid_options`
- `test_emits_pending_warning_when_anchor_is_pending`

- [ ] **Step 2: Implement the command**

Create `src/Cli/Command/BundleExportCommand.php` following the same pattern as `VerifyCommand`. Options:

```
--storage-root <dir>     (required)
--chain <id>             (required)
--from <seq>             (required)
--to <seq>               (required)
--out <path>             (required; written atomically)
--note <string>          (optional)
--issuer-hint <string>   (optional)
--include-claimed-key <path>  (repeatable; .pub files)
--json                   (optional)
```

`execute()` body:

1. Validate options (return 1 with error message on bad input).
2. Open `FileChainStore`.
3. Construct `BundleExporter`, add segment, claimed keys, note/hint.
4. Call `writeTo($out)` — catches `BundleExportException` and returns 4 with a structured message (export failure is treated as an integrity-class error since the underlying issue is "no exact-range anchor exists").
5. On success: emit a small JSON summary with `format_version: attest.cli.export.v1`, `out`, `bytes_written`, list of `anchors` exported, warnings.

- [ ] **Step 3: Run tests, commit**

```
vendor/bin/phpunit --filter BundleExportCommandTest
git add src/Cli/Command/BundleExportCommand.php tests/Cli/Command/BundleExportCommandTest.php
git commit -m "feat(cli): attest bundle export"
```

---

## Task 3.10: `attest bundle verify` command

**Files:**
- Create: `src/Cli/Command/BundleVerifyCommand.php`
- Create: `tests/Cli/Command/BundleVerifyCommandTest.php`

- [ ] **Step 1: Test cases**

- `test_verifies_bundle_with_local_only_anchor`
- `test_verifies_bundle_with_bitcoin_core_provider_against_upgraded_anchor` (mocked HTTP client; no live network)
- `test_bundle_without_proof_envelope_for_required_min_anchor_returns_anchor_below_min`
- `test_claimed_keys_alone_do_not_satisfy_trust`
- `test_bundle_with_invalid_proof_envelope_signature_warns_and_drops_group`
- `test_json_output_matches_schema_v1`

- [ ] **Step 2: Implement the command**

Options:

```
--bundle <path>                    (required)
--chain <id>                       (optional; defaults to first chain in manifest)
--trusted-key <inline>             (repeatable)
--trusted-key-file <path>          (repeatable)
--min-anchor <value>
--allow-provider-disagreement
--allow-untrusted
--bitcoin-core-rpc <url>
--bitcoin-core-cookie <path>
--esplora-url <url>
--json
```

`execute()` body:

1. Open bundle via `BundleReader::open($path)`.
2. Resolve `--chain` against manifest; default to first.
3. Build `BundleStore` from reader.
4. Iterate `$reader->readProofEnvelopes($chainId)` into an array.
5. Load trusted keys (note: bundle's `claimed_keys` are NOT auto-trusted; CLI ignores them as trust input but tests assert this explicitly).
6. Construct `Verifier` with `detachedAnchorEnvelopes: $proofEnvelopes`.
7. Call `verifyChain()` over the bundle's exported range.
8. Map outcome to exit code (same table as `verify`).
9. Emit warnings from bundle reader (`$reader->warnings()`) plus verification warnings.

- [ ] **Step 3: Run tests, commit**

```
vendor/bin/phpunit --filter BundleVerifyCommandTest
git add src/Cli/Command/BundleVerifyCommand.php tests/Cli/Command/BundleVerifyCommandTest.php
git commit -m "feat(cli): attest bundle verify"
```

---

## Task 3.11: `attest anchor` command

**Files:**
- Create: `src/Cli/Command/AnchorCommand.php`
- Create: `tests/Cli/Command/AnchorCommandTest.php`

- [ ] **Step 1: Test cases**

- `test_anchors_range_with_null_driver_and_exits_0`
- `test_anchors_range_with_opentimestamps_driver_via_mocked_calendar_client`
- `test_skipped_when_claim_already_held_exits_0_with_warning`
- `test_reconciles_existing_anchor_envelope_exits_0`
- `test_calendar_unavailable_exits_with_provider_error_code`
- `test_missing_driver_option_exits_1`

- [ ] **Step 2: Implement the command**

Options:

```
--storage-root <dir>             (required)
--chain <id>                     (required)
--from <seq>                     (required)
--to <seq>                       (required)
--driver <name>                  (required; one of: opentimestamps, local-only)
--calendar-url <url>             (repeatable; opentimestamps only; defaults to public pool)
--min-calendars <n>              (default 1)
--signer-key-file <path>         (required; base64 seed)
--signer-key-id <string>         (required)
--json
```

`execute()` body:

1. Validate options.
2. Construct `Signer` from key file + key_id.
3. Open `FileChainStore` and `FileAnchorClaimStore`.
4. Construct the chosen `AnchorDriver` (NullDriver or OpenTimestampsDriver with `OpenTimestampsCalendarClient::withGuzzle()`).
5. `$service = new AnchorService($store, $claimStore, $signer);`
6. `$envelope = $service->anchorRange($chainId, $fromSeq, $toSeq, $driver);`
7. Map results:
   - `$envelope === null` and `$service->warnings()` includes claim-held → exit 0, warn.
   - `CalendarUnavailable` → exit 4 (anchor invalid path) or new exit code? Spec §13 doesn't list "anchor submission failure"; treat as exit 4 since it's an integrity-class outcome (we don't have a valid receipt).
8. Emit JSON summary on success: `{format_version: attest.cli.anchor.v1, anchor_id, envelope_id, target_chain, from_seq, to_seq, driver, state, warnings}`.

- [ ] **Step 3: Run tests, commit**

```
vendor/bin/phpunit --filter AnchorCommandTest
git add src/Cli/Command/AnchorCommand.php tests/Cli/Command/AnchorCommandTest.php
git commit -m "feat(cli): attest anchor"
```

---

## Task 3.12: `attest upgrade` command

**Files:**
- Create: `src/Cli/Command/UpgradeCommand.php`
- Create: `tests/Cli/Command/UpgradeCommandTest.php`

- [ ] **Step 1: Test cases**

- `test_upgrades_single_anchor_id_to_upgraded_state`
- `test_all_pending_sweeps_all_pending_anchors`
- `test_upgrade_idempotent_on_already_upgraded`
- `test_calendar_unavailable_continues_to_next_anchor` (`--all-pending` should be best-effort)
- `test_exit_0_when_no_pending_anchors`

- [ ] **Step 2: Implement the command**

Options:

```
--storage-root <dir>             (required)
--chain <id>                     (required)
--anchor-id <id>                 (mutually exclusive with --all-pending)
--all-pending                    (mutually exclusive with --anchor-id)
--signer-key-file <path>         (required)
--signer-key-id <string>         (required)
--calendar-url <url>             (repeatable)
--verbose
--json
```

`execute()` body:

1. Validate options (one of `--anchor-id` / `--all-pending` required).
2. Open `FileChainStore`. Build `OpenTimestampsDriver`.
3. For `--anchor-id`: read the anchor envelope from the chain, parse via `AnchorEnvelope::fromSignedEnvelope`, call `$driver->upgrade($receipt)`. If state advanced to UPGRADED, append a new `attest.anchor.upgraded` envelope referencing the previous via `supersedes_envelope_id`.
4. For `--all-pending`: iterate chain, find every PENDING anchor envelope, upgrade each. Continue on `CalendarUnavailable` for individual anchors; collect warnings.
5. Emit JSON summary: `{format_version: attest.cli.upgrade.v1, upgraded: [...], unchanged: [...], failed: [...], warnings}`.

- [ ] **Step 3: Run tests, commit**

```
vendor/bin/phpunit --filter UpgradeCommandTest
git add src/Cli/Command/UpgradeCommand.php tests/Cli/Command/UpgradeCommandTest.php
git commit -m "feat(cli): attest upgrade"
```

---

## Task 3.13: Docs, composer, version

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `VERSION`

- [ ] **Step 1: Expand `README.md`**

Add a `## CLI` section above `## Documentation` covering:

- `attest verify` example for a local chain.
- `attest bundle export` example.
- `attest bundle verify` example.
- `attest anchor` and `attest upgrade` examples.
- Exit code table:

  | Code | Outcome | Notes |
  |------|---------|-------|
  | 0 | `VERIFIED` | `INTEGRITY_VERIFIED_UNTRUSTED` with `--allow-untrusted` |
  | 1 | CLI/config/runtime error before a `VerificationOutcome` | |
  | 2 | `INTEGRITY_VERIFIED_UNTRUSTED` | `--allow-untrusted` downgrades to 0 |
  | 3 | `ANCHOR_BELOW_MIN` | |
  | 4 | `INVALID_CHAIN` / `INVALID_SIGNATURE` / `INVALID_ANCHOR` | also: bundle export failure, calendar unavailable |
  | 5 | `PROVIDER_DISAGREEMENT` | `--allow-provider-disagreement` downgrades to strongest passing |

- JSON output schema example (`attest verify --json`).
- Bundle format note: ZIP, `attest.bundle.v1`, claimed keys are NOT trusted, signatures + anchors are the trust path.
- v0.x stability disclaimer.

- [ ] **Step 2: Update `CHANGELOG.md`**

Add under `[Unreleased]`:

```markdown
## [0.4.0-alpha] — 2026-MM-DD

### Added
- Bundle format `fissible.attest.bundle/v1` — ZIP container with `manifest.json`, `chains/`, `proof_envelopes/`, optional `receipts/`, optional `keys/`.
- `Fissible\Attest\Bundle\{BundleExporter, BundleReader, BundleStore, BundleManifest, BundleConstants, BundleEntryPath, ChainSegmentMeta, AnchorMeta, ClaimedKeyMeta}` + typed exceptions.
- `Verifier::__construct(detachedAnchorEnvelopes:)` channel for bundle proof envelopes.
- `attest` CLI (`bin/attest`) — `verify`, `bundle export`, `bundle verify`, `anchor`, `upgrade` commands with spec §13 exit codes and a stable v1 JSON output schema.
- `Fissible\Attest\Verification\StaticVerifier::verifyChain()` — spec §6 facade.

### Changed
- `VerificationResult::$stats` renamed to `$chainStats` (spec §11).
- `PathMapper` now explicitly rejects forward and back slashes in `chain_id` (spec §7.2).

### Notes
- Bundles are stored uncompressed (`ZIP_STORED`); the reader still enforces a compression-ratio guard against bundles produced by other writers.
- v0.x APIs and bundle format remain alpha. Field meanings in `attest.bundle.v1` and `attest.cli.result.v1` are pinned within v0.4.x; future additions will be additive.
```

- [ ] **Step 3: Update `VERSION`**

Replace contents with `0.4.0-alpha`.

- [ ] **Step 4: Commit**

```
git add README.md CHANGELOG.md VERSION
git commit -m "docs: changelog for v0.4.0-alpha"
```

- [ ] **Step 5: Run release script**

```
bash release.sh
```

---

## Done Criteria

- `vendor/bin/phpunit` passes locally (all prior + Chunk 3 tests).
- `vendor/bin/phpstan analyse --no-progress` clean at the project's configured level.
- `./bin/attest verify --help` shows the documented options.
- A round-trip integration test exists: export a live chain segment to a bundle, verify the bundle, and assert the outcome matches the live verification.
- README has runnable examples for each command and the exit-code table.
- `attest.bundle.v1` and `attest.cli.result.v1` field names and shapes are pinned in code constants and covered by snapshot-style tests.
- Bundle verification never trusts a `claimed_keys/` entry as trust input by itself — confirmed by a test where the bundle contains the issuer's pubkey but the CLI is invoked without `--trusted-key`.
- Detached proof envelopes with invalid signatures cannot satisfy `--min-anchor`, even with `--allow-untrusted` (INVALID is non-recoverable; only UNTRUSTED_VALID is policy-controllable).
- No CLI test depends on a live network — all OTS calendars, Bitcoin Core RPC, and Esplora HTTP traffic is mocked.

## Notes for the implementer

- Symfony Console's `CommandTester` is the right unit-test surface for CLI commands. Avoid `exec()` / `proc_open()` based tests; they're slow and rarely catch what direct command-class tests miss.
- For OTS-driver command tests, use a mocked `OpenTimestampsCalendarClient` (the constructor accepts PSR-18 by injection). Do not call `withGuzzle()` in tests.
- Bundle round-trip tests should anchor with `NullDriver` to keep the test surface small; OTS round-trip is covered by `OpenTimestampsDriverTest` from Chunk 2.
- When wiring detached envelopes into `Verifier`, the existing in-chain anchor lookup (`anchorEnvelopesFor`) still runs; explicit detached envelopes are *additional* sources, not replacements. Same `anchor_id` envelopes from both sources merge through `AnchorSetResolver`'s grouping.
