# fissible/attest - Chunk 2 Implementation Plan

> OpenTimestamps anchoring + Bitcoin header providers + verifier state machine.

**Goal:** Move `fissible/attest` from local tamper-evident chains to publicly anchored proofs: batch chain segments into RFC 6962 Merkle roots, submit those roots through OpenTimestamps calendars, upgrade receipts when Bitcoin attestations become available, and verify chains against trusted keys, anchor receipts, and active Bitcoin headers.

**Scope:** `~/lib/fissible/attest` only. Laravel storage/jobs, bundle export, and CLI commands stay in later chunks, but this chunk defines library-level equivalents of the future `--min-anchor` and `--allow-provider-disagreement` CLI options.

**Source spec:** Station doc `docs/superpowers/specs/2026-05-25-fissible-attest-design.md`, especially sections 5.2 and 8-11.

**External protocol notes checked before planning:**
- OpenTimestamps calendars expose `/digest` submission and `/timestamp/{commitment}` upgrade endpoints using `application/vnd.opentimestamps.v1`.
- OTS detached timestamp files bind an initial digest plus a timestamp operation tree. Calendar submissions should use a nonced commitment derived from the root, not the raw root.
- OTS Bitcoin attestations record block height, not block hash. Header providers therefore need height-based lookup.
- Bitcoin Core `getblockheader` reports `confirmations = -1` when a block is not on the main chain.
- Esplora exposes `/block-height/:height`, `/block/:hash`, `/block/:hash/status`, and `/blocks/tip/height`; active-chain proof requires more than parsing a header.

**To validate against a real fixture before coding Task 2.5:**
- OTS varuint encoding is unsigned little-endian base128 (LEB128), per `opentimestamps/core/serialize.py` `read_varuint` / `write_varuint`. Generate a known proof with the reference client and confirm byte-identical round-trip in a scratch test before locking the codec — the policy here is "validate IO/wire-format claims against a real fixture, not theoretical reasoning."

---

## Assumed from Chunk 1

These symbols are referenced throughout this plan and must exist in the repo before Chunk 2 starts. If any are missing, add them to Chunk 1 (or a Chunk 1.5) rather than smuggling them into Chunk 2:

- `Fissible\Attest\Canonical\JcsEncoder::encode()` — RFC 8785 JCS encoder. Used for `AnchorId::derive()`.
- `Fissible\Attest\Chain\EvidenceChain::record()` — appends a signed envelope to a chain under lock.
- `Fissible\Attest\Envelope\SignedEnvelope::signedCanonicalBytes()` / `unsignedCanonicalBytes()` — canonical byte forms used for signing and byte-identity verification.
- `Fissible\Attest\Chain\PathMapper::anchorClaimsDir($chainId)` — filesystem path for per-chain anchor claim directories. **Note:** add this method to the existing `PathMapper` if it isn't already present.
- `Fissible\Attest\Chain\ChainStore::readRange($chainId, $fromSeq, $toSeq)` — yields decoded `SignedEnvelope` instances for `[fromSeq, toSeq]`. Does not return raw bytes; see Task 2.7 and Task 2.12 for the raw-bytes path.
- `Fissible\Attest\Chain\FileChainStore` — concrete `ChainStore` with flock-protected append.

If a symbol does not exist at all, stop and escalate before extending Chunk 2.

### Open questions resolved

The three open questions at the end of the original draft are now decided:

1. **`SUBMITTED` stays in `ProofState`.** It is the persisted state for `NullDriver` and the transient return for OTS submission. The enum comment is updated accordingly.
2. **`RawChainStore` is an optional capability interface,** not part of the core `ChainStore` contract. `FileChainStore` implements both. `Verifier` checks for it with `instanceof` and falls back to `SignedEnvelope::signedCanonicalBytes()` byte recomputation when raw bytes are unavailable.
3. **Exact-range anchoring is the only v1 verification path** for a single anchor. Full-chain verification walks contiguous anchors (see Task 2.13). Subset/inclusion proofs remain deferred.

---

## Design Corrections Before Code

### 1. Header provider lookup must be height-based

The current spec sketches:

```php
public function getActiveChainHeader(string $blockHash): ?ActiveChainHeader;
```

That is not enough for OpenTimestamps. `BitcoinBlockHeaderAttestation` carries a block height and the transformed digest that must equal the Bitcoin block header Merkle root. It does not carry the block hash. Chunk 2 should implement:

```php
interface BlockHeaderProvider
{
    public function name(): string;
    public function trustLevel(): TrustLevel;
    public function getActiveChainHeaderByHeight(int $height): HeaderLookupResult;
}
```

`HeaderLookupResult` must distinguish:
- `active` - provider returned an active-chain header.
- `not_found_or_behind` - provider cannot yet answer that height.
- `provider_error` - transport/auth/rate-limit/unparseable response.

Do not collapse these into `?ActiveChainHeader`; verifier disagreement logic needs hard success, hard mismatch, and soft unknown to be separate.

### 2. OTS receipt verification belongs in the driver

The spec's `AnchorDriver` has `anchor()`, `upgrade()`, and `supports()`, but verifier/bundle sections say receipt bytes are fed to the driver for verification. Chunk 2 should add a verification method:

```php
interface AnchorDriver
{
    public function name(): string;
    public function anchor(AnchorTarget $target): AnchorReceipt;
    public function upgrade(AnchorReceipt $receipt): AnchorReceipt;
    public function verify(AnchorReceipt $receipt, HeaderProviderSet $headers): AnchorVerification;
    public function supports(AnchorReceipt $receipt): bool;
}
```

This keeps OTS proof parsing, OTS state derivation, and Bitcoin-attestation validation behind the OTS driver boundary.

### 3. Persisted state is not verified state

Persisted anchor envelopes record what the receipt contains:

```php
enum ProofState: string
{
    case SUBMITTED = 'submitted'; // NullDriver only; or transient OTS return before pending classification
    case PENDING = 'pending';     // receipt has pending calendar attestations, no Bitcoin attestation
    case UPGRADED = 'upgraded';   // receipt contains at least one Bitcoin block-header attestation
}
```

Verifier outcomes are reader-side and never persisted:

```php
enum AnchorOutcome: string
{
    case LOCAL_ONLY = 'local_only';
    case PENDING = 'pending';
    case UPGRADED_NO_HEADERS = 'upgraded_no_headers';
    case REMOTE_HEADER_CONFIRMED = 'remote_header_confirmed';
    case BITCOIN_VERIFIED = 'bitcoin_verified';
    case PROVIDER_DISAGREEMENT = 'provider_disagreement';
    case INVALID = 'invalid';
}
```

### 4. `--min-anchor` is a policy rank, not a state

Library policy should expose:

```php
final readonly class VerificationPolicy
{
    public function __construct(
        public ?AnchorOutcome $minAnchorOutcome = null,
        public bool $allowProviderDisagreement = false,
        public bool $requireTrustedKey = true,
    ) {}
}
```

Strength order:

```text
LOCAL_ONLY < PENDING < UPGRADED_NO_HEADERS < REMOTE_HEADER_CONFIRMED < BITCOIN_VERIFIED
```

`PROVIDER_DISAGREEMENT` and `INVALID` are terminal states, not ranks. The future CLI maps `--min-anchor pending` to `AnchorOutcome::PENDING`, `--min-anchor bitcoin_verified` to `AnchorOutcome::BITCOIN_VERIFIED`, etc.

---

## Chunk 2 Task List

All tasks happen in `~/lib/fissible/attest`.

Suggested branch grouping:
- `feat/merkle-and-anchor-models`
- `feat/opentimestamps-driver`
- `feat/header-providers`
- `feat/verifier-state-machine`

Each task should land with PHPUnit coverage and PHPStan clean.

### Task 2.1: Add RFC 6962 Merkle primitives

**Files:**
- Create: `src/Merkle/MerkleTree.php`
- Create: `src/Merkle/InclusionProof.php`
- Create: `tests/Merkle/MerkleTreeTest.php`
- Create: `tests/Merkle/vectors/sha256-rfc6962.json`

**Rules:**
- Leaf hash: `sha256(0x00 || signed_canonical_envelope_bytes)`.
- Node hash: `sha256(0x01 || left || right)`.
- Odd leaf promotion: promote the unmatched node unchanged. Do not duplicate Bitcoin-style.
- Root over a chain batch is ordered by `(chain_id, seq)` ascending. For a single-chain batch this is just sequence order.

**Acceptance tests:**
- 1, 2, 3, 4, 5, 7, 8, and 1000 leaves have stable fixture roots.
- Mutating any input byte changes the root.
- Odd-leaf promotion differs from Bitcoin-style duplicate-leaf hashing.
- `MerkleTree::rootHex([])` throws `InvalidArgumentException`.

### Task 2.2: Add anchor value objects and anchor-id derivation

**Files:**
- Create: `src/Anchor/AnchorTarget.php`
- Create: `src/Anchor/AnchorId.php`
- Create: `src/Anchor/AnchorReceipt.php`
- Create: `src/Anchor/ProofState.php`
- Create: `src/Anchor/AnchorOutcome.php`
- Create: `tests/Anchor/AnchorIdTest.php`
- Create: `tests/Anchor/AnchorReceiptTest.php`

**Model:**

```php
final readonly class AnchorTarget
{
    public function __construct(
        public string $chainId,
        public int $fromSeq,
        public int $toSeq,
        public string $merkleAlgorithm,
        public string $rootHex,
    ) {}
}
```

`AnchorId::derive()` must exactly implement:

```php
sha256(JcsEncoder::encode([
    'attest-anchor-v1',
    $chainId,
    $fromSeq,
    $toSeq,
    $driver,
    $rootHex,
]))
```

**Acceptance tests:**
- Opaque chain IDs with `:` `/` `|` and Unicode-like byte sequences cannot collide by delimiter tricks.
- Changing any tuple component changes the ID.
- Invalid ranges (`from_seq < 1`, `to_seq < from_seq`) throw.
- Roots are lower-case 64-char hex.

### Task 2.3: Add anchor envelope payload builder/parser

**Files:**
- Create: `src/Anchor/AnchorEnvelope.php`
- Create: `src/Anchor/InvalidAnchorEnvelope.php`
- Create: `tests/Anchor/AnchorEnvelopeTest.php`

**Responsibilities:**
- Build payloads for `attest.anchor.submitted` and `attest.anchor.upgraded`.
- Parse signed envelopes back into `AnchorReceipt` only when:
  - type is `attest.anchor.submitted` or `attest.anchor.upgraded`;
  - payload has `anchor_id`, `target_chain`, `from_seq`, `to_seq`, `merkle_algorithm`, `root`, `driver`, `state`, `receipt_bytes`;
  - `anchor_id` re-derives from the payload tuple;
  - `receipt_bytes` is `base64:` encoded raw bytes.

**Acceptance tests:**
- Round-trip submitted and upgraded payloads.
- Mismatched `anchor_id` is rejected.
- Missing or non-string receipt bytes are rejected.
- `state=verified` is rejected; verification is never persisted.

### Task 2.4: Add `AnchorClaimStore` and file implementation

**Files:**
- Create: `src/Anchor/AnchorClaim.php`
- Create: `src/Anchor/AnchorClaimStore.php`
- Create: `src/Anchor/FileAnchorClaimStore.php`
- Create: `tests/Anchor/AnchorClaimStoreContractTests.php`
- Create: `tests/Anchor/FileAnchorClaimStoreTest.php`

**File layout:**
- Use existing `PathMapper::anchorClaimsDir($chainId)`.
- One claim directory per `anchor_id`, created by atomic `mkdir()`.
- Claim metadata file inside the directory: `claim.json`.
- Completion marker: update metadata atomically with `completed_at` and `completed_envelope_id`.

**Semantics:**
- `claim()` returns false if another worker already owns the active claim.
- `release()` removes an incomplete claim.
- `complete()` is idempotent if the same envelope ID is supplied.
- `reclaimExpired($ttlSeconds)` yields expired incomplete claims.

**Crash reconciliation:**
- The claim store cannot scan chain contents by itself. Implement reconciliation in Task 2.7's service: before re-anchoring an expired claim, scan chain envelopes for matching `anchor_id` and call `complete()` if found.
- The scan must be bounded. The anchor envelope is always appended at a seq strictly greater than the claim's `to_seq`. Reconciliation reads `ChainStore::readRange($chainId, $claim->toSeq + 1, null)` and stops at the first matching `anchor_id` or end of chain. O(envelopes appended since the claim was taken), not O(chain size).

### Task 2.5: Add OpenTimestamps proof codec

**Files:**
- Create: `src/Anchor/OpenTimestamps/OpenTimestampsProof.php`
- Create: `src/Anchor/OpenTimestamps/OpenTimestampsCodec.php`
- Create: `src/Anchor/OpenTimestamps/OpenTimestampsAttestation.php`
- Create: `src/Anchor/OpenTimestamps/OpenTimestampsOperation.php`
- Create: `tests/Anchor/OpenTimestamps/OpenTimestampsCodecTest.php`
- Create: `tests/Anchor/OpenTimestamps/fixtures/`

**Minimum supported format:**
- Detached timestamp file magic/version.
- File hash op: SHA-256.
- Timestamp operation tree with:
  - append
  - prepend
  - sha256
  - attestation markers
  - fork marker
- Attestations:
  - Pending attestation with calendar URI.
  - Bitcoin block-header attestation with height.
  - Unknown attestation is preserved during round-trip but ignored for verification.

**Protocol constants to implement:**
- Detached file magic: `00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73 00 00 50 72 6f 6f 66 00 bf 89 e2 e8 84 e8 92 94`.
- Major version: `1`.
- Fork marker: `ff`.
- Attestation marker: `00`.
- Operation tags:
  - `08` = `sha256`
  - `f0` = `append` with varbytes argument
  - `f1` = `prepend` with varbytes argument
- Attestation tags:
  - `83 dfe30d2ef90c8e` = pending calendar URI
  - `05 88960d73d71901` = Bitcoin block-header attestation
- Varints: unsigned LEB128 (little-endian base128), matching `write_varuint`/`read_varuint` in `python-opentimestamps/opentimestamps/core/serialize.py`. Confirm byte-identical round-trip against a fixture generated by the reference client before locking the codec.

**Security limits:**
- Max receipt bytes: 1 MB default.
- Max operation tree recursion/depth: 256.
- Max attestation payload: 8 KB.
- Max pending URI length: 1000 bytes and allowed URI characters matching OTS.
- Reject non-SHA256 detached timestamps for v1.

**Acceptance tests:**
- Serialize/decode/serialize is byte-identical for local fixtures.
- A detached receipt with file digest not equal to `AnchorTarget::rootHex` is invalid.
- Applying the operation tree from root reaches the attested digest.
- Pending-only receipts classify as `ProofState::PENDING`.
- Receipts with a Bitcoin block-header attestation classify as `ProofState::UPGRADED`.

### Task 2.6: Add `OpenTimestampsDriver`

**Files:**
- Create: `src/Anchor/AnchorDriver.php`
- Create: `src/Anchor/NullDriver.php`
- Create: `src/Anchor/OpenTimestampsDriver.php`
- Create: `src/Anchor/OpenTimestamps/OpenTimestampsCalendarClient.php`
- Create: `tests/Anchor/OpenTimestampsDriverTest.php`
- Create: `tests/Anchor/NullDriverTest.php`

**Composer:**
- Add to `require`: `psr/http-client:^1.0`, `psr/http-factory:^1.0`, `psr/http-message:^1.1 || ^2.0`.
- Add to `require-dev`: `guzzlehttp/guzzle:^7.7` and `guzzlehttp/psr7:^2.6` (used as the concrete client in tests).
- Add to `suggest`: `guzzlehttp/guzzle` — "PSR-18 HTTP client suitable for OpenTimestampsCalendarClient."

**Wiring contract:**
- `OpenTimestampsCalendarClient::__construct(ClientInterface $http, RequestFactoryInterface $reqs, StreamFactoryInterface $streams)` — no defaults, no `new Client()` inside the driver. The library does not ship a default HTTP client; consumers inject one (Guzzle, Symfony HttpClient PSR-18 adapter, or any other).
- For convenience in tests and example wiring, provide a static factory `OpenTimestampsCalendarClient::withGuzzle(array $guzzleOptions = []): self` in the same file. The factory uses `class_exists(\GuzzleHttp\Client::class)` and throws a clear `LogicException` if Guzzle is not installed. This is the only place in the library that names Guzzle directly, and it is opt-in.

This keeps `fissible/attest` from forcing Guzzle on downstream packages and makes the calendar client trivially mockable in CI (satisfies the "no network in CI" done-criterion).

**Null driver:**
- No network.
- Returns a receipt for the target root with driver name `local-only`.
- Persists `ProofState::SUBMITTED` because the receipt will never advance to PENDING or UPGRADED (no calendar, no Bitcoin attestation possible).
- `verify()` maps the receipt to `AnchorOutcome::LOCAL_ONLY`.
- Exists primarily for tests, dry-run users, and deployments that want explicit "not publicly anchored" receipts.

**Submission flow:**
1. Start with `Timestamp(rootBytes)` in a detached timestamp file.
2. Add `append(random_bytes(16))`, then `sha256`.
3. Submit the resulting nonced commitment bytes to calendars through `POST /digest`.
4. Merge successful calendar timestamp trees into the detached proof.
5. Require at least `m` successful calendars; default `m=1`.
6. Return an `AnchorReceipt` with `ProofState::PENDING` unless a calendar already returned a Bitcoin attestation.

**Upgrade flow:**
1. Parse existing receipt.
2. For each pending attestation URI that is allowlisted, query `/timestamp/{commitmentHex}`.
3. Merge returned timestamp data.
4. If any Bitcoin block-header attestation is now present, return `ProofState::UPGRADED`.
5. If not, return the original receipt unchanged except for optional metadata.

**Calendar defaults:**
- Defaults should match public OTS pools:
  - `https://a.pool.opentimestamps.org`
  - `https://b.pool.opentimestamps.org`
  - `https://a.pool.eternitywall.com`
  - `https://ots.btc.catallaxy.com`
- Upgrade allowlist should include OTS calendar host patterns. Do not blindly follow arbitrary pending URIs unless explicitly configured.

**Acceptance tests:**
- Driver submits the nonced commitment, not the raw root.
- One successful calendar among several failures succeeds when `minCalendars=1`.
- Fewer than `minCalendars` successful calendars throws a typed exception.
- Upgrade is idempotent.
- Unknown attestation data round-trips.
- Calendar response over size cap is rejected.

### Task 2.7: Add anchor orchestration service

**Files:**
- Create: `src/Chain/RawChainStore.php` (interface defined below; consumed here, again by Task 2.12)
- Modify: `src/Chain/FileChainStore.php` (implement `RawChainStore`)
- Create: `tests/Chain/RawChainStoreTest.php`
- Create: `src/Verification/Warning.php` (introduced here; extended by Tasks 2.12-2.15)
- Create: `src/Anchor/AnchorService.php`
- Create: `src/Anchor/AnchorBatchSelector.php`
- Create: `tests/Anchor/AnchorServiceTest.php`

**`Warning` shape (introduced here, extended by later tasks):**

```php
namespace Fissible\Attest\Verification;

final readonly class Warning
{
    public const ANCHOR_OVER_RECOMPUTED_BYTES = 'anchor_over_recomputed_bytes';
    // Additional codes added by later tasks: NO_RAW_BYTES, ANCHOR_COVERAGE_AMBIGUOUS, etc.

    public function __construct(
        public string $code,
        public string $message,
        /** @var array<string,mixed> */
        public array $context = [],
    ) {}
}
```

Later tasks add codes by adding new `const` entries on this class. Do not create per-warning subclasses.

**`RawChainStore` interface (consumed first here, also referenced by Task 2.12):**

```php
namespace Fissible\Attest\Chain;

interface RawChainStore
{
    /**
     * Yields stored canonical envelope record bytes for [fromSeq, toSeq] in seq order.
     *
     * Each yielded string MUST equal SignedEnvelope::signedCanonicalBytes() for that
     * envelope and MUST NOT contain a trailing newline or any other framing byte.
     * Implementations that store JSONL (e.g. FileChainStore) must strip the "\n"
     * record terminator before yielding.
     *
     * @return iterable<string>
     */
    public function readRawRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable;
}
```

**`FileChainStore::readRawRange()` semantics:**
- Acquire a shared lock (`LOCK_SH`) on the chain's lock file before opening the JSONL file. Release on completion. (`readRange()` is currently unlocked; do not change its behavior in this chunk — `readRawRange()` is the new lock-aware reader path.)
- For each line in `[fromSeq, toSeq]`, yield the line with any trailing `\n` (and `\r`, defensively) stripped.
- Skip empty lines (a torn-write tail would never present a complete envelope; never yield partial bytes).

**`RawChainStoreTest` acceptance tests:**
- After appending N envelopes, `readRawRange($chain, 1, N)` yields exactly N byte strings, each byte-identical to the corresponding `SignedEnvelope::signedCanonicalBytes()` and containing no `\n` or `\r`.
- Sub-ranges return the expected slice.
- A file with a torn final line (no terminator) does not produce a partial record.

**Responsibilities:**
- Select `[from_seq, to_seq]` for a chain batch.
- Obtain signed canonical envelope bytes for each envelope in the range, in seq order. Source preference:
  1. If the configured `ChainStore` implements `RawChainStore` (interface defined below; see also Task 2.12), use `readRawRange()` and feed each yielded byte string directly to the Merkle leaf hash.
  2. Otherwise, call `ChainStore::readRange()` and recompute bytes via `SignedEnvelope::signedCanonicalBytes()`. This is correct because canonical encoding is deterministic, but it loses the "what's actually on disk" guarantee — emit a `Warning::ANCHOR_OVER_RECOMPUTED_BYTES` so operators know the anchor commits to the canonical form, not the stored form.
- Compute Merkle root.
- Derive `anchor_id`.
- Claim work through `AnchorClaimStore`.
- Call the driver outside the chain append lock.
- Append `attest.anchor.submitted` or `attest.anchor.upgraded` envelopes through `EvidenceChain::record()`.
- Mark claims complete after the append.

**Important invariant:**
Network I/O never runs while holding the chain append lock. The only chain lock occurs inside `EvidenceChain::record()` when appending the receipt envelope.

**Acceptance tests:**
- Appends anchor envelope with correct range/root/anchor_id.
- Duplicate concurrent workers produce one completed claim and one anchor envelope.
- Crash window after append but before claim completion is reconciled by scanning for the existing `anchor_id`.
- Re-anchoring an already anchored exact range is idempotent.

### Task 2.8: Add header provider contracts and result model

**Files:**
- Create: `src/Headers/TrustLevel.php`
- Create: `src/Headers/BlockHeaderProvider.php`
- Create: `src/Headers/ActiveChainHeader.php`
- Create: `src/Headers/HeaderLookupResult.php`
- Create: `src/Headers/HeaderProviderSet.php`
- Create: `tests/Headers/HeaderLookupResultTest.php`

**Result model:**

```php
enum HeaderLookupStatus: string
{
    case ACTIVE = 'active';
    case NOT_FOUND_OR_BEHIND = 'not_found_or_behind';
    case PROVIDER_ERROR = 'provider_error';
}
```

`ActiveChainHeader` fields:
- `blockHash`
- `height`
- `confirmations`
- `merkleRoot`
- `timeUnixSec`

**Acceptance tests:**
- `HeaderProviderSet` preserves provider names and trust levels.
- `ACTIVE` requires confirmations >= 1 and 64-char hex hashes.
- Provider errors carry a safe diagnostic string but no credentials.

### Task 2.9: Add Bitcoin Core RPC header provider

**Files:**
- Create: `src/Headers/BitcoinCoreRpcHeaderProvider.php`
- Create: `tests/Headers/BitcoinCoreRpcHeaderProviderTest.php`

**Lookup algorithm:**
1. `getblockcount` to know whether the node is behind the requested height.
2. If `height > blockcount`, return `NOT_FOUND_OR_BEHIND`.
3. `getblockhash(height)`.
4. `getblockheader(hash, true)`.
5. Require `confirmations >= 1`.
6. Return `ACTIVE` with `merkleroot`, `time`, `height`, `hash`, and `confirmations`.

**Auth support:**
- URL with user/pass.
- Explicit username/password.
- Cookie file parser for `.cookie`.

**Acceptance tests:**
- Happy path maps response correctly.
- `confirmations = -1` is not active.
- Node behind height returns `NOT_FOUND_OR_BEHIND`.
- RPC auth failure and malformed JSON return `PROVIDER_ERROR`.
- Diagnostics redact credentials.

### Task 2.10: Add Esplora header provider

**Files:**
- Create: `src/Headers/EsploraHeaderProvider.php`
- Create: `tests/Headers/EsploraHeaderProviderTest.php`

**Lookup algorithm:**
1. `GET /blocks/tip/height`.
2. If `height > tip`, return `NOT_FOUND_OR_BEHIND`.
3. `GET /block-height/{height}` to get the active-chain hash at height.
4. `GET /block/{hash}/status`; require `in_best_chain === true`.
5. `GET /block/{hash}`; read `height`, `merkle_root`, and `timestamp`.
6. Compute confirmations as `tip - height + 1`.

**Defaults:**
- No Esplora provider is configured by default in verifier policy.
- Public base URL may default to `https://blockstream.info/api`, but use should be explicit in application/CLI wiring because it is a remote trust source.

**Acceptance tests:**
- Happy path maps response correctly.
- Tip behind target returns `NOT_FOUND_OR_BEHIND`.
- `in_best_chain=false` returns provider error or non-active status, not success.
- HTTP 429/5xx returns `PROVIDER_ERROR`.
- Invalid base URLs are rejected.

### Task 2.11: Add signature/key verification helpers

**Files:**
- Create: `src/Verification/TrustedKey.php`
- Create: `src/Verification/KeyMatch.php`
- Create: `src/Verification/SignatureVerifier.php`
- Create: `tests/Verification/SignatureVerifierTest.php`

**Responsibilities:**
- Map trusted public keys by `key_id` and/or fingerprint.
- Verify Ed25519 signatures against `unsignedCanonicalBytes()`.
- Report which keys matched.
- Distinguish self-consistent but untrusted signatures from invalid signatures.

**Acceptance tests:**
- Valid trusted signature matches.
- Valid but untrusted signature yields no key match, not invalid signature.
- Tampered payload fails signature verification.
- Unknown `sig_alg` fails explicitly.

### Task 2.12: Add chain verifier core

**Files:**
- Create: `src/Verification/Verifier.php`
- Create: `src/Verification/VerificationPolicy.php`
- Create: `src/Verification/VerificationOutcome.php`
- Create: `src/Verification/VerificationResult.php`
- Create: `src/Verification/ChainStats.php`
- Modify: `src/Verification/Warning.php` (add `NO_RAW_BYTES`; introduced in Task 2.7)
- Create: `tests/Verification/VerifierChainTest.php`

**Chain validation order:**
1. Decode each signed envelope from canonical bytes already provided by the store.
2. Re-encode signed canonical bytes and require byte identity with storage bytes where available. For `FileChainStore::readRange()`, add a raw-read path or verifier store adapter if needed; the current `readRange()` returns value objects only.
3. Validate sequence starts at requested `fromSeq` and increments by one.
4. Validate `prev_hash` equals previous `selfHash()`; genesis must have `prev_hash=null`.
5. Validate `chain` matches requested chain ID.
6. Verify signatures against trusted keys.
7. Collect anchor envelopes for Task 2.13.

**Implementation note — `RawChainStore` is an optional capability interface:**

The interface and `FileChainStore` implementation are introduced in Task 2.7. Here the verifier consumes it.

- `Verifier` checks `$store instanceof RawChainStore`. If yes, it compares each stored canonical record byte string against `SignedEnvelope::signedCanonicalBytes()` of the decoded envelope. If they disagree, the chain is `INVALID_CHAIN` (mutation-without-canonical-difference is detected).
- If no, the verifier falls back to using the recomputed canonical bytes and emits `Warning::NO_RAW_BYTES` so operators know mutation-without-canonical-difference cannot be detected.
- `RawChainStore` is deliberately *not* a sub-interface of `ChainStore` so storages that only support raw streaming can implement it independently.

**Acceptance tests:**
- Valid chain returns chain integrity success.
- Broken sequence returns `INVALID_CHAIN` with `brokenAtSeq`.
- Broken `prev_hash` returns `INVALID_CHAIN`.
- Mutated raw bytes that decode to the same object but are not canonical return `INVALID_CHAIN`.
- Tampered payload returns `INVALID_SIGNATURE`.
- Valid signatures with no trusted key return `INTEGRITY_VERIFIED_UNTRUSTED` unless policy allows untrusted in later CLI mapping.

### Task 2.13: Add anchor verifier and envelope grouping

**Files:**
- Create: `src/Verification/AnchorVerification.php`
- Create: `src/Verification/AnchorSetResolver.php`
- Create: `tests/Verification/AnchorSetResolverTest.php`
- Create: `tests/Verification/VerifierAnchorTest.php`

**Anchor envelope resolution:**
- Scan all `attest.anchor.*` envelopes on the chain.
- Group by `anchor_id`.
- Within each group, require all binding fields to agree:
  - `target_chain`
  - `from_seq`
  - `to_seq`
  - `merkle_algorithm`
  - `root`
  - `driver`
- Pick strongest persisted state: `UPGRADED > PENDING > SUBMITTED`.
- If bindings conflict within a group, mark that anchor group `INVALID`.

**Coverage:**
- An anchor proves exactly `[from_seq, to_seq]`.
- For a single anchor lookup, exact range match is required. Subset/inclusion proofs are deferred to bundle work.
- For a *range* verification request `[req_from, req_to]`, the verifier walks resolved anchor groups in seq order and requires a contiguous tiling:
  - The first group must have `from_seq == req_from`.
  - Each subsequent group's `from_seq` must equal the previous group's `to_seq + 1`.
  - The last group must have `to_seq == req_to`.
  - Every group in the tiling must verify against policy.
- If no contiguous tiling exists, the result is `ANCHOR_BELOW_MIN` (when `minAnchorOutcome !== null`) with a warning naming the first uncovered seq.

**Acceptance tests (add to the list below):**
- Three contiguous anchors covering `[1,400]`, `[401,800]`, `[801,1000]` verify the request `[1,1000]`.
- A gap (`[1,400]`, `[500,1000]`) fails with `ANCHOR_BELOW_MIN` and warning naming seq `401`.
- Overlapping anchors with distinct `anchor_id`s (e.g. `[1,500]` and `[400,1000]`) fail tiling: final outcome is `ANCHOR_BELOW_MIN`, accompanied by `Warning::ANCHOR_COVERAGE_AMBIGUOUS` listing the overlapping anchor IDs. This is distinct from same-`anchor_id` binding conflicts (Task 2.13 "Anchor envelope resolution"), which classify the group itself as `INVALID` and surface as `INVALID_ANCHOR`. The verifier does not try to pick a covering subset from overlapping anchors — operators must reconcile before re-verifying.

**Anchor verification flow:**
1. Recompute Merkle root for the target range.
2. Re-derive `anchor_id`.
3. Match a resolved anchor group by exact range/root/driver.
4. Ask the matching driver to verify receipt bytes.
5. Compare outcome to `VerificationPolicy::$minAnchorOutcome`.

**Acceptance tests:**
- Pending receipt yields `AnchorOutcome::PENDING`.
- Upgraded receipt with no providers yields `UPGRADED_NO_HEADERS`.
- Remote provider success yields `REMOTE_HEADER_CONFIRMED`.
- Local provider success yields `BITCOIN_VERIFIED`.
- Root mismatch yields `INVALID_ANCHOR`.
- Missing exact anchor with `minAnchorOutcome !== null` yields `ANCHOR_BELOW_MIN`.

### Task 2.14: Implement provider-disagreement resolution

**Files:**
- Modify: `src/Anchor/OpenTimestampsDriver.php`
- Modify: `src/Verification/Verifier.php`
- Create: `tests/Verification/ProviderDisagreementTest.php`

**Definitions:**
- `PASS`: provider returns active header at the OTS attested height and the header Merkle root equals the OTS transformed digest.
- `MISMATCH`: provider returns active header at that height but the Merkle root does not equal the OTS transformed digest.
- `UNKNOWN`: provider is behind, unavailable, rate-limited, or returns an indeterminate error.

**Resolution algorithm per OTS Bitcoin attestation:**
1. Query every configured provider. Classify each as `PASS`, `MISMATCH`, or `UNKNOWN`.
2. Record `UNKNOWN` providers as warnings; they do not vote on disagreement.
3. **Cross-provider hash check (must run before trust-level selection):** if any two providers returned an active header at the requested height with different `blockHash` values, return `AnchorOutcome::PROVIDER_DISAGREEMENT` regardless of pass/mismatch state. This is a fork-detection signal and must not be masked by trust-level preference.
4. If at least one provider returned `PASS` and at least one returned `MISMATCH`, return `AnchorOutcome::PROVIDER_DISAGREEMENT`.
5. If no provider passed and at least one mismatched, return `AnchorOutcome::INVALID`.
6. If all providers are `UNKNOWN`, return `AnchorOutcome::UPGRADED_NO_HEADERS`.
7. Otherwise (at least one `PASS`, no `MISMATCH`, no hash conflict): select the strongest passing provider by trust level (`LOCAL` beats `REMOTE`) and map to `BITCOIN_VERIFIED` (LOCAL) or `REMOTE_HEADER_CONFIRMED` (REMOTE).

**Policy handling:**
- Default: `PROVIDER_DISAGREEMENT` makes the whole verification result `VerificationOutcome::PROVIDER_DISAGREEMENT`.
- If `allowProviderDisagreement=true`, downgrade to the strongest passing anchor outcome and attach a warning listing disagreeing provider names.
- If there is no passing provider, `allowProviderDisagreement` cannot rescue the result.

**Acceptance tests:**
- Core PASS + Esplora PASS (same hash) -> `BITCOIN_VERIFIED`.
- Core PASS + Esplora PASS (**different hashes at same height**) -> `PROVIDER_DISAGREEMENT`. This is the regression test for the algorithm-ordering bug; it must run with hash-check enabled.
- Esplora PASS only -> `REMOTE_HEADER_CONFIRMED`.
- Core PASS + Esplora MISMATCH -> `PROVIDER_DISAGREEMENT`.
- Core UNKNOWN + Esplora PASS -> `REMOTE_HEADER_CONFIRMED` with warning.
- Core MISMATCH + Esplora UNKNOWN -> `INVALID_ANCHOR`.
- Allowed disagreement (`allowProviderDisagreement=true`) downgrades to strongest passing outcome and emits warning. Note: a hash-conflict disagreement still cannot be downgraded if there is no agreed-upon passing hash.

### Task 2.15: Enforce min-anchor thresholds

**Files:**
- Modify: `src/Verification/Verifier.php`
- Modify: `src/Verification/VerificationPolicy.php`
- Create: `tests/Verification/MinAnchorThresholdTest.php`

**Rules:**
- `minAnchorOutcome=null`: chain/signature verification may succeed without anchors.
- `LOCAL_ONLY`: local/null anchor is enough.
- `PENDING`: OTS pending receipt is enough.
- `UPGRADED_NO_HEADERS`: receipt must contain a Bitcoin attestation, but no header provider is required.
- `REMOTE_HEADER_CONFIRMED`: at least one remote active-chain provider must pass.
- `BITCOIN_VERIFIED`: at least one local Bitcoin Core provider must pass.

**Outcome precedence:**
1. Invalid chain structure -> `INVALID_CHAIN`.
2. Invalid signature -> `INVALID_SIGNATURE`.
3. Invalid anchor proof -> `INVALID_ANCHOR`.
4. Provider disagreement -> `PROVIDER_DISAGREEMENT` unless explicitly allowed.
5. Anchor exists but is below policy threshold, or no exact anchor exists while threshold is set -> `ANCHOR_BELOW_MIN`.
6. No trusted key match -> `INTEGRITY_VERIFIED_UNTRUSTED`.
7. Otherwise -> `VERIFIED`.

**Acceptance tests:**
- Every threshold has an exactly-on-boundary pass case.
- Every threshold has one-below failure case.
- Provider disagreement is not treated as "below min"; it is a distinct failure.
- Invalid anchor is not treated as "below min"; it is a distinct failure.

### Task 2.16: Update public docs and changelog

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**README additions:**
- Explain local integrity vs public anchoring.
- Show library-level verifier example with:
  - trusted keys
  - OTS driver
  - Bitcoin Core header provider
  - `minAnchorOutcome: AnchorOutcome::BITCOIN_VERIFIED`
- Privacy note: calendars receive nonced commitments, but timing/IP metadata can still link submissions.
- Remote Esplora note: useful convenience, weaker than local Bitcoin Core.

**CHANGELOG additions under `[Unreleased]`:**
- Merkle tree primitives.
- OTS anchor driver.
- File anchor claim store.
- Bitcoin Core and Esplora header providers.
- Verifier with min-anchor policy and provider disagreement handling.

---

## Verifier State Machine Summary

The verifier should compute two layers of result:

1. Chain layer:

```text
raw bytes -> canonical parse -> sequence/prev_hash -> signatures -> trusted-key match
```

2. Anchor layer:

```text
anchor envelopes -> grouped anchor_id -> recomputed root -> receipt driver -> header providers -> min-anchor policy
```

Final outcome precedence is intentionally strict. A strong Bitcoin anchor cannot rescue a broken chain or signature. A locally valid chain cannot claim public anchoring when its receipt is invalid, below threshold, or in provider disagreement.

---

## Done Criteria

- `vendor/bin/phpunit` passes locally.
- PHPStan remains clean.
- Verifier tests cover every `VerificationOutcome`.
- Anchor tests cover pending, upgraded-no-headers, remote-confirmed, local-bitcoin-verified, invalid, below-min, and provider-disagreement.
- No network tests depend on public calendars, public Esplora, or a live Bitcoin node. Use mocked HTTP/RPC providers for CI.
- README and changelog describe anchoring as alpha-quality and make the trust difference between Bitcoin Core and Esplora explicit.

## References

- OpenTimestamps website: https://opentimestamps.org/
- OpenTimestamps client: https://github.com/opentimestamps/opentimestamps-client
- python-opentimestamps protocol implementation: https://github.com/opentimestamps/python-opentimestamps
- Bitcoin Core `getblockheader`: https://developer.bitcoin.org/reference/rpc/getblockheader.html
- Esplora HTTP API: https://github.com/Blockstream/esplora/blob/master/API.md
