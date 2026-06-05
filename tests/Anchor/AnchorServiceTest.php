<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor;

use Fissible\Attest\Anchor\AnchorClaim;
use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\AnchorId;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Chain\AppendContext;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\SignedEnvelope;
use Fissible\Attest\Merkle\MerkleTree;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\Warning;
use PHPUnit\Framework\TestCase;

final class AnchorServiceTest extends TestCase
{
    private string $root;
    private FileChainStore $store;
    private FileAnchorClaimStore $claimStore;
    private SodiumSigner $signer;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-anchor-service-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
        $this->store = new FileChainStore($this->root);
        $this->claimStore = new FileAnchorClaimStore($this->root);
        $this->signer = new SodiumSigner(KeyPair::generate(), 'test-key');
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->root);
    }

    public function test_anchor_range_appends_anchor_envelope_and_completes_claim(): void
    {
        $chain = $this->chain();
        $first = $chain->record('t1', ['n' => 1]);
        $second = $chain->record('t2', ['n' => 2]);
        $third = $chain->record('t3', ['n' => 3]);
        $service = $this->service();

        $anchor = $service->anchorRange('tenant:5', 1, 3, new NullDriver());

        $this->assertInstanceOf(SignedEnvelope::class, $anchor);
        $this->assertSame(AnchorEnvelope::SUBMITTED_TYPE, $anchor->envelope->type);
        $root = MerkleTree::rootHex([
            $first->signedCanonicalBytes(),
            $second->signedCanonicalBytes(),
            $third->signedCanonicalBytes(),
        ]);
        $this->assertSame($root, $anchor->envelope->payload['root']);
        $this->assertSame('tenant:5', $anchor->envelope->payload['target_chain']);
        $this->assertSame(1, $anchor->envelope->payload['from_seq']);
        $this->assertSame(3, $anchor->envelope->payload['to_seq']);
        $this->assertSame(NullDriver::NAME, $anchor->envelope->payload['driver']);
        $this->assertSame('base64:', $anchor->envelope->payload['receipt_bytes']);
        $this->assertSame([], iterator_to_array($this->claimStore->reclaimExpired(0)));
    }

    public function test_duplicate_anchor_range_reconciles_existing_anchor_without_appending(): void
    {
        $chain = $this->chain();
        $chain->record('t1', []);
        $chain->record('t2', []);
        $service = $this->service();

        $first = $service->anchorRange('tenant:5', 1, 2, new NullDriver());
        $second = $service->anchorRange('tenant:5', 1, 2, new NullDriver());

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertSame($first->envelope->id, $second->envelope->id);
        $anchorCount = 0;
        foreach ($this->store->readRange('tenant:5', 1) as $envelope) {
            if (str_starts_with($envelope->envelope->type, 'attest.anchor.')) {
                $anchorCount++;
            }
        }
        $this->assertSame(1, $anchorCount);
    }

    public function test_crash_window_claim_is_completed_when_matching_anchor_envelope_exists(): void
    {
        $chain = $this->chain();
        $chain->record('t1', []);
        $chain->record('t2', []);
        $raw = iterator_to_array($this->store->readRawRange('tenant:5', 1, 2), false);
        $target = new AnchorTarget('tenant:5', 1, 2, MerkleTree::ALGORITHM, MerkleTree::rootHex($raw));
        $receipt = (new NullDriver())->anchor($target);
        $anchorId = AnchorId::derive($target, NullDriver::NAME);
        $this->assertTrue($this->claimStore->claim($anchorId, new AnchorClaim(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: 2,
            driver: NullDriver::NAME,
            claimedBy: 'test',
            claimedAtIso8601: '2000-01-01T00:00:00.000Z',
        )));
        $manualAnchor = $chain->record(AnchorEnvelope::SUBMITTED_TYPE, AnchorEnvelope::submittedPayload($receipt));

        $reconciled = $this->service()->anchorRange('tenant:5', 1, 2, new NullDriver());

        $this->assertNotNull($reconciled);
        $this->assertSame($manualAnchor->envelope->id, $reconciled->envelope->id);
        $this->assertArrayNotHasKey($anchorId, iterator_to_array($this->claimStore->reclaimExpired(0)));
    }

    public function test_non_raw_store_emits_recomputed_bytes_warning(): void
    {
        $chain = $this->chain();
        $chain->record('t1', []);
        $store = new class ($this->store) implements ChainStore {
            public function __construct(private readonly ChainStore $inner)
            {
            }

            public function append(string $chainId, callable $buildAndSign): SignedEnvelope
            {
                return $this->inner->append($chainId, $buildAndSign);
            }

            public function tail(string $chainId): ?SignedEnvelope
            {
                return $this->inner->tail($chainId);
            }

            public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
            {
                yield from $this->inner->readRange($chainId, $fromSeq, $toSeq);
            }

            public function listChains(): iterable
            {
                yield from $this->inner->listChains();
            }

            public function exists(string $chainId): bool
            {
                return $this->inner->exists($chainId);
            }
        };
        $service = new AnchorService($store, $this->claimStore, $this->signer, claimedBy: 'test');

        $service->anchorRange('tenant:5', 1, 1, new NullDriver());

        $warnings = $service->warnings();
        $this->assertCount(1, $warnings);
        $this->assertSame(Warning::ANCHOR_OVER_RECOMPUTED_BYTES, $warnings[0]->code);
    }

    private function chain(): EvidenceChain
    {
        return EvidenceChain::open($this->store, 'tenant:5', $this->signer);
    }

    private function service(): AnchorService
    {
        return new AnchorService($this->store, $this->claimStore, $this->signer, claimedBy: 'test');
    }

    private function removeDir(string $path): void
    {
        if (! is_dir($path)) {
            return;
        }
        $entries = scandir($path);
        if ($entries === false) {
            return;
        }
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $child = $path . '/' . $entry;
            if (is_dir($child)) {
                $this->removeDir($child);
            } else {
                @unlink($child);
            }
        }
        @rmdir($path);
    }
}

