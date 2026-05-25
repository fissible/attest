<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Chain;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\InvalidPayload;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class EvidenceChainTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/attest-test-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        @system('rm -rf ' . escapeshellarg($this->root));
    }

    private function chain(): EvidenceChain
    {
        return EvidenceChain::open(
            store: new FileChainStore($this->root),
            chainId: 'tenant:5',
            signer: new SodiumSigner(KeyPair::generate(), 'test-key'),
        );
    }

    public function test_record_returns_signed_envelope(): void
    {
        $chain = $this->chain();
        $env = $chain->record('cms.entry.published', ['entry_id' => 42]);

        $this->assertSame('cms.entry.published', $env->envelope->type);
        $this->assertSame(['entry_id' => 42], $env->envelope->payload);
        $this->assertSame('tenant:5', $env->envelope->chain);
        $this->assertSame(1, $env->envelope->seq);
    }

    public function test_subsequent_records_link_to_previous(): void
    {
        $chain = $this->chain();
        $first = $chain->record('t1', []);
        $second = $chain->record('t2', []);
        $this->assertSame($first->selfHash(), $second->envelope->prevHash);
        $this->assertSame(2, $second->envelope->seq);
    }

    public function test_record_validates_payload(): void
    {
        $chain = $this->chain();
        $this->expectException(InvalidPayload::class);
        $chain->record('bad', ['n' => 1.5]);
    }

    public function test_optional_subject_correlation_tenant_pass_through(): void
    {
        $chain = $this->chain();
        $env = $chain->record(
            type: 'cms.entry.published',
            payload: [],
            subject: 'entry:42',
            correlation: 'req_abc',
            tenant: 'tenant:5',
        );
        $this->assertSame('entry:42', $env->envelope->subject);
        $this->assertSame('req_abc', $env->envelope->correlation);
        $this->assertSame('tenant:5', $env->envelope->tenant);
    }
}
