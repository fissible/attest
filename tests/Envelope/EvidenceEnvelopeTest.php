<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Envelope\EvidenceEnvelope;
use PHPUnit\Framework\TestCase;

final class EvidenceEnvelopeTest extends TestCase
{
    public function test_constructs_with_required_fields(): void
    {
        $env = new EvidenceEnvelope(
            id: '01H123456789',
            chain: 'tenant:5',
            seq: 1,
            ts: '2026-05-25T14:32:11.123Z',
            type: 'cms.entry.published',
            payload: ['entry_id' => 42],
            prevHash: null,
            keyId: 'test-key',
            sigAlg: 'ed25519',
        );
        $this->assertSame(1, $env->seq);
        $this->assertNull($env->prevHash);
        $this->assertSame('tenant:5', $env->chain);
        $this->assertSame(1, $env->v);
    }

    public function test_to_unsigned_array_includes_all_fields_except_sig(): void
    {
        $env = new EvidenceEnvelope(
            id: '01H123456789',
            chain: 'tenant:5',
            seq: 1,
            ts: '2026-05-25T14:32:11.123Z',
            type: 'cms.entry.published',
            payload: ['entry_id' => 42],
            prevHash: null,
            keyId: 'test-key',
            sigAlg: 'ed25519',
        );
        $arr = $env->toUnsignedArray();
        $this->assertArrayNotHasKey('sig', $arr);
        $this->assertArrayHasKey('v', $arr);
        $this->assertSame(1, $arr['v']);
        $this->assertSame('01H123456789', $arr['id']);
        $this->assertSame('tenant:5', $arr['chain']);
        $this->assertSame(1, $arr['seq']);
        $this->assertSame('2026-05-25T14:32:11.123Z', $arr['ts']);
        $this->assertNull($arr['prev_hash']);
    }

    public function test_optional_fields_omitted_when_null(): void
    {
        $env = new EvidenceEnvelope(
            id: '01H',
            chain: 'c',
            seq: 1,
            ts: '2026-05-25T14:32:11Z',
            type: 't',
            payload: [],
            prevHash: null,
            keyId: 'k',
            sigAlg: 'ed25519',
            subject: null,
            correlation: null,
            tenant: null,
        );
        $arr = $env->toUnsignedArray();
        $this->assertArrayNotHasKey('subject', $arr);
        $this->assertArrayNotHasKey('correlation', $arr);
        $this->assertArrayNotHasKey('tenant', $arr);
    }

    public function test_optional_fields_included_when_set(): void
    {
        $env = new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 1, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: [], prevHash: null, keyId: 'k', sigAlg: 'ed25519',
            subject: 'entry:42', correlation: 'req_abc', tenant: 'tenant:5',
        );
        $arr = $env->toUnsignedArray();
        $this->assertSame('entry:42', $arr['subject']);
        $this->assertSame('req_abc', $arr['correlation']);
        $this->assertSame('tenant:5', $arr['tenant']);
    }

    public function test_rejects_zero_or_negative_seq(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new EvidenceEnvelope(
            id: '01H', chain: 'c', seq: 0, ts: '2026-05-25T14:32:11Z',
            type: 't', payload: [], prevHash: null, keyId: 'k', sigAlg: 'ed25519',
        );
    }
}
