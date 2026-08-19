<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Output;

use Fissible\Attest\Anchor\AnchorOutcome;
use Fissible\Attest\Anchor\AnchorReceipt;
use Fissible\Attest\Anchor\AnchorTarget;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Cli\Output\JsonResultEmitter;
use Fissible\Attest\Verification\AnchorVerification;
use Fissible\Attest\Verification\ChainStats;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationResult;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

final class JsonResultEmitterTest extends TestCase
{
    /**
     * A verified chain proves the recorded entries are intact. It does not prove they are all the events
     * that happened, and a consumer reading only `verified: true` has no way to learn that from the
     * output. The caveat travels with the data because that is where the wrong inference forms.
     */
    public function test_verification_payload_declares_that_completeness_is_not_asserted(): void
    {
        $result = new VerificationResult(
            outcome: VerificationOutcome::VERIFIED,
            chainStats: new ChainStats('tenant:5', 1, 5, 5, 5, 0, 0),
            warnings: [],
            signatureResults: [],
            anchorVerification: null,
        );

        $output = new BufferedOutput();
        (new JsonResultEmitter())->emit('verify', $result, 0, $output);

        $payload = json_decode($output->fetch(), true);

        self::assertTrue($payload['verified'], 'Precondition: this is the passing case.');
        self::assertFalse(
            $payload['completeness']['asserted'],
            'Integrity verifying must never read as completeness being established.',
        );
        self::assertNotSame('', $payload['completeness']['statement']);
        self::assertSame(
            'attest.cli.result.v1',
            $payload['format_version'],
            'An additive field must not bump the format version; STABILITY.md permits additions within 1.x.',
        );
    }

    /**
     * The block is constant, not computed. attest cannot detect what bypassed instrumentation, so a value
     * that varied with the outcome would imply it had checked something it never checks.
     */
    public function test_completeness_caveat_does_not_vary_with_the_verification_outcome(): void
    {
        $payloads = [];

        foreach ([VerificationOutcome::VERIFIED, VerificationOutcome::INVALID_CHAIN] as $outcome) {
            $output = new BufferedOutput();
            (new JsonResultEmitter())->emit('verify', new VerificationResult(
                outcome: $outcome,
                chainStats: new ChainStats('tenant:5', 1, 5, 5, 5, 0, 0),
                warnings: [],
                signatureResults: [],
                anchorVerification: null,
            ), 0, $output);

            $payloads[] = json_decode($output->fetch(), true)['completeness'];
        }

        self::assertSame($payloads[0], $payloads[1]);
        self::assertFalse($payloads[0]['asserted']);
    }

    public function test_emits_v1_schema_for_verified_result(): void
    {
        $result = new VerificationResult(
            outcome: VerificationOutcome::VERIFIED,
            chainStats: new ChainStats('tenant:5', 1, 5, 5, 5, 0, 0),
            warnings: [],
            signatureResults: [],
            anchorVerification: null,
        );

        $output = new BufferedOutput();
        (new JsonResultEmitter())->emit('verify', $result, 0, $output);

        $payload = json_decode($output->fetch(), true);

        self::assertSame('attest.cli.result.v1', $payload['format_version']);
        self::assertSame('verify', $payload['command']);
        self::assertSame('verified', $payload['outcome']);
        self::assertTrue($payload['verified']);
        self::assertSame(0, $payload['exit_code']);
        self::assertNull($payload['message']);
        self::assertNull($payload['broken_at_seq']);
        self::assertSame('tenant:5', $payload['chain_stats']['chain_id']);
        self::assertSame(1, $payload['chain_stats']['from_seq']);
        self::assertSame(5, $payload['chain_stats']['to_seq']);
        self::assertSame(5, $payload['chain_stats']['envelope_count']);
        self::assertSame(5, $payload['chain_stats']['trusted_signatures']);
        self::assertSame(0, $payload['chain_stats']['untrusted_signatures']);
        self::assertSame(0, $payload['chain_stats']['anchor_envelopes']);
        self::assertIsArray($payload['signature_summary']);
        self::assertArrayHasKey('trusted_keys_matched', $payload['signature_summary']);
        self::assertNull($payload['anchor_verification']);
        self::assertSame([], $payload['warnings']);
    }

    public function test_emits_v1_schema_with_anchor_verification(): void
    {
        // Compute a valid merkle root from two leaf hashes.
        $rootHex = bin2hex(hash('sha256', str_repeat('a', 64) . str_repeat('b', 64), binary: true));
        $target = new AnchorTarget(
            chainId: 'tenant:5',
            fromSeq: 1,
            toSeq: 2,
            merkleAlgorithm: 'sha256-rfc6962',
            rootHex: $rootHex,
        );
        $receipt = new AnchorReceipt(
            driverName: 'opentimestamps',
            target: $target,
            state: ProofState::UPGRADED,
            receiptBytes: '',
            createdAtIso8601: '2026-06-05T00:00:00.000Z',
        );
        $av = new AnchorVerification(
            receipt: $receipt,
            outcome: AnchorOutcome::LOCAL_ONLY,
            message: 'local anchor verified',
            providerName: 'null-driver',
        );

        $result = new VerificationResult(
            outcome: VerificationOutcome::VERIFIED,
            chainStats: new ChainStats('tenant:5', 1, 2, 2, 2, 0, 1),
            warnings: [],
            signatureResults: [],
            anchorVerification: $av,
        );

        $output = new BufferedOutput();
        (new JsonResultEmitter())->emit('verify', $result, 0, $output);

        $payload = json_decode($output->fetch(), true);

        self::assertSame('attest.cli.result.v1', $payload['format_version']);
        self::assertSame('verified', $payload['outcome']);
        self::assertIsArray($payload['anchor_verification']);
        self::assertSame('local_only', $payload['anchor_verification']['outcome']);
        self::assertSame('null-driver', $payload['anchor_verification']['provider']);
        self::assertSame('local anchor verified', $payload['anchor_verification']['message']);
        self::assertSame(1, $payload['chain_stats']['anchor_envelopes']);
    }
}
