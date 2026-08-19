<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Cli\Output;

use Fissible\Attest\Cli\Output\HumanResultEmitter;
use Fissible\Attest\Cli\Output\JsonResultSchema;
use Fissible\Attest\Verification\ChainStats;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationResult;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

final class HumanResultEmitterTest extends TestCase
{
    private function humanOutput(VerificationOutcome $outcome, string $command = 'verify'): string
    {
        $output = new BufferedOutput();

        (new HumanResultEmitter())->emit($command, new VerificationResult(
            outcome: $outcome,
            chainStats: new ChainStats('tenant:5', 1, 5, 5, 5, 0, 0),
            warnings: [],
            signatureResults: [],
            anchorVerification: null,
        ), 0, $output);

        return $output->fetch();
    }

    /**
     * The wrong inference forms wherever a passing result is read, and human CLI output pasted into an
     * audit ticket is such a place. The caveat is sourced from the same constant the JSON emits, so the
     * two surfaces cannot drift apart.
     */
    public function test_human_output_carries_the_completeness_caveat_from_the_shared_constant(): void
    {
        $text = $this->humanOutput(VerificationOutcome::VERIFIED);

        self::assertStringContainsString(
            'completeness: not asserted — ' . JsonResultSchema::COMPLETENESS_STATEMENT,
            $text,
        );
    }

    /**
     * Constant, not computed — the same principle the JSON block pins. A caveat printed only on passing
     * runs would vary with the outcome, implying attest had checked something it never checks.
     */
    public function test_completeness_caveat_does_not_vary_with_the_verification_outcome(): void
    {
        $caveat = 'completeness: not asserted — ' . JsonResultSchema::COMPLETENESS_STATEMENT;

        self::assertStringContainsString($caveat, $this->humanOutput(VerificationOutcome::VERIFIED));
        self::assertStringContainsString($caveat, $this->humanOutput(VerificationOutcome::INVALID_CHAIN));
    }

    /**
     * Range scoping applies to bundle verification as much as chain verification, so the caveat must not
     * be conditional on which command produced the result.
     */
    public function test_bundle_verify_output_carries_the_same_caveat(): void
    {
        self::assertStringContainsString(
            'completeness: not asserted — ' . JsonResultSchema::COMPLETENESS_STATEMENT,
            $this->humanOutput(VerificationOutcome::VERIFIED, 'bundle:verify'),
        );
    }
}
