<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * @internal
 */
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
