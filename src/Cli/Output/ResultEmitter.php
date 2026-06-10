<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * @internal
 */
interface ResultEmitter
{
    public function emit(string $command, VerificationResult $result, int $exitCode, OutputInterface $output): void;
}
