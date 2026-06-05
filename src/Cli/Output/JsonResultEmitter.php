<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Fissible\Attest\Verification\VerificationResult;
use Symfony\Component\Console\Output\OutputInterface;

final class JsonResultEmitter implements ResultEmitter
{
    public function emit(string $command, VerificationResult $result, int $exitCode, OutputInterface $output): void
    {
        $encoded = json_encode(
            JsonResultSchema::fromVerification($command, $result, $exitCode),
            JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR,
        );
        $output->writeln($encoded);
    }
}
