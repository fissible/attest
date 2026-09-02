<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Output;

use Symfony\Component\Console\Output\OutputInterface;

/**
 * Output for a runtime failure that happened before a VerificationOutcome
 * existed (lock unavailable, unreadable storage, a store bug). Exit code 1 per
 * the CLI contract; under --json a small `attest.cli.error.v1` object so
 * automation always gets JSON from a --json invocation, never a stack trace.
 * @internal
 */
final class RuntimeErrorEmitter
{
    public const FORMAT = 'attest.cli.error.v1';
    public const EXIT_CODE = 1;

    public static function emit(string $command, \Throwable $e, bool $json, OutputInterface $output): int
    {
        if ($json) {
            $output->writeln(json_encode([
                'format_version' => self::FORMAT,
                'command' => $command,
                'exit_code' => self::EXIT_CODE,
                'error' => $e->getMessage(),
                'error_class' => $e::class,
            ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        } else {
            $output->writeln('error: ' . $e->getMessage());
        }

        return self::EXIT_CODE;
    }
}
