<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'verify', description: 'Verify a chain segment against trusted keys and policy.')]
final class VerifyCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('verify: stub implementation; wired in Task 3.8');
        return Command::SUCCESS;
    }
}
