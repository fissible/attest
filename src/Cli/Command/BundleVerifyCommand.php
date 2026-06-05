<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'bundle:verify', description: 'Verify a bundle against trusted keys and policy.')]
final class BundleVerifyCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('bundle:verify: stub implementation; wired in Task 3.10');
        return Command::SUCCESS;
    }
}
