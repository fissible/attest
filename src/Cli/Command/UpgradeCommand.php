<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'upgrade', description: 'Upgrade pending anchor receipts.')]
final class UpgradeCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('upgrade: stub implementation; wired in Task 3.12');
        return Command::SUCCESS;
    }
}
