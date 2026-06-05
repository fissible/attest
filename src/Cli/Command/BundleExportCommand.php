<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'bundle:export', description: 'Export a chain segment to a portable bundle.')]
final class BundleExportCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('bundle:export: stub implementation; wired in Task 3.9');
        return Command::SUCCESS;
    }
}
