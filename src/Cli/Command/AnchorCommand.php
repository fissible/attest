<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'anchor', description: 'Anchor a chain segment to an external timestamp service.')]
final class AnchorCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('anchor: stub implementation; wired in Task 3.11');
        return Command::SUCCESS;
    }
}
