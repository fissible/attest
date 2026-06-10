<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli;

use Fissible\Attest\Cli\Command\AnchorCommand;
use Fissible\Attest\Cli\Command\BundleExportCommand;
use Fissible\Attest\Cli\Command\BundleVerifyCommand;
use Fissible\Attest\Cli\Command\UpgradeCommand;
use Fissible\Attest\Cli\Command\VerifyCommand;
use Symfony\Component\Console\Application;

/**
 * @internal
 */
final class AttestCli
{
    public function run(): int
    {
        $app = new Application('attest', $this->version());
        $app->add(new VerifyCommand());
        $app->add(new BundleExportCommand());
        $app->add(new BundleVerifyCommand());
        $app->add(new AnchorCommand());
        $app->add(new UpgradeCommand());
        return $app->run();
    }

    private function version(): string
    {
        $file = __DIR__ . '/../../VERSION';
        return is_file($file) ? trim((string) file_get_contents($file)) : 'dev';
    }
}
