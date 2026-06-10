<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Fissible\Attest\Bundle\BundleExportException;
use Fissible\Attest\Bundle\BundleExporter;
use Fissible\Attest\Chain\FileChainStore;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'bundle:export', description: 'Export a chain segment to a portable bundle.')]
/**
 * @internal
 */
final class BundleExportCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('storage-root', null, InputOption::VALUE_REQUIRED, 'Path to the FileChainStore root directory (must exist).')
            ->addOption('chain', null, InputOption::VALUE_REQUIRED, 'Chain ID to export.')
            ->addOption('from', null, InputOption::VALUE_REQUIRED, 'Start sequence number (int >= 1).')
            ->addOption('to', null, InputOption::VALUE_REQUIRED, 'End sequence number (int >= from).')
            ->addOption('out', null, InputOption::VALUE_REQUIRED, 'Output path for the bundle file (written atomically).')
            ->addOption('note', null, InputOption::VALUE_REQUIRED, 'Free-text note to embed in the bundle manifest.')
            ->addOption('issuer-hint', null, InputOption::VALUE_REQUIRED, 'Issuer hint to embed in the bundle manifest.')
            ->addOption(
                'include-claimed-key',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Path to a .pub file containing a base64-encoded Ed25519 public key. Repeatable.',
            )
            ->addOption('json', null, InputOption::VALUE_NONE, 'Emit machine-readable JSON output (attest.cli.export.v1).');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // ── Option validation ────────────────────────────────────────────────
        $storageRoot = $input->getOption('storage-root');
        $chainId     = $input->getOption('chain');
        $fromRaw     = $input->getOption('from');
        $toRaw       = $input->getOption('to');
        $outPath     = $input->getOption('out');

        if (! is_string($storageRoot) || ! is_dir($storageRoot)) {
            $output->writeln('error: --storage-root must point to an existing directory');
            return 1;
        }
        if (! is_string($chainId) || $chainId === '') {
            $output->writeln('error: --chain is required and must not be empty');
            return 1;
        }
        if (! is_string($fromRaw) || ! ctype_digit($fromRaw) || (int) $fromRaw < 1) {
            $output->writeln('error: --from must be an integer >= 1');
            return 1;
        }
        if (! is_string($toRaw) || ! ctype_digit($toRaw)) {
            $output->writeln('error: --to must be an integer >= from');
            return 1;
        }
        $fromSeq = (int) $fromRaw;
        $toSeq   = (int) $toRaw;
        if ($toSeq < $fromSeq) {
            $output->writeln('error: --to must be >= --from');
            return 1;
        }
        if (! is_string($outPath) || $outPath === '') {
            $output->writeln('error: --out is required and must not be empty');
            return 1;
        }

        // ── Build exporter ───────────────────────────────────────────────────
        $store    = new FileChainStore($storageRoot);
        $exporter = BundleExporter::create($store)
            ->forChainSegment($chainId, $fromSeq, $toSeq);

        // ── Include claimed keys ─────────────────────────────────────────────
        /** @var list<string> $keyPaths */
        $keyPaths = $input->getOption('include-claimed-key') ?: [];
        foreach ($keyPaths as $keyPath) {
            if (! is_file($keyPath)) {
                $output->writeln('error: --include-claimed-key path not found: ' . $keyPath);
                return 1;
            }
            $b64 = trim((string) file_get_contents($keyPath));
            $raw = base64_decode($b64, strict: true);
            if ($raw === false) {
                $output->writeln('error: --include-claimed-key file does not contain valid base64: ' . $keyPath);
                return 1;
            }
            // Derive keyId from the filename without extension (e.g. "mykey.pub" → "mykey")
            $keyId = pathinfo($keyPath, PATHINFO_FILENAME);
            $exporter->withClaimedKey($raw, keyId: $keyId !== '' ? $keyId : null);
        }

        // ── Optional fields ──────────────────────────────────────────────────
        $note        = $input->getOption('note');
        $issuerHint  = $input->getOption('issuer-hint');
        if (is_string($note) && $note !== '') {
            $exporter->withNote($note);
        }
        if (is_string($issuerHint) && $issuerHint !== '') {
            $exporter->withIssuerHint($issuerHint);
        }

        // ── Write bundle ─────────────────────────────────────────────────────
        try {
            $exporter->writeTo($outPath);
        } catch (BundleExportException $e) {
            $output->writeln('error: ' . $e->getMessage());
            return 4;
        }

        $bytesWritten = (int) filesize($outPath);
        $warnings     = $exporter->warnings();

        // ── Output ───────────────────────────────────────────────────────────
        if ($input->getOption('json')) {
            $jsonOut = [
                'format_version' => 'attest.cli.export.v1',
                'command'        => 'bundle:export',
                'out'            => $outPath,
                'bytes_written'  => $bytesWritten,
                'chain_segments' => [
                    [
                        'chain_id'       => $chainId,
                        'from_seq'       => $fromSeq,
                        'to_seq'         => $toSeq,
                        'envelope_count' => $toSeq - $fromSeq + 1,
                    ],
                ],
                'anchors'  => [],   // populated if we expose manifest anchors in a later pass
                'warnings' => array_map(
                    fn ($w) => [
                        'code'    => $w->code,
                        'message' => $w->message,
                        'context' => $w->context,
                    ],
                    $warnings,
                ),
            ];
            $encoded = json_encode($jsonOut, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $output->write($encoded);
        } else {
            $output->writeln(sprintf(
                'bundle exported to %s (%d bytes)',
                $outPath,
                $bytesWritten,
            ));
            if ($warnings !== []) {
                foreach ($warnings as $w) {
                    $output->writeln('warning [' . $w->code . ']: ' . $w->message);
                }
            }
        }

        return 0;
    }
}
