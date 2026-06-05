<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Fissible\Attest\Anchor\AnchorService;
use Fissible\Attest\Anchor\FileAnchorClaimStore;
use Fissible\Attest\Anchor\NullDriver;
use Fissible\Attest\Anchor\OpenTimestamps\CalendarUnavailable;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'anchor', description: 'Anchor a chain segment to an external timestamp service.')]
final class AnchorCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('storage-root', null, InputOption::VALUE_REQUIRED, 'Path to the FileChainStore root directory (must exist).')
            ->addOption('chain', null, InputOption::VALUE_REQUIRED, 'Chain ID to anchor.')
            ->addOption('from', null, InputOption::VALUE_REQUIRED, 'Start sequence number (int >= 1).')
            ->addOption('to', null, InputOption::VALUE_REQUIRED, 'End sequence number (int >= from).')
            ->addOption('driver', null, InputOption::VALUE_REQUIRED, 'Anchor driver to use: opentimestamps or local-only.')
            ->addOption(
                'calendar-url',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'OpenTimestamps calendar URL(s). Repeatable. Defaults to driver built-in list.',
            )
            ->addOption('min-calendars', null, InputOption::VALUE_REQUIRED, 'Minimum number of calendars required (opentimestamps only).', '1')
            ->addOption('signer-key-file', null, InputOption::VALUE_REQUIRED, 'Path to file containing a base64-encoded 32-byte Ed25519 seed.')
            ->addOption('signer-key-id', null, InputOption::VALUE_REQUIRED, 'Key ID string for the signing key.')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Emit machine-readable JSON output (attest.cli.anchor.v1).');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // ── Option validation ────────────────────────────────────────────────
        $storageRoot   = $input->getOption('storage-root');
        $chainId       = $input->getOption('chain');
        $fromRaw       = $input->getOption('from');
        $toRaw         = $input->getOption('to');
        $driverName    = $input->getOption('driver');
        $signerKeyFile = $input->getOption('signer-key-file');
        $signerKeyId   = $input->getOption('signer-key-id');
        $calendarUrls  = $input->getOption('calendar-url') ?: [];
        $minCalendarsRaw = $input->getOption('min-calendars');

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
            $output->writeln('error: --to must be an integer');
            return 1;
        }
        $fromSeq = (int) $fromRaw;
        $toSeq   = (int) $toRaw;
        if ($toSeq < $fromSeq) {
            $output->writeln('error: --to must be >= --from');
            return 1;
        }
        if (! is_string($driverName) || $driverName === '') {
            $output->writeln('error: --driver is required (opentimestamps or local-only)');
            return 1;
        }
        if (! in_array($driverName, ['opentimestamps', 'local-only'], true)) {
            $output->writeln('error: --driver must be opentimestamps or local-only');
            return 1;
        }
        if (! is_string($signerKeyFile) || $signerKeyFile === '') {
            $output->writeln('error: --signer-key-file is required');
            return 1;
        }
        if (! is_string($signerKeyId) || $signerKeyId === '') {
            $output->writeln('error: --signer-key-id is required');
            return 1;
        }

        // ── Load signer ──────────────────────────────────────────────────────
        if (! is_file($signerKeyFile)) {
            $output->writeln('error: --signer-key-file not found: ' . $signerKeyFile);
            return 1;
        }
        $b64Seed = trim((string) file_get_contents($signerKeyFile));
        $seed = base64_decode($b64Seed, strict: true);
        if ($seed === false) {
            $output->writeln('error: --signer-key-file does not contain valid base64');
            return 1;
        }
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $output->writeln(sprintf(
                'error: --signer-key-file seed must be %d bytes after base64-decode; got %d',
                SODIUM_CRYPTO_SIGN_SEEDBYTES,
                strlen($seed),
            ));
            return 1;
        }
        try {
            $kp = KeyPair::fromSeed($seed);
        } catch (\InvalidArgumentException $e) {
            $output->writeln('error: invalid signer key: ' . $e->getMessage());
            return 1;
        }
        $signer = new SodiumSigner($kp, $signerKeyId);

        // ── Build stores ─────────────────────────────────────────────────────
        $store      = new FileChainStore($storageRoot);
        $claimStore = new FileAnchorClaimStore($storageRoot);

        // ── Build driver ─────────────────────────────────────────────────────
        if ($driverName === 'local-only') {
            $driver = new NullDriver();
        } else {
            // opentimestamps
            $minCalendars = (int) $minCalendarsRaw;
            if ($minCalendars < 1) {
                $output->writeln('error: --min-calendars must be >= 1');
                return 1;
            }
            $client = OpenTimestampsCalendarClient::withGuzzle();
            if ($calendarUrls !== []) {
                $driver = new OpenTimestampsDriver($client, $calendarUrls, $minCalendars);
            } else {
                $driver = new OpenTimestampsDriver($client, minCalendars: $minCalendars);
            }
        }

        // ── Pre-call tail seq (for reconciled vs anchored detection) ─────────
        $preTail = $store->tail($chainId);
        $preSeq  = $preTail?->envelope->seq ?? 0;

        // ── Call AnchorService ───────────────────────────────────────────────
        $service = new AnchorService($store, $claimStore, $signer);
        try {
            $envelope = $service->anchorRange($chainId, $fromSeq, $toSeq, $driver);
        } catch (CalendarUnavailable $e) {
            $output->writeln('error: calendar unavailable: ' . $e->getMessage());
            return 4;
        } catch (\RuntimeException $e) {
            $output->writeln('error: driver error: ' . $e->getMessage());
            return 4;
        }

        // ── Determine result ─────────────────────────────────────────────────
        $warnings = [];
        if ($envelope === null) {
            // Claim held by another worker; reconciliation found no existing envelope.
            $result      = 'skipped';
            $envelopeId  = null;
            $anchorId    = null;
            $state       = null;
            $warnings[]  = 'claim held by another worker; no existing anchor envelope found';
        } else {
            $envelopeId = $envelope->envelope->id;
            $anchorId   = $envelope->envelope->payload['anchor_id'] ?? null;
            $stateRaw   = $envelope->envelope->payload['state'] ?? 'submitted';
            $state      = is_string($stateRaw) ? $stateRaw : 'submitted';

            // Reconciled = envelope already existed before this call.
            if ($envelope->envelope->seq <= $preSeq) {
                $result = 'reconciled';
            } else {
                $result = 'anchored';
            }
        }

        // ── Output ───────────────────────────────────────────────────────────
        if ($input->getOption('json')) {
            $jsonOut = [
                'format_version' => 'attest.cli.anchor.v1',
                'command'        => 'anchor',
                'result'         => $result,
                'anchor_id'      => $anchorId,
                'envelope_id'    => $envelopeId,
                'target_chain'   => $chainId,
                'from_seq'       => $fromSeq,
                'to_seq'         => $toSeq,
                'driver'         => $driverName,
                'state'          => $state,
                'warnings'       => $warnings,
            ];
            $encoded = json_encode($jsonOut, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            $output->write($encoded);
        } else {
            if ($result === 'anchored') {
                $output->writeln(sprintf(
                    'anchored %s[%d,%d] via %s; envelope %s',
                    $chainId,
                    $fromSeq,
                    $toSeq,
                    $driverName,
                    $envelopeId,
                ));
            } elseif ($result === 'reconciled') {
                $output->writeln(sprintf(
                    'reconciled: existing anchor envelope %s for %s[%d,%d]',
                    $envelopeId,
                    $chainId,
                    $fromSeq,
                    $toSeq,
                ));
            } elseif ($result === 'skipped') {
                $output->writeln(sprintf(
                    'warning: skipped — claim held by another worker for %s[%d,%d]',
                    $chainId,
                    $fromSeq,
                    $toSeq,
                ));
            }
            foreach ($warnings as $w) {
                $output->writeln('warning: ' . $w);
            }
        }

        return 0;
    }
}
