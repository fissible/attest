<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Fissible\Attest\Anchor\AnchorEnvelope;
use Fissible\Attest\Anchor\OpenTimestamps\CalendarUnavailable;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestampsDriver;
use Fissible\Attest\Anchor\ProofState;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use Fissible\Attest\Verification\AnchorSetResolver;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'upgrade', description: 'Upgrade pending anchor receipts.')]
final class UpgradeCommand extends Command
{
    /** @var (callable(): OpenTimestampsCalendarClient)|null */
    private $calendarClientFactory;

    /**
     * @param (callable(): OpenTimestampsCalendarClient)|null $calendarClientFactory
     *   Test seam for injecting a mock PSR-18-backed calendar client. When
     *   null, the command falls back to OpenTimestampsCalendarClient::withGuzzle().
     */
    public function __construct(?callable $calendarClientFactory = null)
    {
        parent::__construct();
        $this->calendarClientFactory = $calendarClientFactory;
    }

    protected function configure(): void
    {
        $this
            ->addOption('storage-root', null, InputOption::VALUE_REQUIRED, 'Path to the FileChainStore root directory (must exist).')
            ->addOption('chain', null, InputOption::VALUE_REQUIRED, 'Chain ID to sweep for pending anchors.')
            ->addOption('anchor-id', null, InputOption::VALUE_REQUIRED, 'Upgrade a single anchor by its anchor_id. Mutually exclusive with --all-pending.')
            ->addOption('all-pending', null, InputOption::VALUE_NONE, 'Sweep all pending anchors in the chain. Mutually exclusive with --anchor-id.')
            ->addOption('signer-key-file', null, InputOption::VALUE_REQUIRED, 'Path to file containing a base64-encoded 32-byte Ed25519 seed.')
            ->addOption('signer-key-id', null, InputOption::VALUE_REQUIRED, 'Key ID string for the signing key.')
            ->addOption(
                'calendar-url',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'OpenTimestamps calendar URL(s). Repeatable. Defaults to driver built-in list.',
            )
            ->addOption('json', null, InputOption::VALUE_NONE, 'Emit machine-readable JSON output (attest.cli.upgrade.v1).');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // ── Option validation ────────────────────────────────────────────────
        $storageRoot   = $input->getOption('storage-root');
        $chainId       = $input->getOption('chain');
        $anchorId      = $input->getOption('anchor-id');
        $allPending    = $input->getOption('all-pending');
        $signerKeyFile = $input->getOption('signer-key-file');
        $signerKeyId   = $input->getOption('signer-key-id');
        $calendarUrls  = $input->getOption('calendar-url') ?: [];
        $verbose       = $output->isVerbose();
        $jsonMode      = $input->getOption('json');

        if (! is_string($storageRoot) || ! is_dir($storageRoot)) {
            $output->writeln('error: --storage-root must point to an existing directory');
            return 1;
        }
        if (! is_string($chainId) || $chainId === '') {
            $output->writeln('error: --chain is required and must not be empty');
            return 1;
        }

        // Mutual exclusion: exactly one of --anchor-id / --all-pending required.
        $hasAnchorId  = is_string($anchorId) && $anchorId !== '';
        $hasAllPending = (bool) $allPending;

        if ($hasAnchorId && $hasAllPending) {
            $output->writeln('error: --anchor-id and --all-pending are mutually exclusive');
            return 1;
        }
        if (! $hasAnchorId && ! $hasAllPending) {
            $output->writeln('error: one of --anchor-id or --all-pending is required');
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

        // ── Build stores + driver ────────────────────────────────────────────
        $store  = new FileChainStore($storageRoot);
        $client = $this->calendarClientFactory !== null
            ? ($this->calendarClientFactory)()
            : OpenTimestampsCalendarClient::withGuzzle();
        /** @var list<string> $calendarUrls */
        if ($calendarUrls !== []) {
            $driver = new OpenTimestampsDriver($client, $calendarUrls);
        } else {
            $driver = new OpenTimestampsDriver($client);
        }

        // ── Resolve pending anchor groups ────────────────────────────────────
        $resolver = new AnchorSetResolver();
        $allEnvelopes = $store->readRange($chainId, 1);
        $resolvedGroups = $resolver->resolve($allEnvelopes);

        // Filter: only pending OTS receipts that match our target.
        $candidates = [];
        foreach ($resolvedGroups as $resolved) {
            if (! $resolved->valid || $resolved->receipt === null) {
                continue;
            }
            // Only OTS receipts can be upgraded; local-only (NullDriver) cannot.
            if ($resolved->receipt->driverName !== OpenTimestampsDriver::NAME) {
                continue;
            }
            if ($resolved->receipt->state !== ProofState::PENDING) {
                continue;
            }
            // If --anchor-id was specified, filter to that one only.
            if ($hasAnchorId && $resolved->anchorId !== $anchorId) {
                continue;
            }
            $candidates[] = $resolved;
        }

        // ── Handle no-op case for --all-pending ──────────────────────────────
        if ($hasAllPending && $candidates === []) {
            if ($jsonMode) {
                $jsonOut = [
                    'format_version' => 'attest.cli.upgrade.v1',
                    'command'        => 'upgrade',
                    'upgraded'       => [],
                    'unchanged'      => [],
                    'failed'         => [],
                    'warnings'       => [],
                ];
                $output->write(json_encode($jsonOut, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
            } else {
                $output->writeln('upgraded 0, unchanged 0, failed 0');
            }
            return 0;
        }

        // ── Handle --anchor-id with no match ─────────────────────────────────
        if ($hasAnchorId && $candidates === []) {
            $message = 'no pending OTS anchor found for anchor_id: ' . $anchorId;
            if ($jsonMode) {
                $jsonOut = [
                    'format_version' => 'attest.cli.upgrade.v1',
                    'command'        => 'upgrade',
                    'upgraded'       => [],
                    'unchanged'      => [],
                    'failed'         => [
                        [
                            'anchor_id'   => $anchorId,
                            'envelope_id' => null,
                            'error'       => $message,
                        ],
                    ],
                    'warnings'       => [],
                ];
                $output->write(json_encode($jsonOut, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
            } else {
                $output->writeln('error: ' . $message);
            }
            return 4;
        }

        // ── Sweep candidates ─────────────────────────────────────────────────
        /** @var list<array{anchor_id: string, previous_envelope_id: string|null, new_envelope_id: string}> $upgraded */
        $upgraded  = [];
        /** @var list<array{anchor_id: string, envelope_id: string|null, state: string}> $unchanged */
        $unchanged = [];
        /** @var list<array{anchor_id: string, envelope_id: string|null, error: string}> $failed */
        $failed    = [];
        /** @var list<string> $warnings */
        $warnings  = [];

        $chain = EvidenceChain::open($store, $chainId, $signer);

        foreach ($candidates as $resolved) {
            // $resolved->receipt is non-null here; candidates were filtered above.
            $receipt     = $resolved->receipt;
            assert($receipt !== null);
            // Copy to local var so end() can take it by reference.
            $envelopeIds = $resolved->envelopeIds;
            $prevEnvId   = end($envelopeIds) ?: null;

            try {
                $newReceipt = $driver->upgrade($receipt);
            } catch (CalendarUnavailable $e) {
                $failed[] = [
                    'anchor_id'   => $resolved->anchorId,
                    'envelope_id' => $prevEnvId,
                    'error'       => 'calendar unavailable: ' . $e->getMessage(),
                ];
                if ($verbose && ! $jsonMode) {
                    $output->writeln(sprintf('failed %s: calendar unavailable: %s', $resolved->anchorId, $e->getMessage()));
                }
                continue;
            } catch (\Throwable $e) {
                $failed[] = [
                    'anchor_id'   => $resolved->anchorId,
                    'envelope_id' => $prevEnvId,
                    'error'       => $e->getMessage(),
                ];
                if ($verbose && ! $jsonMode) {
                    $output->writeln(sprintf('failed %s: %s', $resolved->anchorId, $e->getMessage()));
                }
                continue;
            }

            // If state did not advance (still PENDING), record as unchanged.
            if ($newReceipt->state === $receipt->state) {
                $unchanged[] = [
                    'anchor_id'   => $resolved->anchorId,
                    'envelope_id' => $prevEnvId,
                    'state'       => $receipt->state->value,
                ];
                if ($verbose && ! $jsonMode) {
                    $output->writeln(sprintf('unchanged %s (still %s)', $resolved->anchorId, $receipt->state->value));
                }
                continue;
            }

            // State advanced to UPGRADED: append a new envelope.
            $payload = AnchorEnvelope::upgradedPayload($newReceipt, supersedesEnvelopeId: $prevEnvId);
            $newEnvelope = $chain->record(AnchorEnvelope::UPGRADED_TYPE, $payload);
            $newEnvId    = $newEnvelope->envelope->id;

            $upgraded[] = [
                'anchor_id'           => $resolved->anchorId,
                'previous_envelope_id' => $prevEnvId,
                'new_envelope_id'      => $newEnvId,
            ];
            if ($verbose && ! $jsonMode) {
                $output->writeln(sprintf('upgraded %s → envelope %s', $resolved->anchorId, $newEnvId));
            }
        }

        // ── Output ───────────────────────────────────────────────────────────
        if ($jsonMode) {
            $jsonOut = [
                'format_version' => 'attest.cli.upgrade.v1',
                'command'        => 'upgrade',
                'upgraded'       => $upgraded,
                'unchanged'      => $unchanged,
                'failed'         => $failed,
                'warnings'       => $warnings,
            ];
            $output->write(json_encode($jsonOut, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        } else {
            $output->writeln(sprintf(
                'upgraded %d, unchanged %d, failed %d',
                count($upgraded),
                count($unchanged),
                count($failed),
            ));
            foreach ($warnings as $w) {
                $output->writeln('warning: ' . $w);
            }
        }

        // ── Exit code ────────────────────────────────────────────────────────
        // --anchor-id: exit 4 if the single upgrade failed.
        if ($hasAnchorId && $failed !== []) {
            return 4;
        }

        return 0;
    }
}
