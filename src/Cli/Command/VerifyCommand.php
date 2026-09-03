<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Cli\Output\HumanResultEmitter;
use Fissible\Attest\Cli\Output\JsonResultEmitter;
use Fissible\Attest\Cli\Output\RuntimeErrorEmitter;
use Fissible\Attest\Cli\Support\AnchorDriverFactory;
use Fissible\Attest\Cli\Support\HeaderProviderFactory;
use Fissible\Attest\Cli\Support\MinAnchorOption;
use Fissible\Attest\Cli\Support\TrustedKeyLoader;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\Verifier;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'verify', description: 'Verify a chain segment against trusted keys and policy.')]
/**
 * @internal
 */
final class VerifyCommand extends Command
{
    /** @var (callable(?string, ?string, ?string): HeaderProviderSet)|null */
    private $headerProviderFactory;

    /**
     * @param (callable(?string, ?string, ?string): HeaderProviderSet)|null $headerProviderFactory
     */
    public function __construct(?callable $headerProviderFactory = null)
    {
        parent::__construct();
        $this->headerProviderFactory = $headerProviderFactory;
    }

    protected function configure(): void
    {
        $this
            ->addOption('storage-root', null, InputOption::VALUE_REQUIRED, 'Path to the FileChainStore root directory.')
            ->addOption('chain', null, InputOption::VALUE_REQUIRED, 'Chain ID to verify.')
            ->addOption('from', null, InputOption::VALUE_REQUIRED, 'Start sequence number (default 1).', '1')
            ->addOption('to', null, InputOption::VALUE_REQUIRED, 'End sequence number (default: chain tail).')
            ->addOption(
                'trusted-key',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Inline trusted key in the format <key_id>=<base64-pubkey>. Repeatable.',
            )
            ->addOption(
                'trusted-key-file',
                null,
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Path to a .pub file containing a base64-encoded Ed25519 public key, as <key_id>=<path> to bind it to the key id envelopes were signed under; a plain path matches only envelopes whose key_id is the key fingerprint. Repeatable.',
            )
            ->addOption('min-anchor', null, InputOption::VALUE_REQUIRED, 'Minimum anchor outcome required (local_only, pending, upgraded_no_headers, remote_header_confirmed, bitcoin_verified).')
            ->addOption('allow-provider-disagreement', null, InputOption::VALUE_NONE, 'Allow header-provider disagreement; use strongest passing outcome.')
            ->addOption('allow-untrusted', null, InputOption::VALUE_NONE, 'Treat INTEGRITY_VERIFIED_UNTRUSTED as success (exit 0 instead of 2).')
            ->addOption('bitcoin-core-rpc', null, InputOption::VALUE_REQUIRED, 'Bitcoin Core JSON-RPC URL for block-header verification.')
            ->addOption('bitcoin-core-cookie', null, InputOption::VALUE_REQUIRED, 'Path to Bitcoin Core .cookie file for RPC authentication.')
            ->addOption('esplora-url', null, InputOption::VALUE_REQUIRED, 'Esplora REST API base URL for block-header verification.')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Emit machine-readable JSON output (attest.cli.result.v1).');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // ── Option validation ────────────────────────────────────────────────
        try {
            $storageRoot = $input->getOption('storage-root');
            $chainId = $input->getOption('chain');

            if (! is_string($storageRoot) || ! is_dir($storageRoot)) {
                $output->writeln('error: --storage-root must point to an existing directory');
                return 1;
            }
            if (! is_string($chainId) || $chainId === '') {
                $output->writeln('error: --chain is required and must not be empty');
                return 1;
            }

            $fromRaw = $input->getOption('from') ?? '1';
            if (! is_string($fromRaw) || ! ctype_digit($fromRaw) || (int) $fromRaw < 1) {
                $output->writeln('error: --from must be an integer >= 1');
                return 1;
            }
            $fromSeq = (int) $fromRaw;
            $toRaw = $input->getOption('to');
            $toSeq = null;
            if ($toRaw !== null) {
                if (! is_string($toRaw) || ! ctype_digit($toRaw) || (int) $toRaw < $fromSeq) {
                    $output->writeln('error: --to must be an integer >= --from');
                    return 1;
                }
                $toSeq = (int) $toRaw;
            }

            $minAnchor = MinAnchorOption::parse($input->getOption('min-anchor'));

            $trustedKeys = TrustedKeyLoader::load(
                $input->getOption('trusted-key') ?: [],
                $input->getOption('trusted-key-file') ?: [],
            );

            $bitcoinCoreRpc = $input->getOption('bitcoin-core-rpc');
            $bitcoinCoreCookie = $input->getOption('bitcoin-core-cookie');
            $esploraUrl = $input->getOption('esplora-url');
            $headers = $this->headerProviderFactory !== null
                ? ($this->headerProviderFactory)($bitcoinCoreRpc, $bitcoinCoreCookie, $esploraUrl)
                : HeaderProviderFactory::build($bitcoinCoreRpc, $bitcoinCoreCookie, $esploraUrl);
        } catch (\InvalidArgumentException | \RuntimeException $e) {
            $output->writeln('error: ' . $e->getMessage());
            return 1;
        }

        // ── Build and run verification ───────────────────────────────────────
        $store = new FileChainStore($storageRoot);
        $verifier = new Verifier(
            store: $store,
            signatures: new SignatureVerifier($trustedKeys),
            policy: new VerificationPolicy(
                minAnchorOutcome: $minAnchor,
                allowProviderDisagreement: (bool) $input->getOption('allow-provider-disagreement'),
                requireTrustedKey: ! $input->getOption('allow-untrusted'),
            ),
            anchorDrivers: AnchorDriverFactory::verificationDrivers(),
            headers: $headers,
        );

        $json = (bool) $input->getOption('json');
        try {
            $result = $verifier->verifyChain($chainId, $fromSeq, $toSeq);
        } catch (\Throwable $e) {
            // Decode failures inside the range are already VerificationOutcomes
            // (INVALID_CHAIN); anything that still escapes is a runtime error
            // before an outcome existed, which the contract maps to exit 1.
            return RuntimeErrorEmitter::emit('verify', $e, $json, $output);
        }

        $exit = self::exitCodeFor($result->outcome, (bool) $input->getOption('allow-untrusted'));

        $emitter = $json ? new JsonResultEmitter() : new HumanResultEmitter();
        $emitter->emit('verify', $result, $exit, $output);

        return $exit;
    }

    /**
     * Spec §13 exit-code mapping.
     *
     * 0 — VERIFIED (also INTEGRITY_VERIFIED_UNTRUSTED with --allow-untrusted)
     * 1 — CLI/config/runtime error before a VerificationOutcome  [handled above]
     * 2 — INTEGRITY_VERIFIED_UNTRUSTED (without --allow-untrusted)
     * 3 — ANCHOR_BELOW_MIN
     * 4 — INVALID_CHAIN / INVALID_SIGNATURE / INVALID_ANCHOR
     * 5 — PROVIDER_DISAGREEMENT
     */
    private static function exitCodeFor(VerificationOutcome $outcome, bool $allowUntrusted): int
    {
        return match ($outcome) {
            VerificationOutcome::VERIFIED                   => 0,
            VerificationOutcome::INTEGRITY_VERIFIED_UNTRUSTED => $allowUntrusted ? 0 : 2,
            VerificationOutcome::ANCHOR_BELOW_MIN           => 3,
            VerificationOutcome::INVALID_CHAIN,
            VerificationOutcome::INVALID_SIGNATURE,
            VerificationOutcome::INVALID_ANCHOR             => 4,
            VerificationOutcome::PROVIDER_DISAGREEMENT      => 5,
        };
    }
}
