<?php
declare(strict_types=1);

namespace Fissible\Attest\Cli\Command;

use Fissible\Attest\Bundle\BundleReader;
use Fissible\Attest\Bundle\BundleStore;
use Fissible\Attest\Bundle\BundleSupportUnavailable;
use Fissible\Attest\Bundle\InvalidBundle;
use Fissible\Attest\Cli\Output\HumanResultEmitter;
use Fissible\Attest\Cli\Output\JsonResultEmitter;
use Fissible\Attest\Cli\Output\RuntimeErrorEmitter;
use Fissible\Attest\Cli\Support\AnchorDriverFactory;
use Fissible\Attest\Cli\Support\HeaderProviderFactory;
use Fissible\Attest\Cli\Support\MinAnchorOption;
use Fissible\Attest\Cli\Support\TrustedKeyLoader;
use Fissible\Attest\Verification\SignatureVerifier;
use Fissible\Attest\Verification\VerificationOutcome;
use Fissible\Attest\Verification\VerificationPolicy;
use Fissible\Attest\Verification\VerificationResult;
use Fissible\Attest\Verification\Verifier;
use Fissible\Attest\Verification\Warning;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'bundle:verify', description: 'Verify a bundle against trusted keys and policy.')]
/**
 * @internal
 */
final class BundleVerifyCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('bundle', null, InputOption::VALUE_REQUIRED, 'Path to the bundle file (.attest).')
            ->addOption('chain', null, InputOption::VALUE_REQUIRED, 'Chain ID to verify (defaults to first chain in manifest).')
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
        $bundlePath = $input->getOption('bundle');

        if (! is_string($bundlePath) || $bundlePath === '') {
            $output->writeln('error: --bundle is required and must not be empty');
            return 1;
        }

        if (! is_file($bundlePath)) {
            $output->writeln('error: --bundle path does not exist or is not a file: ' . $bundlePath);
            return 1;
        }

        try {
            $minAnchor = MinAnchorOption::parse($input->getOption('min-anchor'));

            $trustedKeys = TrustedKeyLoader::load(
                $input->getOption('trusted-key') ?: [],
                $input->getOption('trusted-key-file') ?: [],
            );

            $headers = HeaderProviderFactory::build(
                $input->getOption('bitcoin-core-rpc'),
                $input->getOption('bitcoin-core-cookie'),
                $input->getOption('esplora-url'),
            );
        } catch (\InvalidArgumentException | \RuntimeException $e) {
            $output->writeln('error: ' . $e->getMessage());
            return 1;
        }

        // ── Open bundle ──────────────────────────────────────────────────────
        try {
            $reader = BundleReader::open($bundlePath);
        } catch (BundleSupportUnavailable $e) {
            // Nothing was read, so nothing was found invalid: exit 1, not 4.
            $output->writeln('error: ' . $e->getMessage());
            return 1;
        } catch (InvalidBundle $e) {
            $output->writeln('error: ' . $e->getMessage());
            return 4;
        }

        // ── Resolve chain ────────────────────────────────────────────────────
        $manifest = $reader->manifest();

        if ($manifest->chains === []) {
            $output->writeln('error: bundle manifest contains no chain segments');
            return 4;
        }

        $chainOption = $input->getOption('chain');
        if (is_string($chainOption) && $chainOption !== '') {
            $chainId = $chainOption;
            $segMeta = null;
            foreach ($manifest->chains as $seg) {
                if ($seg->chainId === $chainId) {
                    $segMeta = $seg;
                    break;
                }
            }
            if ($segMeta === null) {
                $output->writeln("error: chain '$chainId' not found in bundle manifest");
                return 4;
            }
        } else {
            $segMeta = $manifest->chains[0];
            $chainId = $segMeta->chainId;
        }

        $fromSeq = $segMeta->fromSeq;
        $toSeq   = $segMeta->toSeq;

        // ── Build BundleStore and collect proof envelopes ────────────────────
        $bundleStore = new BundleStore($reader);

        $json = (bool) $input->getOption('json');
        try {
            $proofEnvelopes = iterator_to_array($reader->readProofEnvelopes($chainId), false);

            // ── Build verifier ───────────────────────────────────────────────
            // CRITICAL: Claimed keys from the bundle are NEVER auto-trusted.
            // Only $trustedKeys (from --trusted-key / --trusted-key-file) are trust inputs.
            //
            // Always register local-only verification. OTS verification is added when
            // the optional Guzzle PSR-18 stack is installed.
            $verifier = new Verifier(
                store: $bundleStore,
                signatures: new SignatureVerifier($trustedKeys),
                policy: new VerificationPolicy(
                    minAnchorOutcome: $minAnchor,
                    allowProviderDisagreement: (bool) $input->getOption('allow-provider-disagreement'),
                    requireTrustedKey: ! $input->getOption('allow-untrusted'),
                ),
                anchorDrivers: AnchorDriverFactory::verificationDrivers(),
                headers: $headers,
                detachedAnchorEnvelopes: $proofEnvelopes,
            );

            $result = $verifier->verifyChain($chainId, $fromSeq, $toSeq);
        } catch (\Throwable $e) {
            // Undecodable chain records are already INVALID_CHAIN outcomes; what
            // escapes here is a runtime failure before an outcome existed.
            return RuntimeErrorEmitter::emit('bundle:verify', $e, $json, $output);
        }

        // ── Merge bundle reader warnings ─────────────────────────────────────
        $readerWarnings = $reader->warnings();
        if ($readerWarnings !== []) {
            $result = new VerificationResult(
                outcome: $result->outcome,
                chainStats: $result->chainStats,
                warnings: [...$result->warnings, ...$readerWarnings],
                brokenAtSeq: $result->brokenAtSeq,
                message: $result->message,
                signatureResults: $result->signatureResults,
                anchorVerification: $result->anchorVerification,
            );
        }

        $allowUntrusted = (bool) $input->getOption('allow-untrusted');
        $exit = self::exitCodeFor($result->outcome, $allowUntrusted);

        // ── Emit output ──────────────────────────────────────────────────────
        if ($json) {
            $emitter = new JsonResultEmitter();
        } else {
            $output->writeln('bundle: ' . $bundlePath . ' (chain: ' . $chainId . ', seqs ' . $fromSeq . '-' . $toSeq . ')');
            $emitter = new HumanResultEmitter();
        }
        $emitter->emit('bundle:verify', $result, $exit, $output);

        return $exit;
    }

    /**
     * Spec §13 exit-code mapping.
     *
     * 0 — VERIFIED (also INTEGRITY_VERIFIED_UNTRUSTED with --allow-untrusted)
     * 1 — CLI/config/runtime error before a VerificationOutcome  [handled above]
     * 2 — INTEGRITY_VERIFIED_UNTRUSTED (without --allow-untrusted)
     * 3 — ANCHOR_BELOW_MIN
     * 4 — INVALID_CHAIN / INVALID_SIGNATURE / INVALID_ANCHOR / bundle open error
     * 5 — PROVIDER_DISAGREEMENT
     */
    private static function exitCodeFor(VerificationOutcome $outcome, bool $allowUntrusted): int
    {
        return match ($outcome) {
            VerificationOutcome::VERIFIED                      => 0,
            VerificationOutcome::INTEGRITY_VERIFIED_UNTRUSTED  => $allowUntrusted ? 0 : 2,
            VerificationOutcome::ANCHOR_BELOW_MIN              => 3,
            VerificationOutcome::INVALID_CHAIN,
            VerificationOutcome::INVALID_SIGNATURE,
            VerificationOutcome::INVALID_ANCHOR                => 4,
            VerificationOutcome::PROVIDER_DISAGREEMENT         => 5,
        };
    }
}
