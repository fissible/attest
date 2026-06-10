<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Anchor\OpenTimestamps\CalendarUnavailable;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsBranch;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCalendarClient;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsOperation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Headers\HeaderLookupStatus;
use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Headers\TrustLevel;
use Fissible\Attest\Verification\AnchorVerification;
use Fissible\Attest\Verification\Warning;

/**
 * @experimental
 */
final class OpenTimestampsDriver implements AnchorDriver
{
    public const NAME = 'opentimestamps';

    /**
     * @param list<string> $calendarUrls
     * @param list<string> $upgradeAllowlist
     */
    public function __construct(
        private readonly OpenTimestampsCalendarClient $calendarClient,
        private readonly array $calendarUrls = [
            'https://a.pool.opentimestamps.org',
            'https://b.pool.opentimestamps.org',
            'https://a.pool.eternitywall.com',
            'https://ots.btc.catallaxy.com',
        ],
        private readonly int $minCalendars = 1,
        private readonly array $upgradeAllowlist = [
            'https://a.pool.opentimestamps.org',
            'https://b.pool.opentimestamps.org',
            'https://a.pool.eternitywall.com',
            'https://ots.btc.catallaxy.com',
        ],
    ) {
        if ($calendarUrls === []) {
            throw new \InvalidArgumentException('At least one OpenTimestamps calendar URL is required');
        }
        if ($minCalendars < 1) {
            throw new \InvalidArgumentException('minCalendars must be >= 1');
        }
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function anchor(AnchorTarget $target): AnchorReceipt
    {
        $rootBytes = $this->rootBytes($target);
        $nonce = random_bytes(16);
        $append = OpenTimestampsOperation::append($nonce);
        $sha256 = OpenTimestampsOperation::sha256();
        $commitment = $sha256->apply($append->apply($rootBytes));

        $remoteBranches = [];
        $failures = [];
        foreach ($this->calendarUrls as $calendarUrl) {
            try {
                $remoteBranches[] = new OpenTimestampsBranch(
                    $append,
                    new OpenTimestampsTimestamp(
                        $append->apply($rootBytes),
                        branches: [
                            new OpenTimestampsBranch(
                                $sha256,
                                $this->calendarClient->submit($calendarUrl, $commitment),
                            ),
                        ],
                    ),
                );
            } catch (CalendarUnavailable $e) {
                $failures[] = $calendarUrl . ': ' . $e->getMessage();
            }
        }

        if (count($remoteBranches) < $this->minCalendars) {
            throw new CalendarUnavailable(sprintf(
                'OpenTimestamps anchor submission reached %d/%d required calendars%s',
                count($remoteBranches),
                $this->minCalendars,
                $failures === [] ? '' : ' (' . implode('; ', $failures) . ')',
            ));
        }

        $proof = new OpenTimestampsProof($rootBytes, new OpenTimestampsTimestamp($rootBytes, branches: $remoteBranches));

        return $this->receipt($target, $proof);
    }

    public function upgrade(AnchorReceipt $receipt): AnchorReceipt
    {
        if (! $this->supports($receipt)) {
            throw new \InvalidArgumentException('OpenTimestampsDriver does not support receipt driver: ' . $receipt->driverName);
        }

        $proof = OpenTimestampsCodec::decodeDetached($receipt->receiptBytes, $receipt->target->rootHex);
        $upgradedTimestamp = $this->upgradeTimestamp($proof->timestamp);
        $upgradedProof = new OpenTimestampsProof($proof->fileDigest, $upgradedTimestamp);

        if (OpenTimestampsCodec::encodeDetached($upgradedProof) === $receipt->receiptBytes) {
            return $receipt;
        }

        return $this->receipt($receipt->target, $upgradedProof);
    }

    public function verify(AnchorReceipt $receipt, HeaderProviderSet $headers): AnchorVerification
    {
        if (! $this->supports($receipt)) {
            return AnchorVerification::invalid(
                $receipt,
                'OpenTimestampsDriver does not support receipt driver: ' . $receipt->driverName,
            );
        }

        try {
            $proof = OpenTimestampsCodec::decodeDetached($receipt->receiptBytes, $receipt->target->rootHex);
        } catch (\Throwable $e) {
            return AnchorVerification::invalid($receipt, 'Invalid OpenTimestamps receipt: ' . $e->getMessage());
        }

        $bitcoinPaths = array_values(array_filter(
            $proof->timestamp->allAttestations(),
            static fn ($path): bool => $path->attestation->isBitcoin(),
        ));

        if ($bitcoinPaths === []) {
            return new AnchorVerification($receipt, AnchorOutcome::PENDING);
        }

        if (count($headers) === 0) {
            return new AnchorVerification($receipt, AnchorOutcome::UPGRADED_NO_HEADERS);
        }

        $bestPassing = null;
        $sawMismatchWithoutPass = false;
        $warnings = [];
        foreach ($bitcoinPaths as $path) {
            $height = $path->attestation->height;
            if ($height === null) {
                continue;
            }
            $expectedMerkleRoot = bin2hex($path->message);
            $passes = [];
            $mismatches = [];
            $unknowns = [];
            $activeByProvider = [];

            foreach ($headers as $provider) {
                $lookup = $provider->getActiveChainHeaderByHeight($height);
                if ($lookup->status !== HeaderLookupStatus::ACTIVE || $lookup->header === null) {
                    $unknowns[] = $lookup->providerName;
                    $warnings[] = new Warning(
                        Warning::HEADER_PROVIDER_UNKNOWN,
                        'Header provider could not confirm OTS attestation height.',
                        [
                            'provider' => $lookup->providerName,
                            'height' => $height,
                            'status' => $lookup->status->value,
                            'diagnostic' => $lookup->diagnostic,
                        ],
                    );
                    continue;
                }

                $activeByProvider[$lookup->providerName] = $lookup->header->blockHash;
                if ($lookup->header->merkleRoot !== $expectedMerkleRoot) {
                    $mismatches[] = $lookup;
                    continue;
                }

                $passes[] = $lookup;
            }

            $hashes = array_unique(array_values($activeByProvider));
            if (count($hashes) > 1) {
                $best = $this->bestPassingLookup($passes);
                $agreedPassingHash = $this->agreedPassingHash($passes);

                return AnchorVerification::providerDisagreement(
                    receipt: $receipt,
                    message: 'Header providers returned different active block hashes at the OTS attested height',
                    strongestPassingOutcome: $best === null || $agreedPassingHash === null
                        ? null
                        : $this->outcomeForTrust($best->trustLevel),
                    warnings: $warnings,
                    context: [
                        'height' => $height,
                        'active_hashes_by_provider' => $activeByProvider,
                        'passing_providers' => array_map(static fn ($lookup): string => $lookup->providerName, $passes),
                        'agreed_passing_hash' => $agreedPassingHash,
                    ],
                );
            }

            if ($passes !== [] && $mismatches !== []) {
                $best = $this->bestPassingLookup($passes);

                return AnchorVerification::providerDisagreement(
                    receipt: $receipt,
                    message: 'Header providers disagreed on whether the OTS attestation matches the active header merkle root',
                    strongestPassingOutcome: $best === null ? null : $this->outcomeForTrust($best->trustLevel),
                    warnings: $warnings,
                    context: [
                        'height' => $height,
                        'passing_providers' => array_map(static fn ($lookup): string => $lookup->providerName, $passes),
                        'mismatching_providers' => array_map(static fn ($lookup): string => $lookup->providerName, $mismatches),
                    ],
                );
            }

            if ($passes === [] && $mismatches !== []) {
                $sawMismatchWithoutPass = true;
                continue;
            }

            $bestForPath = $this->bestPassingLookup($passes);
            if ($bestForPath !== null
                && ($bestPassing === null || $bestForPath->trustLevel->strength() > $bestPassing->trustLevel->strength())
            ) {
                $bestPassing = $bestForPath;
            }

            if ($passes === [] && $mismatches === [] && $unknowns !== []) {
                continue;
            }
        }

        if ($bestPassing !== null) {
            return new AnchorVerification(
                receipt: $receipt,
                outcome: $this->outcomeForTrust($bestPassing->trustLevel),
                warnings: $warnings,
                providerName: $bestPassing->providerName,
            );
        }

        if ($sawMismatchWithoutPass) {
            return AnchorVerification::invalid(
                $receipt,
                'OpenTimestamps Bitcoin attestation did not match any active header merkle root',
            );
        }

        return new AnchorVerification($receipt, AnchorOutcome::UPGRADED_NO_HEADERS, warnings: $warnings);
    }

    /**
     * @param list<\Fissible\Attest\Headers\HeaderLookupResult> $passes
     */
    private function bestPassingLookup(array $passes): ?\Fissible\Attest\Headers\HeaderLookupResult
    {
        $best = null;
        foreach ($passes as $pass) {
            if ($best === null || $pass->trustLevel->strength() > $best->trustLevel->strength()) {
                $best = $pass;
            }
        }

        return $best;
    }

    /**
     * @param list<\Fissible\Attest\Headers\HeaderLookupResult> $passes
     */
    private function agreedPassingHash(array $passes): ?string
    {
        $counts = [];
        foreach ($passes as $pass) {
            if ($pass->header === null) {
                continue;
            }
            $counts[$pass->header->blockHash] = ($counts[$pass->header->blockHash] ?? 0) + 1;
        }

        foreach ($counts as $hash => $count) {
            if ($count >= 2) {
                return $hash;
            }
        }

        return null;
    }

    private function outcomeForTrust(TrustLevel $trustLevel): AnchorOutcome
    {
        return match ($trustLevel) {
            TrustLevel::LOCAL => AnchorOutcome::BITCOIN_VERIFIED,
            TrustLevel::REMOTE => AnchorOutcome::REMOTE_HEADER_CONFIRMED,
        };
    }

    public function supports(AnchorReceipt $receipt): bool
    {
        return $receipt->driverName === $this->name();
    }

    private function upgradeTimestamp(OpenTimestampsTimestamp $timestamp): OpenTimestampsTimestamp
    {
        $attestations = [];
        foreach ($timestamp->attestations as $attestation) {
            if (! $attestation->isPending() || $attestation->uri === null || ! $this->isUpgradeAllowed($attestation->uri)) {
                $attestations[] = $attestation;
                continue;
            }

            try {
                $upgraded = $this->calendarClient->upgrade($attestation->uri, $timestamp->message);
                $attestations = [...$attestations, ...$upgraded->attestations];
                foreach ($upgraded->branches as $branch) {
                    $timestamp = $timestamp->withOperation($branch->operation, $branch->timestamp);
                }
            } catch (CalendarUnavailable) {
                $attestations[] = $attestation;
            }
        }

        $branches = [];
        foreach ($timestamp->branches as $branch) {
            $branches[] = new OpenTimestampsBranch($branch->operation, $this->upgradeTimestamp($branch->timestamp));
        }

        return new OpenTimestampsTimestamp($timestamp->message, $attestations, $branches);
    }

    private function isUpgradeAllowed(string $uri): bool
    {
        foreach ($this->upgradeAllowlist as $allowed) {
            if ($uri === rtrim($allowed, '/')) {
                return true;
            }
        }

        return false;
    }

    private function receipt(AnchorTarget $target, OpenTimestampsProof $proof): AnchorReceipt
    {
        return new AnchorReceipt(
            driverName: $this->name(),
            target: $target,
            state: $proof->state(),
            receiptBytes: OpenTimestampsCodec::encodeDetached($proof),
            createdAtIso8601: $this->nowIso8601(),
        );
    }

    private function rootBytes(AnchorTarget $target): string
    {
        $rootBytes = hex2bin($target->rootHex);
        if ($rootBytes === false) {
            throw new \InvalidArgumentException('Invalid target root hex');
        }

        return $rootBytes;
    }

    private function nowIso8601(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z');
    }
}
