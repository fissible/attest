<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Verification\AnchorVerification;

/**
 * @experimental
 */
final class NullDriver implements AnchorDriver
{
    public const NAME = 'local-only';

    public function name(): string
    {
        return self::NAME;
    }

    public function anchor(AnchorTarget $target): AnchorReceipt
    {
        return new AnchorReceipt(
            driverName: $this->name(),
            target: $target,
            state: ProofState::SUBMITTED,
            receiptBytes: '',
            createdAtIso8601: $this->nowIso8601(),
        );
    }

    public function upgrade(AnchorReceipt $receipt): AnchorReceipt
    {
        if (! $this->supports($receipt)) {
            throw new \InvalidArgumentException('NullDriver does not support receipt driver: ' . $receipt->driverName);
        }

        return $receipt;
    }

    public function verify(AnchorReceipt $receipt, HeaderProviderSet $headers): AnchorVerification
    {
        if (! $this->supports($receipt)) {
            return AnchorVerification::invalid($receipt, 'NullDriver does not support receipt driver: ' . $receipt->driverName);
        }

        return new AnchorVerification($receipt, AnchorOutcome::LOCAL_ONLY);
    }

    public function supports(AnchorReceipt $receipt): bool
    {
        return $receipt->driverName === $this->name();
    }

    private function nowIso8601(): string
    {
        return (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d\TH:i:s.v\Z');
    }
}
