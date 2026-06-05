<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor;

use Fissible\Attest\Headers\HeaderProviderSet;
use Fissible\Attest\Verification\AnchorVerification;

interface AnchorDriver
{
    public function name(): string;

    public function anchor(AnchorTarget $target): AnchorReceipt;

    public function upgrade(AnchorReceipt $receipt): AnchorReceipt;

    public function verify(AnchorReceipt $receipt, HeaderProviderSet $headers): AnchorVerification;

    public function supports(AnchorReceipt $receipt): bool;
}
