<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

/**
 * The runtime cannot read or write bundles because ext-zip is not loaded.
 *
 * Deliberately not an InvalidBundle: nothing is known about the bundle's
 * contents, so reporting it as invalid would claim a verification result that
 * was never computed.
 *
 * @api
 */
final class BundleSupportUnavailable extends \RuntimeException
{
    public static function missingZipExtension(string $operation): self
    {
        return new self(
            "Cannot $operation an attest bundle: the PHP zip extension (ext-zip) is not loaded. "
            . 'Install/enable ext-zip, or use the chain APIs directly if you do not need bundles.'
        );
    }
}
