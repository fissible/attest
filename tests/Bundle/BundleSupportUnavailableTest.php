<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Bundle;

use Fissible\Attest\Bundle\BundleExportException;
use Fissible\Attest\Bundle\BundleSupportUnavailable;
use Fissible\Attest\Bundle\InvalidBundle;
use PHPUnit\Framework\TestCase;

/**
 * ext-zip is a suggest, not a require, so the bundle entry points guard on it
 * at runtime. The guard itself cannot be exercised where zip is loaded — CI
 * loads it, since the bundle suite needs it — so what is pinned here is the
 * part that would silently misreport if it drifted: which exception type a
 * missing extension produces, and therefore which exit code the CLI returns.
 */
final class BundleSupportUnavailableTest extends TestCase
{
    public function test_names_the_extension_and_the_operation(): void
    {
        $read = BundleSupportUnavailable::missingZipExtension('read');

        $this->assertStringContainsString('ext-zip', $read->getMessage());
        $this->assertStringContainsString('read', $read->getMessage());
        $this->assertStringContainsString(
            'write',
            BundleSupportUnavailable::missingZipExtension('write')->getMessage(),
        );
    }

    /**
     * A missing extension means nothing was read, so nothing was found
     * invalid. Were this an InvalidBundle, bundle:verify would exit 4 and
     * report an environment gap as a failed verification — the one thing a
     * tamper-evidence tool must never confuse.
     */
    public function test_is_not_confusable_with_a_verification_failure(): void
    {
        $e = BundleSupportUnavailable::missingZipExtension('read');

        $this->assertNotInstanceOf(InvalidBundle::class, $e);
        $this->assertNotInstanceOf(BundleExportException::class, $e);
        $this->assertInstanceOf(\RuntimeException::class, $e);
    }
}
