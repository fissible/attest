<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Docs;

use PHPUnit\Framework\TestCase;

/**
 * Issue #36: the README told users to pass a .pub path to --trusted-key,
 * which the loader rejects. Pin the two option forms so the examples cannot
 * drift from the CLI again.
 */
final class ReadmeTrustedKeyExamplesTest extends TestCase
{
    private string $readme;

    protected function setUp(): void
    {
        $this->readme = (string) file_get_contents(dirname(__DIR__, 2) . '/README.md');
        self::assertNotSame('', $this->readme);
    }

    public function test_trusted_key_is_never_given_a_file_path(): void
    {
        // A .pub suffix, any path separator, or the <path> placeholder after
        // the inline option are all the same mistake.
        self::assertDoesNotMatchRegularExpression(
            '/--trusted-key[ =]+(?:<path>|\S*\.pub\b|\S*\/\S*)/',
            $this->readme,
            '--trusted-key takes <key_id>=<base64>; file paths belong to --trusted-key-file',
        );
    }

    public function test_trusted_key_file_examples_carry_a_key_id(): void
    {
        preg_match_all('/--trusted-key-file[ =]+(\S+)/', $this->readme, $m);
        self::assertNotEmpty($m[1], 'README must show at least one --trusted-key-file example');
        foreach ($m[1] as $value) {
            if (str_starts_with($value, '<') || str_starts_with($value, '[')) {
                continue; // placeholder syntax such as [<key_id>=]<path>
            }
            self::assertStringContainsString('=', $value, "--trusted-key-file example should bind a key id: $value");
        }
    }

    public function test_readme_explains_plain_path_is_fingerprint_only(): void
    {
        // The statement must sit with the option it qualifies: within 300
        // characters of a --trusted-key-file mention, "plain path" and
        // "fingerprint" both appear.
        self::assertMatchesRegularExpression(
            '/--trusted-key-file.{0,300}plain path.{0,300}fingerprint/s',
            $this->readme,
            'README must say, next to --trusted-key-file, that a plain path (no key id) matches only by fingerprint',
        );
    }
}
