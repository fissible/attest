<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final class BundleConstants
{
    public const FORMAT = 'fissible.attest.bundle/v1';

    public const MANIFEST_ENTRY = 'manifest.json';
    public const CHAINS_PREFIX = 'chains/';
    public const PROOF_ENVELOPES_PREFIX = 'proof_envelopes/';
    public const RECEIPTS_PREFIX = 'receipts/';
    public const KEYS_PREFIX = 'keys/';

    public const ALLOWED_PREFIXES = [
        self::CHAINS_PREFIX,
        self::PROOF_ENVELOPES_PREFIX,
        self::RECEIPTS_PREFIX,
        self::KEYS_PREFIX,
    ];

    public const MAX_ENTRY_PATH_LEN = 256;
    public const MAX_MANIFEST_BYTES = 1_048_576;          // 1 MB
    public const MAX_MEMBER_BYTES = 50 * 1_048_576;       // 50 MB
    public const MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1_048_576; // 500 MB
    public const MAX_COMPRESSION_RATIO = 100;             // reject if uncompressed/compressed > 100
}
