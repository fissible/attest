<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Envelope;

use Fissible\Attest\Canonical\JcsEncoder;
use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Envelope\Binary;
use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\PayloadValidator;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

final class BinaryRoundTripTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/attest-binary-' . bin2hex(random_bytes(8));
        mkdir($this->tmpDir, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->tmpDir));
    }

    public function test_payload_validator_canonicalizes_binary_to_array_stand_in(): void
    {
        $payload = ['blob' => Binary::ofRaw('hi')];
        $canonical = PayloadValidator::ensure($payload);

        self::assertSame(
            ['blob' => ['$binary' => base64_encode('hi')]],
            $canonical,
        );
    }

    public function test_jcs_encodes_canonicalized_binary_payload(): void
    {
        $payload = ['blob' => Binary::ofRaw('hi')];
        $canonical = PayloadValidator::ensure($payload);

        $encoded = JcsEncoder::encode($canonical);

        self::assertStringContainsString('"$binary":"' . base64_encode('hi') . '"', $encoded);
    }

    public function test_record_with_binary_payload_signs_and_round_trips_to_storage(): void
    {
        $store = new FileChainStore($this->tmpDir);
        $kp = KeyPair::generate();
        $signer = new SodiumSigner($kp, keyId: 'k1');
        $chain = EvidenceChain::open($store, 'chain-with-binary', $signer);

        $signed = $chain->record('app.event', ['blob' => Binary::ofRaw("\x00\x01\x02hello")]);

        self::assertSame(
            ['blob' => ['$binary' => base64_encode("\x00\x01\x02hello")]],
            $signed->envelope->payload,
        );

        // Round-trip through canonical bytes
        $reread = EnvelopeCodec::decodeSigned($signed->signedCanonicalBytes());
        self::assertSame($signed->signedCanonicalBytes(), $reread->signedCanonicalBytes());
        self::assertSame(
            ['blob' => ['$binary' => base64_encode("\x00\x01\x02hello")]],
            $reread->envelope->payload,
        );
    }

    public function test_binary_oversize_still_fails_at_validation(): void
    {
        $this->expectException(\Fissible\Attest\Envelope\InvalidPayload::class);
        PayloadValidator::ensure(['blob' => Binary::ofRaw(str_repeat('x', Binary::MAX_BYTES + 1))]);
    }
}
