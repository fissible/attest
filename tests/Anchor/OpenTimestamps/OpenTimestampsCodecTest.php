<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Anchor\OpenTimestamps;

use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsAttestation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsCodec;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsOperation;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsProof;
use Fissible\Attest\Anchor\OpenTimestamps\OpenTimestampsTimestamp;
use Fissible\Attest\Anchor\ProofState;
use PHPUnit\Framework\TestCase;

final class OpenTimestampsCodecTest extends TestCase
{
    public function test_fixture_decodes_and_serializes_byte_identically(): void
    {
        $bytes = $this->fixtureBytes('pending-detached.hex');

        $proof = OpenTimestampsCodec::decodeDetached($bytes, str_repeat('11', 32));

        $this->assertSame(str_repeat('11', 32), $proof->fileDigestHex());
        $this->assertSame(ProofState::PENDING, $proof->state());
        $this->assertSame($bytes, OpenTimestampsCodec::encodeDetached($proof));
    }

    public function test_applying_operation_tree_reaches_attested_digest(): void
    {
        $proof = OpenTimestampsCodec::decodeDetached($this->fixtureBytes('pending-detached.hex'));

        $attestations = $proof->timestamp->allAttestations();

        $this->assertCount(1, $attestations);
        $expected = hash('sha256', $proof->fileDigest . 'nonce', binary: true);
        $this->assertSame($expected, $attestations[0]->message);
        $this->assertSame('https://a.pool.opentimestamps.org', $attestations[0]->attestation->uri);
    }

    public function test_expected_root_mismatch_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('file digest');

        OpenTimestampsCodec::decodeDetached($this->fixtureBytes('pending-detached.hex'), str_repeat('22', 32));
    }

    public function test_bitcoin_attestation_classifies_as_upgraded(): void
    {
        $rootHex = str_repeat('22', 32);
        $digest = hex2bin($rootHex);
        $this->assertIsString($digest);
        $timestamp = (new OpenTimestampsTimestamp($digest))
            ->withAttestation(OpenTimestampsAttestation::bitcoin(840000));
        $proof = new OpenTimestampsProof($digest, $timestamp);

        $decoded = OpenTimestampsCodec::decodeDetached(OpenTimestampsCodec::encodeDetached($proof), $rootHex);
        $attestations = $decoded->timestamp->allAttestations();

        $this->assertSame(ProofState::UPGRADED, $decoded->state());
        $this->assertSame(840000, $attestations[0]->attestation->height);
    }

    public function test_unknown_attestation_round_trips(): void
    {
        $rootHex = str_repeat('33', 32);
        $digest = hex2bin($rootHex);
        $this->assertIsString($digest);
        $unknown = OpenTimestampsAttestation::unknown("\x01\x02\x03\x04\x05\x06\x07\x08", 'payload');
        $timestamp = (new OpenTimestampsTimestamp($digest))->withAttestation($unknown);
        $proof = new OpenTimestampsProof($digest, $timestamp);

        $decoded = OpenTimestampsCodec::decodeDetached(OpenTimestampsCodec::encodeDetached($proof), $rootHex);
        $attestation = $decoded->timestamp->allAttestations()[0]->attestation;

        $this->assertTrue($attestation->isUnknown());
        $this->assertSame($unknown->tag, $attestation->tag);
        $this->assertSame($unknown->payload, $attestation->payload);
        $this->assertSame(ProofState::SUBMITTED, $decoded->state());
    }

    public function test_non_sha256_detached_timestamp_is_rejected(): void
    {
        $bytes = $this->fixtureBytes('pending-detached.hex');
        $bytes[32] = "\x03";

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('SHA-256');

        OpenTimestampsCodec::decodeDetached($bytes);
    }

    public function test_pending_uri_validation_is_restrictive(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('URI');

        OpenTimestampsAttestation::pending('https://example.com/?q=bad');
    }

    public function test_oversized_receipt_is_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('max size');

        OpenTimestampsCodec::decodeDetached(str_repeat("\x00", 1048577));
    }

    public function test_operation_tags_and_arguments(): void
    {
        $this->assertSame(hash('sha256', 'abc', binary: true), OpenTimestampsOperation::sha256()->apply('abc'));
        $this->assertSame('abctail', OpenTimestampsOperation::append('tail')->apply('abc'));
        $this->assertSame('headabc', OpenTimestampsOperation::prepend('head')->apply('abc'));
    }

    private function fixtureBytes(string $name): string
    {
        $hex = trim((string) file_get_contents(__DIR__ . '/fixtures/' . $name));
        $bytes = hex2bin($hex);
        $this->assertIsString($bytes);

        return $bytes;
    }
}
