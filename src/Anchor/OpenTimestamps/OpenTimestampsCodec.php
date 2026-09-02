<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

/**
 * @experimental
 */
final class OpenTimestampsCodec
{
    private const HEADER_MAGIC = "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
    private const MAJOR_VERSION = 1;
    private const ATTESTATION_TAG = "\x00";
    private const FORK_TAG = "\xff";
    private const MAX_RECEIPT_BYTES = 1048576;
    private const MAX_RECURSION = 256;

    public static function encodeDetached(OpenTimestampsProof $proof): string
    {
        $writer = new OpenTimestampsWriteBuffer();
        $writer->writeBytes(self::HEADER_MAGIC);
        $writer->writeByte(self::MAJOR_VERSION);
        $writer->writeBytes(OpenTimestampsOperation::TAG_SHA256);
        $writer->writeBytes($proof->fileDigest);
        self::writeTimestamp($writer, $proof->timestamp);

        return $writer->bytes();
    }

    public static function encodeTimestampBytes(OpenTimestampsTimestamp $timestamp): string
    {
        $writer = new OpenTimestampsWriteBuffer();
        self::writeTimestamp($writer, $timestamp);

        return $writer->bytes();
    }

    public static function decodeDetached(string $bytes, ?string $expectedRootHex = null): OpenTimestampsProof
    {
        if (strlen($bytes) > self::MAX_RECEIPT_BYTES) {
            throw new \InvalidArgumentException('OpenTimestamps receipt exceeds max size');
        }

        $reader = new OpenTimestampsReadBuffer($bytes);
        $reader->expectBytes(self::HEADER_MAGIC);
        $version = $reader->readByte();
        if ($version !== self::MAJOR_VERSION) {
            throw new \InvalidArgumentException('Unsupported OpenTimestamps major version: ' . $version);
        }

        $fileHashTag = $reader->readBytes(1);
        if ($fileHashTag !== OpenTimestampsOperation::TAG_SHA256) {
            throw new \InvalidArgumentException('Only SHA-256 detached OpenTimestamps files are supported');
        }

        $fileDigest = $reader->readBytes(32);
        $timestamp = self::readTimestamp($reader, $fileDigest, self::MAX_RECURSION);
        $reader->assertEof();

        $proof = new OpenTimestampsProof($fileDigest, $timestamp);
        if ($expectedRootHex !== null) {
            $proof->assertFileDigestHex($expectedRootHex);
        }

        return $proof;
    }

    public static function decodeTimestampBytes(string $bytes, string $message): OpenTimestampsTimestamp
    {
        if (strlen($bytes) > self::MAX_RECEIPT_BYTES) {
            throw new \InvalidArgumentException('OpenTimestamps timestamp exceeds max size');
        }

        $reader = new OpenTimestampsReadBuffer($bytes);
        $timestamp = self::readTimestamp($reader, $message, self::MAX_RECURSION);
        $reader->assertEof();

        return $timestamp;
    }

    private static function writeTimestamp(OpenTimestampsWriteBuffer $writer, OpenTimestampsTimestamp $timestamp): void
    {
        if ($timestamp->isEmpty()) {
            throw new \InvalidArgumentException('OpenTimestamps timestamp node must not be empty');
        }

        $attestations = $timestamp->attestations;
        usort($attestations, static fn (
            OpenTimestampsAttestation $a,
            OpenTimestampsAttestation $b,
        ): int => $a->compare($b));

        $branches = $timestamp->branches;
        usort($branches, static fn (
            OpenTimestampsBranch $a,
            OpenTimestampsBranch $b,
        ): int => $a->operation->compare($b->operation));

        if (count($attestations) > 1) {
            for ($i = 0; $i < count($attestations) - 1; $i++) {
                $writer->writeBytes(self::FORK_TAG);
                self::writeAttestation($writer, $attestations[$i]);
            }
        }

        if ($branches === []) {
            self::writeAttestation($writer, $attestations[count($attestations) - 1]);
            return;
        }

        if ($attestations !== []) {
            $writer->writeBytes(self::FORK_TAG);
            self::writeAttestation($writer, $attestations[count($attestations) - 1]);
        }

        for ($i = 0; $i < count($branches) - 1; $i++) {
            $writer->writeBytes(self::FORK_TAG);
            self::writeOperation($writer, $branches[$i]->operation);
            self::writeTimestamp($writer, $branches[$i]->timestamp);
        }

        $last = $branches[count($branches) - 1];
        self::writeOperation($writer, $last->operation);
        self::writeTimestamp($writer, $last->timestamp);
    }

    private static function writeAttestation(OpenTimestampsWriteBuffer $writer, OpenTimestampsAttestation $attestation): void
    {
        $writer->writeBytes(self::ATTESTATION_TAG);
        $writer->writeBytes($attestation->tag);
        $writer->writeVarbytes($attestation->payload);
    }

    private static function writeOperation(OpenTimestampsWriteBuffer $writer, OpenTimestampsOperation $operation): void
    {
        $writer->writeBytes($operation->tag);
        if ($operation->tag === OpenTimestampsOperation::TAG_APPEND
            || $operation->tag === OpenTimestampsOperation::TAG_PREPEND
        ) {
            $writer->writeVarbytes($operation->argument ?? '');
        }
    }

    private static function readTimestamp(
        OpenTimestampsReadBuffer $reader,
        string $message,
        int $recursionRemaining,
    ): OpenTimestampsTimestamp {
        if ($recursionRemaining < 1) {
            throw new \InvalidArgumentException('OpenTimestamps timestamp exceeds max recursion depth');
        }

        $timestamp = new OpenTimestampsTimestamp($message);
        $tag = $reader->readBytes(1);
        while ($tag === self::FORK_TAG) {
            $timestamp = self::readTagOrAttestation($reader, $timestamp, $reader->readBytes(1), $recursionRemaining);
            $tag = $reader->readBytes(1);
        }

        return self::readTagOrAttestation($reader, $timestamp, $tag, $recursionRemaining);
    }

    private static function readTagOrAttestation(
        OpenTimestampsReadBuffer $reader,
        OpenTimestampsTimestamp $timestamp,
        string $tag,
        int $recursionRemaining,
    ): OpenTimestampsTimestamp {
        if ($tag === self::ATTESTATION_TAG) {
            $attestationTag = $reader->readBytes(OpenTimestampsAttestation::TAG_SIZE);
            $payload = $reader->readVarbytes(OpenTimestampsAttestation::MAX_PAYLOAD_SIZE);
            return $timestamp->withAttestation(OpenTimestampsAttestation::fromPayload($attestationTag, $payload));
        }

        $operation = self::readOperation($reader, $tag);
        $result = $operation->apply($timestamp->message);
        $child = self::readTimestamp($reader, $result, $recursionRemaining - 1);

        return $timestamp->withOperation($operation, $child);
    }

    private static function readOperation(OpenTimestampsReadBuffer $reader, string $tag): OpenTimestampsOperation
    {
        if ($tag === OpenTimestampsOperation::TAG_SHA256) {
            return OpenTimestampsOperation::sha256();
        }
        if ($tag === OpenTimestampsOperation::TAG_APPEND) {
            return OpenTimestampsOperation::append($reader->readVarbytes(OpenTimestampsOperation::MAX_ARGUMENT_BYTES));
        }
        if ($tag === OpenTimestampsOperation::TAG_PREPEND) {
            return OpenTimestampsOperation::prepend($reader->readVarbytes(OpenTimestampsOperation::MAX_ARGUMENT_BYTES));
        }

        throw new \InvalidArgumentException('Unsupported OpenTimestamps operation tag: ' . bin2hex($tag));
    }
}

final class OpenTimestampsReadBuffer
{
    private int $offset = 0;

    public function __construct(private readonly string $bytes)
    {
    }

    public function readByte(): int
    {
        return ord($this->readBytes(1));
    }

    public function readBytes(int $length): string
    {
        if ($length < 0) {
            throw new \InvalidArgumentException('length must be >= 0');
        }
        if ($this->offset + $length > strlen($this->bytes)) {
            throw new \InvalidArgumentException('truncated OpenTimestamps receipt');
        }

        $out = substr($this->bytes, $this->offset, $length);
        $this->offset += $length;

        return $out;
    }

    public function readVaruint(): int
    {
        $value = 0;
        $shift = 0;
        while (true) {
            $byte = $this->readByte();
            // Nine 7-bit groups fill bits 0..62; a tenth group would shift
            // past the sign bit and wrap silently in PHP's signed arithmetic.
            if ($shift > 56) {
                throw new \InvalidArgumentException('OpenTimestamps varuint is too large');
            }
            if (($byte & 0x80) === 0) {
                if ($byte === 0 && $shift > 0) {
                    throw new \InvalidArgumentException('OpenTimestamps varuint is not minimally encoded');
                }
                return $value | ($byte << $shift);
            }
            $value |= ($byte & 0x7f) << $shift;
            $shift += 7;
        }
    }

    public function readVarbytes(int $maxLength, int $minLength = 0): string
    {
        $length = $this->readVaruint();
        if ($length > $maxLength) {
            throw new \InvalidArgumentException('OpenTimestamps varbytes exceeds max length');
        }
        if ($length < $minLength) {
            throw new \InvalidArgumentException('OpenTimestamps varbytes below min length');
        }

        return $this->readBytes($length);
    }

    public function expectBytes(string $expected): void
    {
        $actual = $this->readBytes(strlen($expected));
        if ($actual !== $expected) {
            throw new \InvalidArgumentException('OpenTimestamps magic/header mismatch');
        }
    }

    public function assertEof(): void
    {
        if ($this->offset !== strlen($this->bytes)) {
            throw new \InvalidArgumentException('OpenTimestamps receipt has trailing garbage');
        }
    }
}

final class OpenTimestampsWriteBuffer
{
    private string $bytes = '';

    public function writeByte(int $byte): void
    {
        if ($byte < 0 || $byte > 255) {
            throw new \InvalidArgumentException('byte out of range');
        }
        $this->bytes .= chr($byte);
    }

    public function writeBytes(string $bytes): void
    {
        $this->bytes .= $bytes;
    }

    public function writeVaruint(int $value): void
    {
        if ($value < 0) {
            throw new \InvalidArgumentException('varuint value must be >= 0');
        }
        if ($value === 0) {
            $this->writeByte(0);
            return;
        }
        while ($value !== 0) {
            $byte = $value & 0x7f;
            $value >>= 7;
            if ($value !== 0) {
                $byte |= 0x80;
            }
            $this->writeByte($byte);
        }
    }

    public function writeVarbytes(string $bytes): void
    {
        $this->writeVaruint(strlen($bytes));
        $this->writeBytes($bytes);
    }

    public function bytes(): string
    {
        return $this->bytes;
    }
}
