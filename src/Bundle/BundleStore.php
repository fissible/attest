<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

use Fissible\Attest\Chain\AppendContext;
use Fissible\Attest\Chain\ChainStore;
use Fissible\Attest\Chain\RawChainStore;
use Fissible\Attest\Chain\UndecodableRecord;
use Fissible\Attest\Envelope\EnvelopeCodec;
use Fissible\Attest\Envelope\SignedEnvelope;

/**
 * Wraps a BundleReader as a verifier-compatible ChainStore + RawChainStore.
 *
 * Read-only: append() throws LogicException.
 *
 * Proof envelopes are NOT exposed via readRange()/readRawRange() — they must
 * be fed to Verifier through the detached-anchor constructor channel
 * (Task 3.6 and BundleReader::readProofEnvelopes()).
 * @internal
 */
final class BundleStore implements ChainStore, RawChainStore
{
    public function __construct(private readonly BundleReader $reader)
    {
    }

    /**
     * @throws \LogicException always — BundleStore is read-only.
     */
    public function append(string $chainId, callable $buildAndSign): SignedEnvelope
    {
        throw new \LogicException('BundleStore is read-only; append() is not supported');
    }

    public function tail(string $chainId): ?SignedEnvelope
    {
        $last = null;
        foreach ($this->readRange($chainId, 1) as $env) {
            $last = $env;
        }
        return $last;
    }

    /**
     * @return iterable<SignedEnvelope>
     */
    public function readRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
    {
        foreach ($this->decodedLines($chainId, $fromSeq, $toSeq) as $record) {
            yield $record['env'];
        }
    }

    /**
     * @return iterable<string>
     */
    public function readRawRange(string $chainId, int $fromSeq, ?int $toSeq = null): iterable
    {
        foreach ($this->decodedLines($chainId, $fromSeq, $toSeq) as $record) {
            yield $record['raw'];
        }
    }

    /**
     * Same positional rule as FileChainStore: a line that does not decode takes
     * the sequence after the last decoded one; inside the range that is an
     * UndecodableRecord, before it is skipped, after it ends the read.
     *
     * @return iterable<array{raw: string, env: SignedEnvelope}>
     */
    private function decodedLines(string $chainId, int $fromSeq, ?int $toSeq): iterable
    {
        $lastSeq = 0;
        foreach ($this->reader->readChainSegmentRaw($chainId) as $raw) {
            try {
                $env = EnvelopeCodec::decodeSigned($raw);
            } catch (\Throwable $e) {
                $assumedSeq = $lastSeq + 1;
                if ($toSeq !== null && $assumedSeq > $toSeq) {
                    break;
                }
                if ($assumedSeq < $fromSeq) {
                    $lastSeq = $assumedSeq;
                    continue;
                }
                throw UndecodableRecord::wrap($chainId, $assumedSeq, $e);
            }
            $lastSeq = $env->envelope->seq;
            if ($env->envelope->seq < $fromSeq) {
                continue;
            }
            if ($toSeq !== null && $env->envelope->seq > $toSeq) {
                break;
            }
            yield ['raw' => $raw, 'env' => $env];
        }
    }

    /**
     * @return iterable<string>
     */
    public function listChains(): iterable
    {
        foreach ($this->reader->manifest()->chains as $segMeta) {
            yield $segMeta->chainId;
        }
    }

    public function exists(string $chainId): bool
    {
        foreach ($this->reader->manifest()->chains as $segMeta) {
            if ($segMeta->chainId === $chainId) {
                return true;
            }
        }
        return false;
    }
}
