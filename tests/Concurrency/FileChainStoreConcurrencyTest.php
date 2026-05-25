<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Concurrency;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Signing\KeyPair;
use Fissible\Attest\Signing\SodiumSigner;
use PHPUnit\Framework\TestCase;

/**
 * Verifies FileChainStore's per-chain lock prevents interleaved appends
 * from corrupting prev_hash continuity or producing duplicate seqs.
 *
 * Requires pcntl. Auto-skipped on platforms without it (Windows).
 */
final class FileChainStoreConcurrencyTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        if (! function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        $this->root = sys_get_temp_dir() . '/attest-concurrent-' . bin2hex(random_bytes(8));
        mkdir($this->root, 0o700, recursive: true);
    }

    protected function tearDown(): void
    {
        if (isset($this->root)) {
            @system('rm -rf ' . escapeshellarg($this->root));
        }
    }

    public function test_8_workers_appending_100_envelopes_produces_single_linear_chain(): void
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $seedFile = $this->root . '/seed';
        file_put_contents($seedFile, $seed);

        $workers = 8;
        $perWorker = 100;
        $pids = [];

        for ($w = 0; $w < $workers; $w++) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                $this->fail('fork failed');
            }
            if ($pid === 0) {
                // Child.
                $childSeed = (string) file_get_contents($seedFile);
                $signer = new SodiumSigner(KeyPair::fromSeed($childSeed), 'shared');
                $chain = EvidenceChain::open(
                    store: new FileChainStore($this->root),
                    chainId: 'shared',
                    signer: $signer,
                );
                for ($i = 0; $i < $perWorker; $i++) {
                    $chain->record('worker-event', ['w' => $w, 'i' => $i]);
                }
                exit(0);
            }
            $pids[] = $pid;
        }

        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
            $this->assertSame(0, pcntl_wexitstatus($status), "worker $pid exited non-zero");
        }

        $store = new FileChainStore($this->root);
        $envs = iterator_to_array($store->readRange('shared', 1), false);
        $this->assertCount($workers * $perWorker, $envs);

        $prevHash = null;
        $prevSeq = 0;
        foreach ($envs as $env) {
            $this->assertSame(
                $prevSeq + 1,
                $env->envelope->seq,
                "seq gap or duplicate at seq {$env->envelope->seq}",
            );
            $this->assertSame(
                $prevHash,
                $env->envelope->prevHash,
                "prev_hash break at seq {$env->envelope->seq}",
            );
            $prevSeq = $env->envelope->seq;
            $prevHash = $env->selfHash();
        }
    }
}
