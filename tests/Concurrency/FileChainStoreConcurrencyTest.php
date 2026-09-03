<?php
declare(strict_types=1);

namespace Fissible\Attest\Tests\Concurrency;

use Fissible\Attest\Chain\EvidenceChain;
use Fissible\Attest\Chain\FileChainStore;
use Fissible\Attest\Chain\PathMapper;
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

    /**
     * Issue #35: recovery from a torn tail (discarding the partial line before
     * appending) must happen inside the same critical section as the append.
     * Eight workers start against a file whose last record is torn; exactly
     * one of them may perform the repair, and every record must still land on
     * its own line with contiguous seqs and prev_hash links.
     */
    public function test_workers_appending_after_torn_tail_produce_single_linear_chain(): void
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $seedFile = $this->root . '/seed';
        file_put_contents($seedFile, $seed);
        $signer = new SodiumSigner(KeyPair::fromSeed($seed), 'shared');
        $seedStore = new FileChainStore($this->root);
        $chain = EvidenceChain::open($seedStore, 'shared', $signer);
        $intactFirst = $chain->record('seed', ['n' => 1]);
        $chain->record('seed', ['n' => 2]);
        $path = $this->root . '/chains/' . substr(hash('sha256', 'shared'), 0, 32) . '.jsonl';
        $bytes = (string) file_get_contents($path);
        file_put_contents($path, substr($bytes, 0, strlen($bytes) - 40));

        $workers = 8;
        $perWorker = 25;
        $pids = [];
        for ($w = 0; $w < $workers; $w++) {
            $pid = pcntl_fork();
            if ($pid === -1) {
                $this->fail('fork failed');
            }
            if ($pid === 0) {
                $childSeed = (string) file_get_contents($seedFile);
                $childChain = EvidenceChain::open(
                    store: new FileChainStore($this->root),
                    chainId: 'shared',
                    signer: new SodiumSigner(KeyPair::fromSeed($childSeed), 'shared'),
                );
                for ($i = 0; $i < $perWorker; $i++) {
                    $childChain->record('worker-event', ['w' => $w, 'i' => $i]);
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
        $this->assertCount(1 + $workers * $perWorker, $envs, 'one intact seed record plus every worker append');
        $this->assertSame($intactFirst->signedCanonicalBytes(), $envs[0]->signedCanonicalBytes());

        $lines = explode("\n", rtrim((string) file_get_contents($path), "\n"));
        $this->assertCount(1 + $workers * $perWorker, $lines, 'every record must occupy exactly one line');

        $prevHash = null;
        $prevSeq = 0;
        foreach ($envs as $env) {
            $this->assertSame($prevSeq + 1, $env->envelope->seq, "seq gap or duplicate at seq {$env->envelope->seq}");
            $this->assertSame($prevHash, $env->envelope->prevHash, "prev_hash break at seq {$env->envelope->seq}");
            $prevSeq = $env->envelope->seq;
            $prevHash = $env->selfHash();
        }
    }

    /**
     * Issue #35, deterministic form: while another process holds the append
     * lock, an appender that finds a torn tail must not touch the file. The
     * parent holds LOCK_EX on the chain's lock file, a child calls append()
     * against a torn tail, and the parent checks the torn bytes are still
     * there before releasing the lock. Only after release may the child
     * discard the partial and append.
     *
     * Residual window, accepted deliberately: the child signals readiness just
     * before append(), and the parent then watches the file for 300 ms. A
     * runner that deschedules the child for longer than that between the
     * signal and its lock attempt would let a repair-before-lock
     * implementation slip through. Closing that window needs a hook inside
     * FileChainStore to report lock acquisition, which is test-only code in a
     * production class. A correct implementation cannot fail this test on
     * timing grounds.
     */
    public function test_torn_tail_is_not_repaired_until_the_append_lock_is_held(): void
    {
        $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $seedFile = $this->root . '/seed';
        file_put_contents($seedFile, $seed);
        $signer = new SodiumSigner(KeyPair::fromSeed($seed), 'shared');
        $chain = EvidenceChain::open(new FileChainStore($this->root), 'shared', $signer);
        $first = $chain->record('seed', ['n' => 1]);
        $chain->record('seed', ['n' => 2]);
        $mapper = new PathMapper($this->root);
        $path = $mapper->jsonlPath('shared');
        $bytes = (string) file_get_contents($path);
        $torn = substr($bytes, 0, strlen($bytes) - 40);
        file_put_contents($path, $torn);

        $lockFp = fopen($mapper->lockPath('shared'), 'cb');
        $this->assertIsResource($lockFp);
        $this->assertTrue(flock($lockFp, LOCK_EX));

        $readyFile = $this->root . '/child-ready';
        $pid = pcntl_fork();
        if ($pid === -1) {
            $this->fail('fork failed');
        }
        if ($pid === 0) {
            $childSeed = (string) file_get_contents($seedFile);
            $childChain = EvidenceChain::open(
                store: new FileChainStore($this->root),
                chainId: 'shared',
                signer: new SodiumSigner(KeyPair::fromSeed($childSeed), 'shared'),
            );
            // Signal the parent immediately before entering append().
            touch($readyFile);
            $childChain->record('worker-event', ['after' => 'lock']);
            exit(0);
        }

        // Wait (bounded) for the child to announce it is about to append,
        // then observe the file for a while: any repair attempted before the
        // lock is acquired would show up here as a shortened file.
        $deadline = microtime(true) + 5.0;
        while (! file_exists($readyFile)) {
            $this->assertLessThan($deadline, microtime(true), 'child never signalled readiness');
            usleep(5_000);
        }
        $observeUntil = microtime(true) + 0.3;
        while (microtime(true) < $observeUntil) {
            $this->assertSame($torn, (string) file_get_contents($path), 'file must be untouched while the lock is held elsewhere');
            usleep(10_000);
        }
        $this->assertSame(0, pcntl_waitpid($pid, $status, WNOHANG), 'child must still be blocked on the lock');

        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        pcntl_waitpid($pid, $status);
        $this->assertSame(0, pcntl_wexitstatus($status), 'child exited non-zero');

        $store = new FileChainStore($this->root);
        $envs = iterator_to_array($store->readRange('shared', 1), false);
        $this->assertCount(2, $envs);
        $this->assertSame($first->signedCanonicalBytes(), $envs[0]->signedCanonicalBytes());
        $this->assertSame(2, $envs[1]->envelope->seq);
        $this->assertSame($first->selfHash(), $envs[1]->envelope->prevHash);
        $this->assertSame(
            $envs[0]->signedCanonicalBytes() . "\n" . $envs[1]->signedCanonicalBytes() . "\n",
            (string) file_get_contents($path),
        );
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
