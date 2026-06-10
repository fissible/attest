<?php
declare(strict_types=1);

namespace Fissible\Attest\Headers;

/**
 * @implements \IteratorAggregate<int, BlockHeaderProvider>
 * @experimental
 */
final readonly class HeaderProviderSet implements \Countable, \IteratorAggregate
{
    /** @var list<BlockHeaderProvider> */
    private array $providers;

    public function __construct(BlockHeaderProvider ...$providers)
    {
        $seen = [];
        foreach ($providers as $provider) {
            $name = $provider->name();
            if ($name === '') {
                throw new \InvalidArgumentException('header provider name must not be empty');
            }
            if (isset($seen[$name])) {
                throw new \InvalidArgumentException('duplicate header provider name: ' . $name);
            }
            $seen[$name] = true;
        }

        $this->providers = array_values($providers);
    }

    /**
     * @return list<BlockHeaderProvider>
     */
    public function providers(): array
    {
        return $this->providers;
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_map(static fn (BlockHeaderProvider $provider): string => $provider->name(), $this->providers);
    }

    /**
     * @return array<string, TrustLevel>
     */
    public function trustLevelsByName(): array
    {
        $levels = [];
        foreach ($this->providers as $provider) {
            $levels[$provider->name()] = $provider->trustLevel();
        }

        return $levels;
    }

    public function count(): int
    {
        return count($this->providers);
    }

    public function getIterator(): \Traversable
    {
        yield from $this->providers;
    }
}

