<?php
declare(strict_types=1);

namespace Fissible\Attest\Anchor\OpenTimestamps;

final readonly class OpenTimestampsOperation
{
    public const TAG_SHA256 = "\x08";
    public const TAG_APPEND = "\xf0";
    public const TAG_PREPEND = "\xf1";
    public const MAX_ARGUMENT_BYTES = 4096;
    public const MAX_RESULT_BYTES = 4096;

    private function __construct(
        public string $tag,
        public ?string $argument = null,
    ) {
        if ($tag === self::TAG_SHA256 && $argument !== null) {
            throw new \InvalidArgumentException('sha256 operation must not have an argument');
        }
        if (($tag === self::TAG_APPEND || $tag === self::TAG_PREPEND) && $argument === null) {
            throw new \InvalidArgumentException('append/prepend operation requires an argument');
        }
        if ($argument !== null && strlen($argument) > self::MAX_ARGUMENT_BYTES) {
            throw new \InvalidArgumentException('operation argument exceeds max length');
        }
        if (! in_array($tag, [self::TAG_SHA256, self::TAG_APPEND, self::TAG_PREPEND], true)) {
            throw new \InvalidArgumentException('unsupported OpenTimestamps operation tag');
        }
    }

    public static function sha256(): self
    {
        return new self(self::TAG_SHA256);
    }

    public static function append(string $bytes): self
    {
        return new self(self::TAG_APPEND, $bytes);
    }

    public static function prepend(string $bytes): self
    {
        return new self(self::TAG_PREPEND, $bytes);
    }

    public static function fromTag(string $tag, ?string $argument = null): self
    {
        return new self($tag, $argument);
    }

    public function apply(string $message): string
    {
        if (strlen($message) > self::MAX_RESULT_BYTES) {
            throw new \InvalidArgumentException('message exceeds max operation input length');
        }

        $result = match ($this->tag) {
            self::TAG_SHA256 => hash('sha256', $message, binary: true),
            self::TAG_APPEND => $message . $this->argument,
            self::TAG_PREPEND => $this->argument . $message,
            default => throw new \LogicException('unsupported operation'),
        };

        if ($result === '' || strlen($result) > self::MAX_RESULT_BYTES) {
            throw new \InvalidArgumentException('operation result length is invalid');
        }

        return $result;
    }

    public function compare(self $other): int
    {
        $tagComparison = strcmp($this->tag, $other->tag);
        if ($tagComparison !== 0) {
            return $tagComparison;
        }

        return strcmp($this->argument ?? '', $other->argument ?? '');
    }

    public function tagHex(): string
    {
        return bin2hex($this->tag);
    }
}

