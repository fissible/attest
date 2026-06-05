<?php
declare(strict_types=1);

namespace Fissible\Attest\Bundle;

final readonly class BundleManifest
{
    public string $format;

    /**
     * @param list<ChainSegmentMeta> $chains
     * @param list<AnchorMeta>       $anchors
     * @param list<ClaimedKeyMeta>   $claimedKeys
     */
    public function __construct(
        public string $createdAt,
        public array $chains,
        public array $anchors,
        public array $claimedKeys = [],
        public ?string $issuerHint = null,
        public ?string $note = null,
    ) {
        $this->format = BundleConstants::FORMAT;
        if ($createdAt === '') {
            throw new InvalidBundleManifest('created_at must not be empty');
        }
    }

    public function toJson(): string
    {
        $out = [
            'format'     => $this->format,
            'created_at' => $this->createdAt,
            'chains'     => array_map(fn (ChainSegmentMeta $c) => $c->toArray(), $this->chains),
            'anchors'    => array_map(fn (AnchorMeta $a) => $a->toArray(), $this->anchors),
        ];
        if ($this->claimedKeys !== []) {
            $out['claimed_keys'] = array_map(fn (ClaimedKeyMeta $k) => $k->toArray(), $this->claimedKeys);
        }
        if ($this->issuerHint !== null) {
            $out['issuer_hint'] = $this->issuerHint;
        }
        if ($this->note !== null) {
            $out['note'] = $this->note;
        }
        return json_encode($out, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public static function fromJson(string $json): self
    {
        if (strlen($json) > BundleConstants::MAX_MANIFEST_BYTES) {
            throw new InvalidBundleManifest('Manifest exceeds size cap');
        }
        try {
            $arr = json_decode($json, true, depth: 32, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidBundleManifest('Manifest is not valid JSON: ' . $e->getMessage());
        }
        if (! is_array($arr)) {
            throw new InvalidBundleManifest('Manifest must be a JSON object');
        }
        if (($arr['format'] ?? null) !== BundleConstants::FORMAT) {
            throw new InvalidBundleManifest('Unsupported format: ' . var_export($arr['format'] ?? null, true));
        }
        if (! isset($arr['created_at']) || ! is_string($arr['created_at'])) {
            throw new InvalidBundleManifest('Manifest missing created_at');
        }
        if (! isset($arr['chains']) || ! is_array($arr['chains'])) {
            throw new InvalidBundleManifest('Manifest missing chains');
        }
        if (! isset($arr['anchors']) || ! is_array($arr['anchors'])) {
            throw new InvalidBundleManifest('Manifest missing anchors');
        }

        $chains = array_map(
            fn ($c) => is_array($c) ? ChainSegmentMeta::fromArray($c) : throw new InvalidBundleManifest('Invalid chain entry'),
            array_values($arr['chains']),
        );
        $anchors = array_map(
            fn ($a) => is_array($a) ? AnchorMeta::fromArray($a) : throw new InvalidBundleManifest('Invalid anchor entry'),
            array_values($arr['anchors']),
        );
        $keys = array_map(
            fn ($k) => is_array($k) ? ClaimedKeyMeta::fromArray($k) : throw new InvalidBundleManifest('Invalid key entry'),
            array_values($arr['claimed_keys'] ?? []),
        );

        return new self(
            createdAt:   $arr['created_at'],
            chains:      $chains,
            anchors:     $anchors,
            claimedKeys: $keys,
            issuerHint:  isset($arr['issuer_hint']) && is_string($arr['issuer_hint']) ? $arr['issuer_hint'] : null,
            note:        isset($arr['note']) && is_string($arr['note']) ? $arr['note'] : null,
        );
    }
}
