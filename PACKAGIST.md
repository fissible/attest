# Packagist Registration

This package is not yet on Packagist. Registration happens at v1.0.0 release, not during alpha. When ready:

1. Sign in at https://packagist.org with the fissible org account.
2. Click "Submit" and enter the repo URL: `https://github.com/fissible/attest`.
3. Enable Packagist's GitHub webhook auto-update (Packagist will request access during submission).
4. Verify the package page renders at `https://packagist.org/packages/fissible/attest`.
5. Repeat for `fissible/attest-laravel`.

For testing the adapter locally before Packagist registration, use a path repository in the consumer app's composer.json:

```json
"repositories": [
  {"type": "path", "url": "../attest"},
  {"type": "path", "url": "../attest-laravel"}
]
```

Stability flag in consumer apps during alpha: `"minimum-stability": "dev"`, `"prefer-stable": true`.
