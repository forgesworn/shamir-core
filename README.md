# @forgesworn/shamir-core

[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

GF(256) Shamir's Secret Sharing for TypeScript. Split a secret into threshold-of-n shares and reconstruct from any threshold-sized subset.

**Zero runtime dependencies.** Pure TypeScript, Web Crypto only.

## Install

```bash
npm install @forgesworn/shamir-core
```

## Requirements

**Node.js 19 or later**, or any runtime with a global Web Crypto `crypto.getRandomValues` (current browsers, Deno, Bun). `splitSecret` calls the global `crypto` directly, and Node.js only exposes it without a flag from version 19. Node.js 19 is end-of-life, so in practice use a maintained release.

On Node.js 18, `splitSecret` throws a plain `ReferenceError` (not a Shamir error) because `crypto` is undefined. Either start Node with `--experimental-global-webcrypto`, or define the global before calling it:

```javascript
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;
```

These are workarounds, not a supported configuration. `reconstructSecret` does not use `crypto`.

**ESM only.** The package has `"type": "module"` and its `exports` map has only an `import` condition. `require('@forgesworn/shamir-core')` therefore fails with `ERR_PACKAGE_PATH_NOT_EXPORTED` on every Node.js version, including those that can otherwise `require()` ES modules. From CommonJS, use dynamic `import()`:

```javascript
async function main() {
  const { splitSecret, reconstructSecret } = await import('@forgesworn/shamir-core');
  const shares = splitSecret(new Uint8Array([1, 2, 3]), 2, 3);
  return reconstructSecret(shares.slice(0, 2), 2);
}
```

## Quick Start

```typescript
import { splitSecret, reconstructSecret } from '@forgesworn/shamir-core';

// Split a 32-byte key into 5 shares, any 3 can reconstruct
const secret = crypto.getRandomValues(new Uint8Array(32));
const shares = splitSecret(secret, 3, 5);

// Reconstruct from shares 1, 3 and 5 (any 3 shares will do)
const subset = shares.filter((share) => [1, 3, 5].includes(share.id));
const recovered = reconstructSecret(subset, 3);
// recovered holds the same bytes as secret
```

## API

Everything is a named export of the package entry point. There is no default export.

```typescript
import {
  splitSecret,
  reconstructSecret,
  ShamirError,
  ShamirValidationError,
  ShamirCryptoError,
  type ShamirShare, // type only, erased at compile time
} from '@forgesworn/shamir-core';
```

### `splitSecret(secret, threshold, shares)`

Split a secret into Shamir shares.

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret` | `Uint8Array` | The secret bytes to split (any length) |
| `threshold` | `number` | Minimum shares needed to reconstruct (2--255) |
| `shares` | `number` | Total shares to create (threshold--255) |

Returns `ShamirShare[]`. Each share has `{ id, threshold, data }`.

### `reconstructSecret(shares, threshold)`

Reconstruct a secret from shares using Lagrange interpolation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `shares` | `ShamirShare[]` | At least `threshold` shares |
| `threshold` | `number` | The threshold used during splitting |

Returns `Uint8Array` (the reconstructed secret).

Only the first `threshold` shares are used. Extra shares are ignored.

### `ShamirShare`

```typescript
interface ShamirShare {
  id: number;        // 1--255 (GF(256) evaluation point)
  threshold: number; // 2--255 (minimum shares to reconstruct)
  data: Uint8Array;  // Share data (same length as original secret)
}
```

The interpolation uses only `id` and `data`. `threshold` is metadata for callers and encoders, but `reconstructSecret` cross-checks it against its own `threshold` argument whenever the share carries an integer value (see below). At runtime a share with a missing or non-integer `threshold` skips that check.

### Errors

All errors extend `Error`, and the two specific classes extend `ShamirError`, so `catch (err) { if (err instanceof ShamirError) ... }` covers every error the library throws on purpose.

- `ShamirError`: base class, never thrown directly.
- `ShamirValidationError`: invalid input. Every error the public functions can currently throw is this class.
- `ShamirCryptoError`: internal arithmetic failure. Its only throw site is the GF(256) inverse of zero, which the duplicate-ID and ID-range checks make unreachable through the public API as currently implemented. It is exported so that callers can catch it, but do not expect to see it.

`splitSecret` throws `ShamirValidationError` when:

- `secret` is not a `Uint8Array` (a Node.js `Buffer` is accepted)
- `secret` is empty
- `threshold` or `shares` is not a safe integer
- `threshold` is outside 2--255
- `shares` is less than `threshold` or greater than 255

`reconstructSecret` throws `ShamirValidationError` when:

- its `threshold` argument is not a safe integer of at least 2
- `shares` is not an array, or holds fewer than `threshold` shares (too few shares)
- any of the first `threshold` entries is not an object, or has an `id` that is not an integer in 1--255 (so id 0 is rejected)
- any of those entries has `data` that is not a `Uint8Array`
- two of those entries share an `id` (duplicate IDs)
- any of those entries has an integer `threshold` that differs from the `threshold` argument
- the data of the first of those entries is empty
- those entries have `data` of different lengths

Only the first `threshold` entries are validated or used. Later entries are ignored, even if malformed.

Some failures do not throw a Shamir error. If `crypto.getRandomValues` is unavailable, `splitSecret` throws whatever the runtime raises (a `ReferenceError` on Node.js 18 without the flag). Wrong data is not detected at all: see Security notes.

## Why This Library

- **Zero dependencies.** No transitive supply chain. Only Web Crypto (`crypto.getRandomValues`).
- **GF(256) log/exp table lookup.** O(1) field multiplication, same polynomial as AES (0x11b).
- **Memory zeroing.** Internal polynomial coefficients and random bytes are zeroed after use (defence-in-depth). Secrets, shares and results you hold are yours to zero; see Security notes.
- **Strict validation.** Duplicate share IDs, out-of-range IDs, mismatched lengths, and malformed inputs are caught with typed errors. Threshold mismatches are caught when the share carries a threshold.
- **No secret length limit.** Split any size secret. The maths has no ceiling.
- **TypeScript-first.** Strict mode, `noUncheckedIndexedAccess`, full type declarations.

## Security notes

- **No integrity check.** Shares carry no checksum, MAC or signature. A corrupted or tampered share, shares from different splits, or a `threshold` argument that is too low for shares without `threshold` metadata all return wrong bytes without any error. Verify the reconstructed secret at the application level (for example with a hash, a MAC, or by successfully decrypting something with it).
- **Not constant-time.** GF(256) multiplication uses log/exp table lookups indexed by secret-dependent bytes and returns early when an operand is zero. Timing and cache side channels are possible, and JavaScript runtimes give no constant-time guarantee in any case. Do not run it where an attacker can measure its timing at fine granularity.
- **Zeroing is partial.** `splitSecret` zeroes its internal polynomial coefficient and random-byte buffers. It does not touch your `secret` array or the `data` of the shares it returns. `reconstructSecret` zeroes nothing: it reads the share `data` arrays in place and returns a new array that you own. Call `.fill(0)` on the secret, the shares and the reconstructed result when you have finished with them. Even then, the runtime may have copied the bytes elsewhere, and numeric intermediates cannot be zeroed.
- **Randomness.** Coefficients come only from `crypto.getRandomValues`. There is no fallback generator and no seeding.
- **What a share reveals.** `data` has the same length as the secret, and `id` and `threshold` are stored in the clear.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## More documentation

[`llms.txt`](llms.txt) is a short machine-readable summary. [`llms-full.txt`](llms-full.txt) is the full reference with more examples and implementation details. Both ship in the npm package.

## Ecosystem

| Package | Purpose |
|---------|---------|
| [`@forgesworn/shamir-words`](https://github.com/forgesworn/shamir-words) | BIP-39 word encoding for shares (depends on this package) |
| [`dominion-protocol`](https://github.com/forgesworn/dominion) | Epoch-based encrypted access control (depends on this package) |

## Part of the ForgeSworn Toolkit

[ForgeSworn](https://forgesworn.dev) builds open-source cryptographic identity, payments, and coordination tools for Nostr.

| Library | What it does |
|---------|-------------|
| [nsec-tree](https://github.com/forgesworn/nsec-tree) | Deterministic sub-identity derivation |
| [ring-sig](https://github.com/forgesworn/ring-sig) | SAG/LSAG ring signatures on secp256k1 |
| [range-proof](https://github.com/forgesworn/range-proof) | Pedersen commitment range proofs |
| [canary-kit](https://github.com/forgesworn/canary-kit) | Coercion-resistant spoken verification |
| [spoken-token](https://github.com/forgesworn/spoken-token) | Human-speakable verification tokens |
| [toll-booth](https://github.com/forgesworn/toll-booth) | L402 payment middleware |
| [geohash-kit](https://github.com/forgesworn/geohash-kit) | Geohash toolkit with polygon coverage |
| [nostr-attestations](https://github.com/forgesworn/nostr-attestations) | NIP-VA verifiable attestations |
| [dominion](https://github.com/forgesworn/dominion) | Epoch-based encrypted access control |
| [nostr-veil](https://github.com/forgesworn/nostr-veil) | Privacy-preserving Web of Trust |

## Licence

MIT
