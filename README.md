# @forgesworn/shamir-core

[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

GF(256) Shamir's Secret Sharing for TypeScript. Split a secret into threshold-of-n shares and reconstruct from any threshold-sized subset.

**Zero runtime dependencies.** Pure TypeScript, Web Crypto only.

## Install

```bash
npm install @forgesworn/shamir-core
```

## Quick Start

```typescript
import { splitSecret, reconstructSecret } from '@forgesworn/shamir-core';

// Split a 32-byte key into 5 shares, any 3 can reconstruct
const secret = crypto.getRandomValues(new Uint8Array(32));
const shares = splitSecret(secret, 3, 5);

// Reconstruct from any 3 shares
const recovered = reconstructSecret([shares[0], shares[2], shares[4]], 3);
// recovered is identical to secret
```

## API

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

### Error Classes

- `ShamirError` -- base class
- `ShamirValidationError` -- invalid parameters
- `ShamirCryptoError` -- internal crypto errors

## Why This Library

- **Zero dependencies.** No transitive supply chain. Only Web Crypto (`crypto.getRandomValues`).
- **GF(256) log/exp table lookup.** O(1) field multiplication, same polynomial as AES (0x11b).
- **Memory zeroing.** Polynomial coefficients are zeroed after use (defence-in-depth).
- **Strict validation.** Duplicate share IDs, threshold mismatches, and malformed inputs are caught with typed errors.
- **No secret length limit.** Split any size secret. The maths has no ceiling.
- **TypeScript-first.** Strict mode, `noUncheckedIndexedAccess`, full type declarations.

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
