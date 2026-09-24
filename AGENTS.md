# shamir-core

TypeScript library for Shamir's Secret Sharing over GF(256). Zero runtime dependencies. Single source file, no CLI, pure library.

## Build & Test

| Command | Purpose |
|---------|---------|
| `npm install` | Install dependencies |
| `npm run build` | Compile (`tsc` → `dist/`) |
| `npm test` | Run test suite (vitest run) |
| `npm run typecheck` | Type-check (`tsc --noEmit`) |

## Structure

```
src/index.ts: entire library (GF(256) arithmetic, Shamir split/reconstruct, types, errors)
tests/index.test.ts: test suite (vitest)
dist/: compiled output
```

## Conventions

- British English in docs and comments (licence, serialise, colour)
- Strict TypeScript, `noUncheckedIndexedAccess` enabled
- Error hierarchy: `ShamirError` -> `ShamirValidationError` / `ShamirCryptoError`
- Zero secrets in memory: polynomial coefficients are zeroed after use (`zeroBytes`)
- Zero runtime dependencies: only Web Crypto (`crypto.getRandomValues`)

## Key decisions

- GF(256) uses log/exp table lookup with generator 0x03, irreducible polynomial 0x11b (same as AES)
- Share IDs are 1-indexed (1-255), not 0-indexed: 0 is not a valid GF(256) evaluation point
- No secret length limit: consumers (e.g. shamir-words BIP-39 encoding) enforce their own
- `reconstructSecret` uses only the first `threshold` shares from the array

## Common Pitfalls

- Share IDs are 1-indexed (1-255), not 0-indexed
- `reconstructSecret` uses only the first `threshold` shares; extra shares are ignored
- The `threshold` field on `ShamirShare` is metadata for encoding; the maths doesn't need it

## Release

- Releases via `forgesworn/anvil@v0` (workflow_call); do not manually bump version
- Commit messages drive versioning: `feat:` minor, `fix:` patch, `feat!:` major
- Work on branches, merge to main only when complete
