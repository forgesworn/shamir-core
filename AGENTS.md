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
llms.txt, llms-full.txt: AI-facing docs, shipped in the npm package; keep them in step with README.md and the source
dist/: compiled output
```

## Conventions

- British English in docs and comments (licence, serialise, colour)
- Strict TypeScript, `noUncheckedIndexedAccess` enabled
- Error hierarchy: `ShamirError` -> `ShamirValidationError` / `ShamirCryptoError`
- Zero internal secret scratch buffers: polynomial coefficients and random bytes are zeroed after use (`zeroBytes`). The caller's secret, the returned shares and the reconstructed secret are not zeroed by the library; the caller owns them
- Zero runtime dependencies: only Web Crypto (`crypto.getRandomValues`), used as the bare global `crypto`, so the Node floor is 19 (`engines`)
- ESM only: `"type": "module"` and an `exports` map with only an `import` condition, so `require()` fails

## Key decisions

- GF(256) uses log/exp table lookup with generator 0x03, irreducible polynomial 0x11b (same as AES)
- Share IDs are 1-indexed (1-255), not 0-indexed: 0 is not a valid GF(256) evaluation point
- No secret length limit: consumers (e.g. shamir-words BIP-39 encoding) enforce their own
- `reconstructSecret` uses only the first `threshold` shares from the array

## Common Pitfalls

- Share IDs are 1-indexed (1-255), not 0-indexed
- `reconstructSecret` uses only the first `threshold` shares; extra shares are ignored
- The `threshold` field on `ShamirShare` is metadata for encoding; the interpolation uses only `id` and `data`. `reconstructSecret` still checks it: a share whose integer `threshold` differs from the argument throws `ShamirValidationError`. A missing or non-integer `threshold` skips the check, so a wrong `threshold` argument then silently returns wrong bytes
- Only the first `threshold` shares are validated; later entries are ignored even if malformed
- `ShamirCryptoError` is thrown only by the internal GF(256) inverse of zero, which validation makes unreachable from the public API; every deliberate throw today is `ShamirValidationError`
- There is no integrity check: a wrong or tampered share returns a wrong secret without an error
- Multiplication is table-lookup based and not constant-time; do not describe it as such

## Release

- Releases via `forgesworn/anvil@v0` (workflow_call); do not manually bump version
- Commit messages drive versioning: `feat:` minor, `fix:` patch, `feat!:` major
- Work on branches, merge to main only when complete
