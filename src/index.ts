// Shamir's Secret Sharing over GF(256)
// Split secrets into threshold-of-n shares using polynomial interpolation
// Zero runtime dependencies — only Web Crypto for randomness

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ShamirError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ShamirError';
  }
}

export class ShamirValidationError extends ShamirError {
  constructor(message: string) {
    super(message);
    this.name = 'ShamirValidationError';
  }
}

export class ShamirCryptoError extends ShamirError {
  constructor(message: string) {
    super(message);
    this.name = 'ShamirCryptoError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ShamirShare {
  id: number;          // 1-255 (the x coordinate in GF(256))
  threshold: number;   // 2-255 (minimum shares needed to reconstruct)
  data: Uint8Array;    // evaluated polynomial bytes
}

// ---------------------------------------------------------------------------
// GF(256) Arithmetic — irreducible polynomial 0x11b (same as AES)
// ---------------------------------------------------------------------------

const IRREDUCIBLE = 0x11b;
const GENERATOR = 0x03;

/** Log table: log_g(i) for i in [0..255]. LOG[0] is unused. */
const LOG = new Uint8Array(256);
/** Exp table: g^i for i in [0..255]. EXP[255] wraps to EXP[0]. */
const EXP = new Uint8Array(256);

/** Carryless multiplication used only during table construction */
function gf256MulSlow(a: number, b: number): number {
  let result = 0;
  let aa = a;
  let bb = b;
  while (bb > 0) {
    if (bb & 1) result ^= aa;
    aa <<= 1;
    if (aa & 0x100) aa ^= IRREDUCIBLE;
    bb >>= 1;
  }
  return result;
}

// Build log/exp tables at module load time using generator 0x03
{
  let val = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = val;
    LOG[val] = i;
    val = gf256MulSlow(val, GENERATOR);
  }
  // Wrap: makes modular indexing simpler
  EXP[255] = EXP[0]!;
}

/** Addition in GF(256) is XOR */
function gf256Add(a: number, b: number): number {
  return a ^ b;
}

/** Multiplication in GF(256) using log/exp tables */
function gf256Mul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a]! + LOG[b]!) % 255]!;
}

/** Multiplicative inverse in GF(256) */
function gf256Inv(a: number): number {
  if (a === 0) throw new ShamirCryptoError('No inverse for zero in GF(256)');
  return EXP[(255 - LOG[a]!) % 255]!;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Evaluate a polynomial at x in GF(256) using Horner's method.
 * coeffs[0] is the constant term (the secret byte).
 */
function evalPoly(coeffs: Uint8Array, x: number): number {
  let result = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    result = gf256Add(gf256Mul(result, x), coeffs[i]!);
  }
  return result;
}

/** Zero a byte array (defence-in-depth for secret material) */
function zeroBytes(arr: Uint8Array): void {
  arr.fill(0);
}
