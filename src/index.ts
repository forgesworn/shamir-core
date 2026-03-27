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

// ---------------------------------------------------------------------------
// Shamir's Secret Sharing
// ---------------------------------------------------------------------------

/**
 * Split a secret into shares using Shamir's Secret Sharing over GF(256).
 *
 * @param secret    The secret bytes to split (any length)
 * @param threshold Minimum shares needed to reconstruct (>= 2)
 * @param shares    Total number of shares to create (>= threshold, <= 255)
 * @returns Array of ShamirShare objects
 */
export function splitSecret(
  secret: Uint8Array,
  threshold: number,
  shares: number,
): ShamirShare[] {
  if (!(secret instanceof Uint8Array)) {
    throw new ShamirValidationError('Secret must be a Uint8Array');
  }
  if (secret.length === 0) {
    throw new ShamirValidationError('Secret must not be empty');
  }
  if (!Number.isSafeInteger(threshold) || !Number.isSafeInteger(shares)) {
    throw new ShamirValidationError('Threshold and shares must be safe integers');
  }
  if (threshold < 2 || threshold > 255) {
    throw new ShamirValidationError('Threshold must be in [2, 255]');
  }
  if (shares < threshold) {
    throw new ShamirValidationError('Number of shares must be >= threshold');
  }
  if (shares > 255) {
    throw new ShamirValidationError('Number of shares must be <= 255');
  }

  const secretLen = secret.length;
  const result: ShamirShare[] = [];

  for (let i = 0; i < shares; i++) {
    result.push({ id: i + 1, threshold, data: new Uint8Array(secretLen) });
  }

  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    const coeffs = new Uint8Array(threshold);
    const rand = new Uint8Array(threshold - 1);
    try {
      coeffs[0] = secret[byteIdx]!;
      crypto.getRandomValues(rand);
      for (let j = 1; j < threshold; j++) {
        coeffs[j] = rand[j - 1]!;
      }

      for (let i = 0; i < shares; i++) {
        result[i]!.data[byteIdx] = evalPoly(coeffs, i + 1);
      }
    } finally {
      zeroBytes(coeffs);
      zeroBytes(rand);
    }
  }

  return result;
}

/**
 * Reconstruct a secret from shares using Lagrange interpolation over GF(256).
 *
 * @param shares    Array of shares (at least `threshold` shares)
 * @param threshold The threshold used during splitting
 * @returns The reconstructed secret bytes
 */
export function reconstructSecret(
  shares: ShamirShare[],
  threshold: number,
): Uint8Array {
  if (!Number.isSafeInteger(threshold) || threshold < 2) {
    throw new ShamirValidationError('Threshold must be an integer >= 2');
  }
  if (!Array.isArray(shares) || shares.length < threshold) {
    throw new ShamirValidationError(
      `Need at least ${threshold} shares, got ${Array.isArray(shares) ? shares.length : 0}`,
    );
  }

  // Snapshot share properties to prevent TOCTOU via Proxy/getter objects
  const raw = shares.slice(0, threshold);
  const used: Array<{ id: number; threshold: number; data: Uint8Array }> = [];

  const ids = new Set<number>();
  for (const share of raw) {
    if (!share || typeof share !== 'object') {
      throw new ShamirValidationError('Each share must be an object with id and data properties');
    }
    // Snapshot once to prevent getter-based TOCTOU
    const id = share.id;
    const shareThreshold = share.threshold;
    const data = share.data;

    if (!Number.isInteger(id) || id < 1 || id > 255) {
      throw new ShamirValidationError('Invalid share ID: must be an integer in [1, 255]');
    }
    if (!(data instanceof Uint8Array)) {
      throw new ShamirValidationError('Share data must be a Uint8Array');
    }
    if (ids.has(id)) {
      throw new ShamirValidationError('Duplicate share IDs detected — each share must have a unique ID');
    }
    if (Number.isInteger(shareThreshold) && shareThreshold !== threshold) {
      throw new ShamirValidationError(
        `Share threshold (${shareThreshold}) does not match supplied threshold (${threshold})`,
      );
    }
    ids.add(id);
    used.push({ id, threshold: shareThreshold, data });
  }

  const secretLen = used[0]!.data.length;
  if (secretLen === 0) {
    throw new ShamirValidationError('Share data must not be empty');
  }
  for (const share of used) {
    if (share.data.length !== secretLen) {
      throw new ShamirValidationError('Inconsistent share lengths — shares may be from different secrets');
    }
  }

  const result = new Uint8Array(secretLen);

  // Lagrange interpolation at x = 0 for each byte position
  for (let byteIdx = 0; byteIdx < secretLen; byteIdx++) {
    let value = 0;

    for (let i = 0; i < threshold; i++) {
      const xi = used[i]!.id;
      const yi = used[i]!.data[byteIdx]!;

      // Lagrange basis l_i(0) = product of x_j / (x_i ^ x_j) for j != i
      let basis = 1;
      for (let j = 0; j < threshold; j++) {
        if (i === j) continue;
        const xj = used[j]!.id;
        basis = gf256Mul(basis, gf256Mul(xj, gf256Inv(gf256Add(xi, xj))));
      }

      value = gf256Add(value, gf256Mul(yi, basis));
    }

    result[byteIdx] = value;
  }

  return result;
}
