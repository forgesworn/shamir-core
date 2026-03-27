import { describe, it, expect } from 'vitest';

import {
  ShamirError,
  ShamirValidationError,
  ShamirCryptoError,
  splitSecret,
  reconstructSecret,
  type ShamirShare,
} from '../src/index.js';

describe('error hierarchy', () => {
  it('ShamirValidationError extends ShamirError', () => {
    const err = new ShamirValidationError('test');
    expect(err).toBeInstanceOf(ShamirError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ShamirValidationError');
    expect(err.message).toBe('test');
  });

  it('ShamirCryptoError extends ShamirError', () => {
    const err = new ShamirCryptoError('test');
    expect(err).toBeInstanceOf(ShamirError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ShamirCryptoError');
    expect(err.message).toBe('test');
  });
});

describe('splitSecret', () => {
  const secret5 = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"

  it('splits a 5-byte secret into 3 shares with threshold 2', () => {
    const shares = splitSecret(secret5, 2, 3);
    expect(shares).toHaveLength(3);
    for (const s of shares) {
      expect(s.data).toBeInstanceOf(Uint8Array);
      expect(s.data.length).toBe(5);
      expect(s.threshold).toBe(2);
    }
    expect(shares.map(s => s.id)).toEqual([1, 2, 3]);
  });

  it('produces different share data from the secret', () => {
    const shares = splitSecret(secret5, 2, 3);
    const allSame = shares.every(s =>
      Array.from(s.data).every((b, i) => b === secret5[i])
    );
    expect(allSame).toBe(false);
  });

  it('splits a 32-byte secret (key-sized)', () => {
    const secret32 = new Uint8Array(32).map((_, i) => i * 8);
    const shares = splitSecret(secret32, 3, 5);
    expect(shares).toHaveLength(5);
    for (const s of shares) {
      expect(s.data.length).toBe(32);
      expect(s.threshold).toBe(3);
    }
  });

  it('accepts secrets larger than 255 bytes', () => {
    const big = new Uint8Array(512).map((_, i) => i & 0xff);
    const shares = splitSecret(big, 2, 3);
    expect(shares).toHaveLength(3);
    for (const s of shares) {
      expect(s.data.length).toBe(512);
    }
  });

  it('rejects empty secret', () => {
    expect(() => splitSecret(new Uint8Array(0), 2, 3))
      .toThrow(ShamirValidationError);
  });

  it('rejects threshold < 2', () => {
    expect(() => splitSecret(secret5, 1, 3))
      .toThrow(ShamirValidationError);
  });

  it('rejects threshold > 255', () => {
    expect(() => splitSecret(secret5, 256, 256))
      .toThrow(ShamirValidationError);
  });

  it('rejects shares < threshold', () => {
    expect(() => splitSecret(secret5, 3, 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects shares > 255 (GF(256) limit)', () => {
    expect(() => splitSecret(secret5, 2, 256))
      .toThrow(ShamirValidationError);
  });

  it('accepts shares = 255 (GF(256) boundary)', () => {
    const shares = splitSecret(new Uint8Array([42]), 2, 255);
    expect(shares).toHaveLength(255);
  });

  it('rejects non-integer threshold', () => {
    expect(() => splitSecret(secret5, 2.5, 3))
      .toThrow(ShamirValidationError);
  });

  it('rejects non-integer shares', () => {
    expect(() => splitSecret(secret5, 2, 3.5))
      .toThrow(ShamirValidationError);
  });
});

describe('reconstructSecret', () => {
  const secret5 = new Uint8Array([72, 101, 108, 108, 111]);

  it('reconstructs with 2-of-3 (shares 1,2)', () => {
    const shares = splitSecret(secret5, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[1]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret5));
  });

  it('reconstructs with 2-of-3 (shares 2,3)', () => {
    const shares = splitSecret(secret5, 2, 3);
    const recovered = reconstructSecret([shares[1]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret5));
  });

  it('reconstructs with 2-of-3 (shares 1,3)', () => {
    const shares = splitSecret(secret5, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret5));
  });

  it('reconstructs with all 3-of-3 shares', () => {
    const shares = splitSecret(secret5, 2, 3);
    const recovered = reconstructSecret(shares, 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret5));
  });

  it('reconstructs 3-of-5 with non-adjacent shares', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const shares = splitSecret(secret, 3, 5);
    const recovered = reconstructSecret([shares[0]!, shares[2]!, shares[4]!], 3);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('reconstructs 5-of-5', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const shares = splitSecret(secret, 5, 5);
    const recovered = reconstructSecret(shares, 5);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('rejects below-threshold reconstruction when metadata is present', () => {
    const secret = new Uint8Array([10, 20, 30, 40]);
    const shares = splitSecret(secret, 5, 5);
    // shares have threshold=5 in metadata, caller passes 4 -- should throw
    expect(() => reconstructSecret(shares.slice(0, 4), 4))
      .toThrow('does not match supplied threshold');
  });

  it('reconstructs a 32-byte secret', () => {
    const secret32 = new Uint8Array(32).map((_, i) => i * 8);
    const shares = splitSecret(secret32, 3, 5);
    const recovered = reconstructSecret([shares[1]!, shares[3]!, shares[4]!], 3);
    expect(Array.from(recovered)).toEqual(Array.from(secret32));
  });

  it('reconstructs a secret larger than 255 bytes', () => {
    const big = new Uint8Array(512).map((_, i) => i & 0xff);
    const shares = splitSecret(big, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(big));
  });

  it('handles all-zero secret', () => {
    const secret = new Uint8Array(8).fill(0);
    const shares = splitSecret(secret, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('handles all-0xFF secret', () => {
    const secret = new Uint8Array(8).fill(0xff);
    const shares = splitSecret(secret, 2, 3);
    const recovered = reconstructSecret([shares[1]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('handles zero bytes interspersed', () => {
    const secret = new Uint8Array([0, 0, 0, 255, 0]);
    const shares = splitSecret(secret, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });

  it('handles single-byte secret', () => {
    const secret = new Uint8Array([42]);
    const shares = splitSecret(secret, 2, 3);
    const recovered = reconstructSecret([shares[0]!, shares[2]!], 2);
    expect(Array.from(recovered)).toEqual([42]);
  });

  it('rejects threshold < 2', () => {
    const shares = splitSecret(secret5, 2, 3);
    expect(() => reconstructSecret(shares, 1))
      .toThrow(ShamirValidationError);
  });

  it('rejects fewer shares than threshold', () => {
    const shares = splitSecret(secret5, 3, 5);
    expect(() => reconstructSecret([shares[0]!], 3))
      .toThrow(ShamirValidationError);
  });

  it('rejects duplicate share IDs', () => {
    const share1: ShamirShare = { id: 1, threshold: 2, data: new Uint8Array([10]) };
    const share2: ShamirShare = { id: 1, threshold: 2, data: new Uint8Array([20]) };
    expect(() => reconstructSecret([share1, share2], 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects share ID 0', () => {
    const share1: ShamirShare = { id: 0, threshold: 2, data: new Uint8Array([10]) };
    const share2: ShamirShare = { id: 2, threshold: 2, data: new Uint8Array([20]) };
    expect(() => reconstructSecret([share1, share2], 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects share ID > 255', () => {
    const share1: ShamirShare = { id: 1, threshold: 2, data: new Uint8Array([10]) };
    const share2: ShamirShare = { id: 300, threshold: 2, data: new Uint8Array([20]) };
    expect(() => reconstructSecret([share1, share2], 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects mismatched share data lengths', () => {
    const share1: ShamirShare = { id: 1, threshold: 2, data: new Uint8Array([1, 2, 3]) };
    const share2: ShamirShare = { id: 2, threshold: 2, data: new Uint8Array([4, 5]) };
    expect(() => reconstructSecret([share1, share2], 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects empty share data', () => {
    const share1: ShamirShare = { id: 1, threshold: 2, data: new Uint8Array(0) };
    const share2: ShamirShare = { id: 2, threshold: 2, data: new Uint8Array(0) };
    expect(() => reconstructSecret([share1, share2], 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects mismatched threshold in share metadata', () => {
    const share1: ShamirShare = { id: 1, threshold: 2, data: new Uint8Array([10]) };
    const share2: ShamirShare = { id: 2, threshold: 3, data: new Uint8Array([20]) };
    expect(() => reconstructSecret([share1, share2], 2))
      .toThrow(ShamirValidationError);
  });

  it('rejects caller threshold that does not match share metadata', () => {
    const shares = splitSecret(new Uint8Array([42]), 3, 5);
    // shares have threshold=3, but caller passes threshold=2
    expect(() => reconstructSecret([shares[0]!, shares[1]!], 2))
      .toThrow('does not match supplied threshold');
  });

  it('reconstructs with non-sequential share order', () => {
    const secret = new Uint8Array([1, 2, 3, 4]);
    const shares = splitSecret(secret, 3, 5);
    const recovered = reconstructSecret([shares[3]!, shares[1]!, shares[0]!], 3);
    expect(Array.from(recovered)).toEqual(Array.from(secret));
  });
});
