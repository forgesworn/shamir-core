import { describe, it, expect } from 'vitest';

import {
  ShamirError,
  ShamirValidationError,
  ShamirCryptoError,
  splitSecret,
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
