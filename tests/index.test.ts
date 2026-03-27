import { describe, it, expect } from 'vitest';

import {
  ShamirError,
  ShamirValidationError,
  ShamirCryptoError,
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
