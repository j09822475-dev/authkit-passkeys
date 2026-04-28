import { describe, expect, it } from 'vitest';
import { sha256 } from '../core/crypto/digest.js';
import { toHex } from '../core/encoding/hex.js';

describe('sha256', () => {
  it('should compute the canonical SHA-256 of an empty input', async () => {
    const digest = await sha256(new Uint8Array(0));
    expect(toHex(digest)).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('should compute the canonical SHA-256 of "abc"', async () => {
    const digest = await sha256(new TextEncoder().encode('abc'));
    expect(toHex(digest)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('should always return 32 bytes', async () => {
    const d1 = await sha256(new Uint8Array([1]));
    const d2 = await sha256(new Uint8Array(1024));
    expect(d1.length).toBe(32);
    expect(d2.length).toBe(32);
  });
});
