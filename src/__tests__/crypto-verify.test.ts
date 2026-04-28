import { describe, expect, it } from 'vitest';
import { dummyVerify, ecdsaComponentLengthForAlg, verifySignature } from '../core/crypto/verify.js';
import { parseCoseKey } from '../core/cose/key.js';
import { coseKeyEs256, generateP256Keypair, rawToDerEcdsa } from './fixtures/webauthn.js';
import { UnsupportedAlgorithmError } from '../errors/index.js';
import { encodeCbor, type CborInput } from './fixtures/cbor-encode.js';
import { webcrypto } from 'node:crypto';

const subtle = (webcrypto as unknown as Crypto).subtle;

describe('verifySignature', () => {
  it('should verify a valid ES256 signature against a parsed COSE key', async () => {
    const kp = await generateP256Keypair();
    const cose = parseCoseKey(coseKeyEs256(kp.jwk));
    const data = new TextEncoder().encode('payload');
    const rawSig = new Uint8Array(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data),
    );
    const der = rawToDerEcdsa(rawSig, 32);
    const ok = await verifySignature(cose, der, data);
    expect(ok).toBe(true);
  });

  it('should return false when the signature does not match the data', async () => {
    const kp = await generateP256Keypair();
    const cose = parseCoseKey(coseKeyEs256(kp.jwk));
    const data = new TextEncoder().encode('payload');
    const otherData = new TextEncoder().encode('different');
    const rawSig = new Uint8Array(
      await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, otherData),
    );
    const der = rawToDerEcdsa(rawSig, 32);
    expect(await verifySignature(cose, der, data)).toBe(false);
  });

  it('should throw UnsupportedAlgorithmError for an unmapped algorithm', async () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 2);
    m.set(3, 999);
    m.set(-1, 1);
    m.set(-2, new Uint8Array(32));
    m.set(-3, new Uint8Array(32));
    const cose = parseCoseKey(encodeCbor(m));
    await expect(verifySignature(cose, new Uint8Array(64), new Uint8Array(8))).rejects.toThrow(
      UnsupportedAlgorithmError,
    );
  });
});

describe('dummyVerify', () => {
  it('should always resolve to false', async () => {
    expect(await dummyVerify(new Uint8Array([1, 2, 3]))).toBe(false);
  });

  it('should reuse the cached crypto key on repeat calls', async () => {
    const a = await dummyVerify(new Uint8Array([1]));
    const b = await dummyVerify(new Uint8Array([2]));
    expect(a).toBe(false);
    expect(b).toBe(false);
  });
});

describe('ecdsaComponentLengthForAlg', () => {
  it('should return 32 for ES256', () => {
    expect(ecdsaComponentLengthForAlg(-7)).toBe(32);
  });

  it('should return 48 for ES384', () => {
    expect(ecdsaComponentLengthForAlg(-35)).toBe(48);
  });

  it('should return 66 for ES512', () => {
    expect(ecdsaComponentLengthForAlg(-36)).toBe(66);
  });

  it('should default to 32 for non-ECDSA identifiers', () => {
    expect(ecdsaComponentLengthForAlg(-8)).toBe(32);
    expect(ecdsaComponentLengthForAlg(-257)).toBe(32);
  });
});
