import { describe, expect, it } from 'vitest';
import {
  exportCoseKeyAsSpki,
  importCoseKey,
  parseCoseKey,
} from '../core/cose/key.js';
import { encodeCbor, type CborInput } from './fixtures/cbor-encode.js';
import {
  coseKeyEdDSA,
  coseKeyEs256,
  generateP256Keypair,
} from './fixtures/webauthn.js';
import {
  PasskeyError,
  UnsupportedAlgorithmError,
} from '../errors/index.js';
import { webcrypto } from 'node:crypto';

const subtle = (webcrypto as unknown as Crypto).subtle;

describe('parseCoseKey', () => {
  it('should parse an EC2 / P-256 / ES256 COSE key', async () => {
    const kp = await generateP256Keypair();
    const cose = parseCoseKey(coseKeyEs256(kp.jwk));
    expect(cose.kty).toBe(2);
    expect(cose.alg).toBe(-7);
    expect(cose.crv).toBe(1);
    expect(cose.x).toBeInstanceOf(Uint8Array);
    expect(cose.y).toBeInstanceOf(Uint8Array);
  });

  it('should parse an OKP / Ed25519 / EdDSA COSE key', () => {
    const x = new Uint8Array(32);
    x[0] = 7;
    const cose = parseCoseKey(coseKeyEdDSA(x));
    expect(cose.kty).toBe(1);
    expect(cose.alg).toBe(-8);
    expect(cose.crv).toBe(6);
    expect(cose.x).toEqual(x);
  });

  it('should parse an RSA COSE key', () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 3); // kty: RSA
    m.set(3, -257); // alg: RS256
    m.set(-1, new Uint8Array([0x01, 0x02])); // n
    m.set(-2, new Uint8Array([0x01, 0x00, 0x01])); // e
    const cose = parseCoseKey(encodeCbor(m));
    expect(cose.kty).toBe(3);
    expect(cose.alg).toBe(-257);
    expect(cose.n).toEqual(new Uint8Array([0x01, 0x02]));
    expect(cose.e).toEqual(new Uint8Array([0x01, 0x00, 0x01]));
  });

  it('should throw when the input is not a CBOR map', () => {
    expect(() => parseCoseKey(encodeCbor(42))).toThrow(PasskeyError);
  });

  it('should reject an unknown kty', () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 99); // unknown kty
    m.set(3, -7);
    expect(() => parseCoseKey(encodeCbor(m))).toThrow(PasskeyError);
  });

  it('should reject an EC2 key missing coordinates', () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 2);
    m.set(3, -7);
    m.set(-1, 1);
    // x missing → throws "is not bytes" via reading the map.
    expect(() => parseCoseKey(encodeCbor(m))).toThrow(PasskeyError);
  });

  it('should reject when the alg field is not a number', () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 2);
    m.set(3, 'ES256');
    m.set(-1, 1);
    m.set(-2, new Uint8Array(32));
    m.set(-3, new Uint8Array(32));
    expect(() => parseCoseKey(encodeCbor(m))).toThrow(PasskeyError);
  });
});

describe('importCoseKey', () => {
  it('should import an ES256 COSE key as a verify-only CryptoKey', async () => {
    const kp = await generateP256Keypair();
    const cose = parseCoseKey(coseKeyEs256(kp.jwk));
    const key = await importCoseKey(cose);
    expect(key.usages).toContain('verify');
    expect(key.algorithm.name).toBe('ECDSA');
  });

  it('should import an Ed25519 COSE key', async () => {
    const ed = (await subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const rawX = new Uint8Array(await subtle.exportKey('raw', ed.publicKey));
    const cose = parseCoseKey(coseKeyEdDSA(rawX));
    const imported = await importCoseKey(cose);
    expect(imported.algorithm.name).toBe('Ed25519');
  });

  it('should reject OKP curves other than Ed25519', async () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 1); // OKP
    m.set(3, -8);
    m.set(-1, 99); // unsupported curve
    m.set(-2, new Uint8Array(32));
    const cose = parseCoseKey(encodeCbor(m));
    await expect(importCoseKey(cose)).rejects.toThrow(UnsupportedAlgorithmError);
  });

  it('should reject EC2 keys with a malformed curve identifier', async () => {
    const kp = await generateP256Keypair();
    const m = new Map<CborInput, CborInput>();
    m.set(1, 2);
    m.set(3, -7);
    m.set(-1, 99);
    m.set(-2, new Uint8Array(32));
    m.set(-3, new Uint8Array(32));
    const cose = parseCoseKey(encodeCbor(m));
    void kp; // referenced for symmetry
    await expect(importCoseKey(cose)).rejects.toThrow(PasskeyError);
  });

  it('should throw UnsupportedAlgorithmError for an unknown alg', async () => {
    const m = new Map<CborInput, CborInput>();
    m.set(1, 2);
    m.set(3, 999);
    m.set(-1, 1);
    m.set(-2, new Uint8Array(32));
    m.set(-3, new Uint8Array(32));
    const cose = parseCoseKey(encodeCbor(m));
    await expect(importCoseKey(cose)).rejects.toThrow(UnsupportedAlgorithmError);
  });
});

describe('exportCoseKeyAsSpki', () => {
  it('should export an ES256 COSE key as SPKI bytes', async () => {
    const kp = await generateP256Keypair();
    const cose = parseCoseKey(coseKeyEs256(kp.jwk));
    const spki = await exportCoseKeyAsSpki(cose);
    expect(spki).toBeInstanceOf(Uint8Array);
    expect(spki.byteLength).toBeGreaterThan(0);
    // SPKI starts with a SEQUENCE tag.
    expect(spki[0]).toBe(0x30);
  });
});
