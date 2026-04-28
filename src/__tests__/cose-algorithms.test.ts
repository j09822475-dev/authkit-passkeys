import { describe, expect, it } from 'vitest';
import {
  COSE_ALG,
  COSE_CURVE,
  DEFAULT_PUB_KEY_CRED_ALGS,
  coseAlgId,
  coseAlgToWebCrypto,
  isEcdsaAlg,
} from '../core/cose/algorithms.js';

describe('COSE_ALG', () => {
  it('should pin the IANA-registered identifiers for every supported algorithm', () => {
    expect(COSE_ALG.ES256).toBe(-7);
    expect(COSE_ALG.EdDSA).toBe(-8);
    expect(COSE_ALG.ES384).toBe(-35);
    expect(COSE_ALG.ES512).toBe(-36);
    expect(COSE_ALG.RS256).toBe(-257);
    expect(COSE_ALG.RS384).toBe(-258);
    expect(COSE_ALG.RS512).toBe(-259);
    expect(COSE_ALG.PS256).toBe(-37);
  });
});

describe('COSE_CURVE', () => {
  it('should pin the IANA-registered curve identifiers', () => {
    expect(COSE_CURVE.P_256).toBe(1);
    expect(COSE_CURVE.P_384).toBe(2);
    expect(COSE_CURVE.P_521).toBe(3);
    expect(COSE_CURVE.ED25519).toBe(6);
  });
});

describe('DEFAULT_PUB_KEY_CRED_ALGS', () => {
  it('should default to ES256, EdDSA, RS256 in that exact order', () => {
    expect(DEFAULT_PUB_KEY_CRED_ALGS).toEqual(['ES256', 'EdDSA', 'RS256']);
  });
});

describe('coseAlgId', () => {
  it('should resolve algorithm names to their COSE identifiers', () => {
    expect(coseAlgId('ES256')).toBe(-7);
    expect(coseAlgId('EdDSA')).toBe(-8);
    expect(coseAlgId('RS256')).toBe(-257);
  });
});

describe('coseAlgToWebCrypto', () => {
  it('should map ES256 to ECDSA P-256 / SHA-256', () => {
    const r = coseAlgToWebCrypto(-7);
    expect(r).toEqual({
      importParams: { name: 'ECDSA', namedCurve: 'P-256' },
      verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
    });
  });

  it('should map ES384 / ES512 to the matching ECDSA curve and hash', () => {
    expect(coseAlgToWebCrypto(-35)).toEqual({
      importParams: { name: 'ECDSA', namedCurve: 'P-384' },
      verifyParams: { name: 'ECDSA', hash: 'SHA-384' },
    });
    expect(coseAlgToWebCrypto(-36)).toEqual({
      importParams: { name: 'ECDSA', namedCurve: 'P-521' },
      verifyParams: { name: 'ECDSA', hash: 'SHA-512' },
    });
  });

  it('should map EdDSA to the Ed25519 algorithm', () => {
    expect(coseAlgToWebCrypto(-8)).toEqual({
      importParams: { name: 'Ed25519' },
      verifyParams: { name: 'Ed25519' },
    });
  });

  it('should map RS256 / RS384 / RS512 to RSASSA-PKCS1-v1_5 with the right hash', () => {
    expect(coseAlgToWebCrypto(-257)?.verifyParams).toEqual({ name: 'RSASSA-PKCS1-v1_5' });
    expect(coseAlgToWebCrypto(-258)?.importParams).toEqual({
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-384',
    });
    expect(coseAlgToWebCrypto(-259)?.importParams).toEqual({
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-512',
    });
  });

  it('should map PS256 to RSA-PSS with saltLength 32', () => {
    expect(coseAlgToWebCrypto(-37)).toEqual({
      importParams: { name: 'RSA-PSS', hash: 'SHA-256' },
      verifyParams: { name: 'RSA-PSS', saltLength: 32 },
    });
  });

  it('should return null for unknown algorithm identifiers', () => {
    expect(coseAlgToWebCrypto(999)).toBeNull();
    expect(coseAlgToWebCrypto(0)).toBeNull();
  });
});

describe('isEcdsaAlg', () => {
  it('should return true for ECDSA algorithm identifiers', () => {
    expect(isEcdsaAlg(-7)).toBe(true);
    expect(isEcdsaAlg(-35)).toBe(true);
    expect(isEcdsaAlg(-36)).toBe(true);
  });

  it('should return false for non-ECDSA identifiers', () => {
    expect(isEcdsaAlg(-8)).toBe(false); // EdDSA
    expect(isEcdsaAlg(-257)).toBe(false); // RS256
    expect(isEcdsaAlg(-37)).toBe(false); // PS256
  });
});
