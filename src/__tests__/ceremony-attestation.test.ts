import { describe, expect, it } from 'vitest';
import { parseAttestationObject } from '../core/ceremony/attestation.js';
import { encodeCbor, type CborInput } from './fixtures/cbor-encode.js';
import {
  buildAuthData,
  coseKeyEs256,
  generateP256Keypair,
  sha256,
  utf8,
} from './fixtures/webauthn.js';
import { PasskeyError } from '../errors/index.js';

describe('parseAttestationObject', () => {
  it('should parse a well-formed none-fmt attestation', async () => {
    const rpIdHash = await sha256(utf8('example.com'));
    const kp = await generateP256Keypair();
    const credentialPublicKey = coseKeyEs256(kp.jwk);
    const authData = buildAuthData({
      rpIdHash,
      flags: { up: true, uv: true, at: true },
      signCount: 0,
      attestedCredentialData: {
        aaguid: new Uint8Array(16),
        credentialId: new Uint8Array([1, 2]),
        credentialPublicKey,
      },
    });
    const attMap = new Map<CborInput, CborInput>();
    attMap.set('fmt', 'none');
    attMap.set('attStmt', new Map());
    attMap.set('authData', authData);
    const att = parseAttestationObject(encodeCbor(attMap));
    expect(att.fmt).toBe('none');
    expect(att.attStmt).toEqual({});
    expect(att.authData.flags.up).toBe(true);
    expect(att.rawAuthData).toBeInstanceOf(Uint8Array);
  });

  it('should drop attStmt entries with non-string keys', async () => {
    const rpIdHash = await sha256(utf8('example.com'));
    const kp = await generateP256Keypair();
    const credentialPublicKey = coseKeyEs256(kp.jwk);
    const authData = buildAuthData({
      rpIdHash,
      flags: { up: true, at: true },
      signCount: 0,
      attestedCredentialData: {
        aaguid: new Uint8Array(16),
        credentialId: new Uint8Array([1]),
        credentialPublicKey,
      },
    });
    const stmt = new Map<CborInput, CborInput>();
    stmt.set('alg', -7);
    stmt.set(123, 'dropped');
    const attMap = new Map<CborInput, CborInput>();
    attMap.set('fmt', 'packed');
    attMap.set('attStmt', stmt);
    attMap.set('authData', authData);
    const att = parseAttestationObject(encodeCbor(attMap));
    expect(att.attStmt).toEqual({ alg: -7 });
  });

  it('should throw when the top-level value is not a CBOR map', () => {
    expect(() => parseAttestationObject(encodeCbor(42))).toThrow(PasskeyError);
  });

  it('should throw when fmt is missing or not a string', () => {
    const attMap = new Map<CborInput, CborInput>();
    attMap.set('fmt', 7);
    attMap.set('attStmt', new Map());
    attMap.set('authData', new Uint8Array(37));
    expect(() => parseAttestationObject(encodeCbor(attMap))).toThrow(PasskeyError);
  });

  it('should throw when authData is missing or not bytes', async () => {
    const attMap = new Map<CborInput, CborInput>();
    attMap.set('fmt', 'none');
    attMap.set('attStmt', new Map());
    attMap.set('authData', 'not-bytes');
    expect(() => parseAttestationObject(encodeCbor(attMap))).toThrow(PasskeyError);
  });

  it('should throw when attStmt is not a CBOR map', () => {
    const attMap = new Map<CborInput, CborInput>();
    attMap.set('fmt', 'none');
    attMap.set('attStmt', 'oops');
    attMap.set('authData', new Uint8Array(37));
    expect(() => parseAttestationObject(encodeCbor(attMap))).toThrow(PasskeyError);
  });
});
