import { describe, expect, it } from 'vitest';
import { parseAuthenticatorData } from '../core/ceremony/auth-data.js';
import {
  buildAuthData,
  coseKeyEs256,
  generateP256Keypair,
  sha256,
  utf8,
} from './fixtures/webauthn.js';
import { encodeCbor, type CborInput } from './fixtures/cbor-encode.js';
import { PasskeyError } from '../errors/index.js';

describe('parseAuthenticatorData', () => {
  it('should reject buffers shorter than 37 bytes', () => {
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow(PasskeyError);
  });

  it('should parse a minimal authData with no attested credential data', async () => {
    const rpIdHash = await sha256(utf8('example.com'));
    const auth = buildAuthData({
      rpIdHash,
      flags: { up: true, uv: true },
      signCount: 7,
    });
    const parsed = parseAuthenticatorData(auth);
    expect(Array.from(parsed.rpIdHash)).toEqual(Array.from(rpIdHash));
    expect(parsed.flags.up).toBe(true);
    expect(parsed.flags.uv).toBe(true);
    expect(parsed.flags.at).toBe(false);
    expect(parsed.signCount).toBe(7);
    expect(parsed.attestedCredentialData).toBeUndefined();
    expect(parsed.extensions).toBeUndefined();
  });

  it('should parse attestedCredentialData when AT flag is set', async () => {
    const kp = await generateP256Keypair();
    const rpIdHash = await sha256(utf8('example.com'));
    const credentialPublicKey = coseKeyEs256(kp.jwk);
    const credId = new Uint8Array([1, 2, 3, 4]);
    const aaguid = new Uint8Array(16);
    const auth = buildAuthData({
      rpIdHash,
      flags: { up: true, at: true },
      signCount: 0,
      attestedCredentialData: { aaguid, credentialId: credId, credentialPublicKey },
    });
    const parsed = parseAuthenticatorData(auth);
    expect(parsed.attestedCredentialData).toBeDefined();
    expect(Array.from(parsed.attestedCredentialData!.credentialId)).toEqual(Array.from(credId));
    expect(Array.from(parsed.attestedCredentialData!.aaguid)).toEqual(Array.from(aaguid));
    expect(Array.from(parsed.attestedCredentialData!.credentialPublicKey)).toEqual(
      Array.from(credentialPublicKey),
    );
  });

  it('should parse extensions when ED flag is set', async () => {
    const rpIdHash = await sha256(utf8('example.com'));
    // Empty CBOR map = single byte 0xa0
    const extMap = new Map<CborInput, CborInput>();
    const extBytes = encodeCbor(extMap);
    const auth = buildAuthData({
      rpIdHash,
      flags: { up: true, ed: true },
      signCount: 1,
      extensions: extBytes,
    });
    const parsed = parseAuthenticatorData(auth);
    expect(parsed.extensions).toBeDefined();
    expect(Array.from(parsed.extensions!)).toEqual(Array.from(extBytes));
  });

  it('should throw when attested credential data is truncated in the header', async () => {
    const rpIdHash = await sha256(utf8('example.com'));
    const flagsByte = 0x40 | 0x01; // AT + UP
    const counter = new Uint8Array(4);
    // Header: rpIdHash (32) + flags (1) + counter (4) = 37 bytes; need >= 37+18 for ACD.
    const arr = new Uint8Array(37 + 5);
    arr.set(rpIdHash, 0);
    arr[32] = flagsByte;
    arr.set(counter, 33);
    expect(() => parseAuthenticatorData(arr)).toThrow(PasskeyError);
  });

  it('should throw when credentialId length exceeds the remaining buffer', async () => {
    const rpIdHash = await sha256(utf8('example.com'));
    const flagsByte = 0x40 | 0x01; // AT + UP
    const auth = new Uint8Array(37 + 18);
    auth.set(rpIdHash, 0);
    auth[32] = flagsByte;
    // counter zero (offset 33-36), aaguid zero (37-52), credIdLen = 0xffff at 53-54.
    auth[53] = 0xff;
    auth[54] = 0xff;
    expect(() => parseAuthenticatorData(auth)).toThrow(PasskeyError);
  });
});
