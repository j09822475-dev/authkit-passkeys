/**
 * Helper to build fully-valid WebAuthn registration / authentication fixtures
 * driven by an ephemeral key generated via `crypto.subtle`. Produces the same
 * byte shapes a real authenticator would, so verifyRegistration /
 * verifyAuthentication can run end-to-end without a browser.
 */

import { webcrypto } from 'node:crypto';
import { encodeCbor, type CborInput } from './cbor-encode.js';

const subtle = (webcrypto as unknown as Crypto).subtle;

export interface RegistrationFixture {
  authData: Uint8Array;
  clientDataJSON: Uint8Array;
  attestationObject: Uint8Array;
  credentialId: Uint8Array;
  /** Raw COSE-encoded credential public key (the bytes embedded in authData). */
  credentialPublicKey: Uint8Array;
  privateKey: CryptoKey;
  publicCryptoKey: CryptoKey;
  rpIdHash: Uint8Array;
  challenge: Uint8Array;
  origin: string;
  rpId: string;
  aaguid: Uint8Array;
}

export interface AuthenticationFixture {
  authData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  credentialId: Uint8Array;
  rpIdHash: Uint8Array;
  challenge: Uint8Array;
  origin: string;
  rpId: string;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

export function concat(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function generateP256Keypair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  jwk: JsonWebKey;
}> {
  const pair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const jwk = await subtle.exportKey('jwk', pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, jwk };
}

function b64uToBytes(b64u: string): Uint8Array {
  const padded = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const s = atob(padded + '='.repeat(padLen));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Build a COSE EC2/P-256 key map from a JWK exported public key. */
export function coseKeyEs256(jwk: JsonWebKey): Uint8Array {
  if (!jwk.x || !jwk.y) throw new Error('jwk missing x/y');
  const x = b64uToBytes(jwk.x);
  const y = b64uToBytes(jwk.y);
  const map = new Map<CborInput, CborInput>();
  map.set(1, 2); // kty: EC2
  map.set(3, -7); // alg: ES256
  map.set(-1, 1); // crv: P-256
  map.set(-2, x);
  map.set(-3, y);
  return encodeCbor(map);
}

/** Build a COSE Ed25519/OKP key map from raw 32-byte x. */
export function coseKeyEdDSA(rawX: Uint8Array): Uint8Array {
  const map = new Map<CborInput, CborInput>();
  map.set(1, 1); // kty: OKP
  map.set(3, -8); // alg: EdDSA
  map.set(-1, 6); // crv: Ed25519
  map.set(-2, rawX);
  return encodeCbor(map);
}

/** Convert raw r||s (Web Crypto output) to DER SEQUENCE. */
export function rawToDerEcdsa(raw: Uint8Array, componentLen: number): Uint8Array {
  const r = raw.subarray(0, componentLen);
  const s = raw.subarray(componentLen, componentLen * 2);

  const enc = (n: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < n.length - 1 && n[i] === 0) i++;
    let trimmed = n.subarray(i);
    // High bit set → prepend 0x00 to indicate positive integer.
    if ((trimmed[0] as number) & 0x80) {
      const out = new Uint8Array(trimmed.length + 1);
      out[0] = 0x00;
      out.set(trimmed, 1);
      trimmed = out;
    }
    return concat(new Uint8Array([0x02, trimmed.length]), trimmed);
  };

  const rEnc = enc(r);
  const sEnc = enc(s);
  const body = concat(rEnc, sEnc);
  return concat(new Uint8Array([0x30, body.length]), body);
}

interface BuildAuthDataInput {
  rpIdHash: Uint8Array;
  flags: { up?: boolean; uv?: boolean; be?: boolean; bs?: boolean; at?: boolean; ed?: boolean };
  signCount: number;
  attestedCredentialData?: {
    aaguid: Uint8Array;
    credentialId: Uint8Array;
    credentialPublicKey: Uint8Array;
  };
  extensions?: Uint8Array;
}

export function buildAuthData(input: BuildAuthDataInput): Uint8Array {
  let flagsByte = 0;
  if (input.flags.up) flagsByte |= 0x01;
  if (input.flags.uv) flagsByte |= 0x04;
  if (input.flags.be) flagsByte |= 0x08;
  if (input.flags.bs) flagsByte |= 0x10;
  if (input.flags.at) flagsByte |= 0x40;
  if (input.flags.ed) flagsByte |= 0x80;

  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, input.signCount);

  const parts: Uint8Array[] = [
    input.rpIdHash,
    new Uint8Array([flagsByte]),
    counter,
  ];
  if (input.attestedCredentialData) {
    const { aaguid, credentialId, credentialPublicKey } = input.attestedCredentialData;
    if (aaguid.length !== 16) throw new Error('aaguid must be 16 bytes');
    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, credentialId.length);
    parts.push(aaguid, credIdLen, credentialId, credentialPublicKey);
  }
  if (input.extensions) parts.push(input.extensions);
  return concat(...parts);
}

export interface BuildRegistrationOptions {
  rpId?: string;
  origin?: string;
  challenge?: Uint8Array;
  signCount?: number;
  uv?: boolean;
  be?: boolean;
  bs?: boolean;
  fmt?: 'none' | 'packed';
  /** Override for AAGUID; default is empty (none-fmt anonymous). */
  aaguid?: Uint8Array;
  credentialId?: Uint8Array;
  /** When provided, use this kp instead of generating a fresh one. */
  keypair?: { privateKey: CryptoKey; publicKey: CryptoKey; jwk: JsonWebKey };
  /** When set in 'packed' mode, omit the alg field to provoke a packed-error. */
  malformedPacked?: boolean;
}

export async function buildRegistrationFixture(
  opts: BuildRegistrationOptions = {},
): Promise<RegistrationFixture> {
  const rpId = opts.rpId ?? 'example.com';
  const origin = opts.origin ?? 'https://example.com';
  const challenge = opts.challenge ?? webcrypto.getRandomValues(new Uint8Array(32));
  const signCount = opts.signCount ?? 0;
  const uv = opts.uv ?? true;
  const be = opts.be ?? false;
  const bs = opts.bs ?? false;
  const fmt = opts.fmt ?? 'none';
  const aaguid = opts.aaguid ?? new Uint8Array(16);
  const credentialId =
    opts.credentialId ?? webcrypto.getRandomValues(new Uint8Array(16));
  const kp = opts.keypair ?? (await generateP256Keypair());

  const rpIdHash = await sha256(utf8(rpId));
  const credentialPublicKey = coseKeyEs256(kp.jwk);

  const authData = buildAuthData({
    rpIdHash,
    flags: { up: true, uv, be, bs, at: true },
    signCount,
    attestedCredentialData: { aaguid, credentialId, credentialPublicKey },
  });

  const clientDataObj = {
    type: 'webauthn.create',
    challenge: toBase64Url(challenge),
    origin,
    crossOrigin: false,
  };
  const clientDataJSON = utf8(JSON.stringify(clientDataObj));

  let attStmt: Map<CborInput, CborInput>;
  if (fmt === 'none') {
    attStmt = new Map();
  } else {
    // Packed self-attestation.
    if (opts.malformedPacked) {
      attStmt = new Map();
    } else {
      const clientDataHash = await sha256(clientDataJSON);
      const signedData = concat(authData, clientDataHash);
      const rawSig = new Uint8Array(
        await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signedData),
      );
      const der = rawToDerEcdsa(rawSig, 32);
      attStmt = new Map<CborInput, CborInput>();
      attStmt.set('alg', -7);
      attStmt.set('sig', der);
    }
  }

  const attestationMap = new Map<CborInput, CborInput>();
  attestationMap.set('fmt', fmt);
  attestationMap.set('attStmt', attStmt);
  attestationMap.set('authData', authData);
  const attestationObject = encodeCbor(attestationMap);

  return {
    authData,
    clientDataJSON,
    attestationObject,
    credentialId,
    credentialPublicKey,
    privateKey: kp.privateKey,
    publicCryptoKey: kp.publicKey,
    rpIdHash,
    challenge,
    origin,
    rpId,
    aaguid,
  };
}

export interface BuildAuthenticationOptions {
  rpId?: string;
  origin?: string;
  challenge?: Uint8Array;
  signCount?: number;
  uv?: boolean;
  be?: boolean;
  bs?: boolean;
  privateKey: CryptoKey;
  credentialId: Uint8Array;
  /** When true, scrambles the signature bytes after signing. */
  invalidSignature?: boolean;
}

export async function buildAuthenticationFixture(
  opts: BuildAuthenticationOptions,
): Promise<AuthenticationFixture> {
  const rpId = opts.rpId ?? 'example.com';
  const origin = opts.origin ?? 'https://example.com';
  const challenge = opts.challenge ?? webcrypto.getRandomValues(new Uint8Array(32));
  const signCount = opts.signCount ?? 1;
  const uv = opts.uv ?? true;
  const be = opts.be ?? false;
  const bs = opts.bs ?? false;

  const rpIdHash = await sha256(utf8(rpId));
  const authData = buildAuthData({
    rpIdHash,
    flags: { up: true, uv, be, bs, at: false },
    signCount,
  });

  const clientDataObj = {
    type: 'webauthn.get',
    challenge: toBase64Url(challenge),
    origin,
    crossOrigin: false,
  };
  const clientDataJSON = utf8(JSON.stringify(clientDataObj));
  const clientDataHash = await sha256(clientDataJSON);
  const signedData = concat(authData, clientDataHash);
  const rawSig = new Uint8Array(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, opts.privateKey, signedData),
  );
  let der = rawToDerEcdsa(rawSig, 32);
  if (opts.invalidSignature) {
    // Flip last byte of the integer payload to invalidate.
    der = der.slice();
    der[der.length - 1] = (der[der.length - 1] as number) ^ 0xff;
  }

  return {
    authData,
    clientDataJSON,
    signature: der,
    credentialId: opts.credentialId,
    rpIdHash,
    challenge,
    origin,
    rpId,
  };
}
