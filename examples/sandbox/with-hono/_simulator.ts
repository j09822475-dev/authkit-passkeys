/**
 * Simulated WebAuthn authenticator. Produces the exact byte shapes a real
 * platform authenticator (Touch ID, Windows Hello, YubiKey) would, signed by
 * an ephemeral P-256 keypair held in memory.
 *
 * Real WebAuthn ceremonies cannot run in Node — the browser owns
 * `navigator.credentials.create / get`. To keep these examples runnable
 * (`npx tsx examples/basic-usage.ts`), we stand in for the browser with this
 * helper. The server-side calls (`generateRegistrationOptions`,
 * `verifyRegistration`, `verifyAuthentication`) execute end-to-end against
 * the real library code — only the `navigator.credentials.*` step is mocked.
 */

import { webcrypto } from 'node:crypto';
import type {
  AuthenticationOptionsJSON,
  AuthenticationResponseJSON,
  RegistrationOptionsJSON,
  RegistrationResponseJSON,
} from '@authkit/passkeys/types';

const subtle = (webcrypto as unknown as Crypto).subtle;

export interface VirtualAuthenticator {
  origin: string;
  rpId: string;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey;
  credentialId: Uint8Array;
  aaguid: Uint8Array;
  signCount: number;
  /** Multi-device sync flags (BE / BS) — flip to mimic an iCloud-synced passkey. */
  backupEligible: boolean;
  backupState: boolean;
}

export interface CreateAuthenticatorInput {
  origin: string;
  rpId: string;
  /** 16-byte AAGUID. Defaults to all-zero (anonymous, matches `attestation: 'none'`). */
  aaguid?: Uint8Array;
  /** Default: false / false (single-device platform authenticator). */
  backupEligible?: boolean;
  backupState?: boolean;
}

export async function createVirtualAuthenticator(
  input: CreateAuthenticatorInput,
): Promise<VirtualAuthenticator> {
  const pair = (await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const publicJwk = await subtle.exportKey('jwk', pair.publicKey);
  return {
    origin: input.origin,
    rpId: input.rpId,
    privateKey: pair.privateKey,
    publicJwk,
    credentialId: webcrypto.getRandomValues(new Uint8Array(16)),
    aaguid: input.aaguid ?? new Uint8Array(16),
    signCount: 0,
    backupEligible: input.backupEligible ?? false,
    backupState: input.backupState ?? false,
  };
}

/** Produce a {@link RegistrationResponseJSON} matching the given options. */
export async function simulateRegistration(
  auth: VirtualAuthenticator,
  options: RegistrationOptionsJSON,
): Promise<RegistrationResponseJSON> {
  const challenge = fromB64u(options.challenge);
  const rpIdHash = await sha256(utf8(auth.rpId));
  const credentialPublicKey = coseKeyEs256(auth.publicJwk);

  const authData = buildAuthData({
    rpIdHash,
    flags: { up: true, uv: true, be: auth.backupEligible, bs: auth.backupState, at: true },
    signCount: auth.signCount,
    attested: {
      aaguid: auth.aaguid,
      credentialId: auth.credentialId,
      credentialPublicKey,
    },
  });

  const clientDataJSON = utf8(
    JSON.stringify({
      type: 'webauthn.create',
      challenge: toB64u(challenge),
      origin: auth.origin,
      crossOrigin: false,
    }),
  );

  // `attestation: 'none'` keeps the CBOR statement empty.
  const attStmt = new Map<string | number, unknown>();
  const attestationMap = new Map<string | number, unknown>();
  attestationMap.set('fmt', 'none');
  attestationMap.set('attStmt', attStmt);
  attestationMap.set('authData', authData);
  const attestationObject = encodeCbor(attestationMap);

  return {
    id: toB64u(auth.credentialId),
    rawId: toB64u(auth.credentialId),
    type: 'public-key',
    response: {
      clientDataJSON: toB64u(clientDataJSON),
      attestationObject: toB64u(attestationObject),
      transports: ['internal'],
    },
    clientExtensionResults: {},
    authenticatorAttachment: 'platform',
  };
}

/** Produce an {@link AuthenticationResponseJSON} matching the given options. */
export async function simulateAuthentication(
  auth: VirtualAuthenticator,
  options: AuthenticationOptionsJSON,
): Promise<AuthenticationResponseJSON> {
  auth.signCount += 1;
  const challenge = fromB64u(options.challenge);
  const rpIdHash = await sha256(utf8(auth.rpId));
  const authData = buildAuthData({
    rpIdHash,
    flags: { up: true, uv: true, be: auth.backupEligible, bs: auth.backupState, at: false },
    signCount: auth.signCount,
  });

  const clientDataJSON = utf8(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: toB64u(challenge),
      origin: auth.origin,
      crossOrigin: false,
    }),
  );

  const clientDataHash = await sha256(clientDataJSON);
  const signedData = concat(authData, clientDataHash);
  const rawSig = new Uint8Array(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, auth.privateKey, signedData),
  );
  const derSig = rawToDerEcdsa(rawSig, 32);

  return {
    id: toB64u(auth.credentialId),
    rawId: toB64u(auth.credentialId),
    type: 'public-key',
    response: {
      clientDataJSON: toB64u(clientDataJSON),
      authenticatorData: toB64u(authData),
      signature: toB64u(derSig),
      userHandle: null,
    },
    clientExtensionResults: {},
    authenticatorAttachment: 'platform',
  };
}

// ---------------------------------------------------------------------------
// Internal helpers — base64url, COSE/CBOR, ECDSA r||s → DER, authData layout.
// Kept inline so the file is drop-in copyable into a StackBlitz sandbox.
// ---------------------------------------------------------------------------

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

function concat(...arrs: Uint8Array[]): Uint8Array {
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

function toB64u(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64u(b64u: string): Uint8Array {
  const padded = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const s = atob(padded + '='.repeat(padLen));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function coseKeyEs256(jwk: JsonWebKey): Uint8Array {
  if (!jwk.x || !jwk.y) throw new Error('jwk missing x/y');
  const x = fromB64u(jwk.x);
  const y = fromB64u(jwk.y);
  const map = new Map<number, unknown>();
  map.set(1, 2);
  map.set(3, -7);
  map.set(-1, 1);
  map.set(-2, x);
  map.set(-3, y);
  return encodeCbor(map);
}

function rawToDerEcdsa(raw: Uint8Array, componentLen: number): Uint8Array {
  const r = raw.subarray(0, componentLen);
  const s = raw.subarray(componentLen, componentLen * 2);
  const enc = (n: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < n.length - 1 && n[i] === 0) i++;
    let trimmed = n.subarray(i);
    if ((trimmed[0] as number) & 0x80) {
      const out = new Uint8Array(trimmed.length + 1);
      out[0] = 0x00;
      out.set(trimmed, 1);
      trimmed = out;
    }
    return concat(new Uint8Array([0x02, trimmed.length]), trimmed);
  };
  const body = concat(enc(r), enc(s));
  return concat(new Uint8Array([0x30, body.length]), body);
}

interface BuildAuthDataInput {
  rpIdHash: Uint8Array;
  flags: { up?: boolean; uv?: boolean; be?: boolean; bs?: boolean; at?: boolean; ed?: boolean };
  signCount: number;
  attested?: { aaguid: Uint8Array; credentialId: Uint8Array; credentialPublicKey: Uint8Array };
}

function buildAuthData(input: BuildAuthDataInput): Uint8Array {
  let flagsByte = 0;
  if (input.flags.up) flagsByte |= 0x01;
  if (input.flags.uv) flagsByte |= 0x04;
  if (input.flags.be) flagsByte |= 0x08;
  if (input.flags.bs) flagsByte |= 0x10;
  if (input.flags.at) flagsByte |= 0x40;
  if (input.flags.ed) flagsByte |= 0x80;
  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, input.signCount);
  const parts: Uint8Array[] = [input.rpIdHash, new Uint8Array([flagsByte]), counter];
  if (input.attested) {
    if (input.attested.aaguid.length !== 16) throw new Error('aaguid must be 16 bytes');
    const credIdLen = new Uint8Array(2);
    new DataView(credIdLen.buffer).setUint16(0, input.attested.credentialId.length);
    parts.push(input.attested.aaguid, credIdLen, input.attested.credentialId, input.attested.credentialPublicKey);
  }
  return concat(...parts);
}

// Minimal CBOR encoder (RFC 8949 deterministic-ish) covering the shapes we
// need: unsigned/negative ints, byte strings, text strings, arrays, maps.
type CborInput = number | string | Uint8Array | Map<CborInput, CborInput> | CborInput[];

function encodeCbor(value: CborInput): Uint8Array {
  if (typeof value === 'number') return encodeInt(value);
  if (typeof value === 'string') return encodeText(value);
  if (value instanceof Uint8Array) return encodeBytes(value);
  if (Array.isArray(value)) return encodeArray(value);
  if (value instanceof Map) return encodeMap(value);
  throw new Error(`Unsupported CBOR value: ${typeof value}`);
}

function encodeHead(majorType: number, n: number): Uint8Array {
  const major = majorType << 5;
  if (n < 24) return new Uint8Array([major | n]);
  if (n < 0x100) return new Uint8Array([major | 24, n]);
  if (n < 0x10000) {
    const out = new Uint8Array(3);
    out[0] = major | 25;
    new DataView(out.buffer).setUint16(1, n);
    return out;
  }
  if (n < 0x100000000) {
    const out = new Uint8Array(5);
    out[0] = major | 26;
    new DataView(out.buffer).setUint32(1, n);
    return out;
  }
  throw new Error('CBOR int too large for this minimal encoder');
}

function encodeInt(n: number): Uint8Array {
  if (!Number.isInteger(n)) throw new Error('non-integer number');
  return n >= 0 ? encodeHead(0, n) : encodeHead(1, -n - 1);
}

function encodeBytes(b: Uint8Array): Uint8Array {
  return concat(encodeHead(2, b.length), b);
}

function encodeText(s: string): Uint8Array {
  const b = utf8(s);
  return concat(encodeHead(3, b.length), b);
}

function encodeArray(items: CborInput[]): Uint8Array {
  const head = encodeHead(4, items.length);
  return concat(head, ...items.map(encodeCbor));
}

function encodeMap(m: Map<CborInput, CborInput>): Uint8Array {
  const head = encodeHead(5, m.size);
  const parts: Uint8Array[] = [head];
  for (const [k, v] of m) {
    parts.push(encodeCbor(k));
    parts.push(encodeCbor(v));
  }
  return concat(...parts);
}
