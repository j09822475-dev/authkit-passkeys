import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ATTESTATION_VERIFIERS,
  verifyAttestation,
  verifyNoneAttestation,
  verifyPackedAttestation,
} from '../server/attestation/index.js';
import {
  InvalidAttestationError,
  UnsupportedAttestationFormatError,
} from '../errors/index.js';
import {
  buildAuthData,
  coseKeyEs256,
  generateP256Keypair,
  rawToDerEcdsa,
  sha256,
  utf8,
} from './fixtures/webauthn.js';
import { encodeCbor, type CborInput } from './fixtures/cbor-encode.js';
import { parseAttestationObject } from '../core/ceremony/attestation.js';
import { webcrypto } from 'node:crypto';
import type { AttestationVerifier } from '../server/attestation/types.js';
import type { ParsedAttestationObject } from '../types/parsed.js';

const subtle = (webcrypto as unknown as Crypto).subtle;

async function buildPackedSelfAttestation(opts: {
  rpId?: string;
  malformed?: boolean;
  noAcd?: boolean;
  badAlg?: boolean;
  withX5c?: boolean;
  emptyX5c?: boolean;
  invalidX5c?: boolean;
}): Promise<{ att: ParsedAttestationObject; clientDataHash: Uint8Array }> {
  const rpId = opts.rpId ?? 'example.com';
  const kp = await generateP256Keypair();
  const credentialPublicKey = coseKeyEs256(kp.jwk);
  const rpIdHash = await sha256(utf8(rpId));
  const authData = buildAuthData({
    rpIdHash,
    flags: { up: true, uv: true, at: !opts.noAcd },
    signCount: 0,
    ...(opts.noAcd
      ? {}
      : {
          attestedCredentialData: {
            aaguid: new Uint8Array(16),
            credentialId: new Uint8Array([1, 2, 3]),
            credentialPublicKey,
          },
        }),
  });
  const clientDataHash = await sha256(utf8('clientdata'));
  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData, 0);
  signedData.set(clientDataHash, authData.length);
  const rawSig = new Uint8Array(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signedData),
  );
  const der = rawToDerEcdsa(rawSig, 32);

  const stmt = new Map<CborInput, CborInput>();
  if (!opts.malformed) {
    stmt.set('alg', opts.badAlg ? -257 : -7);
    stmt.set('sig', der);
  }
  if (opts.withX5c) {
    stmt.set('x5c', opts.invalidX5c ? ['not-bytes' as unknown as Uint8Array] : [new Uint8Array([1, 2, 3])]);
  }
  if (opts.emptyX5c) {
    stmt.set('x5c', []);
  }

  const attMap = new Map<CborInput, CborInput>();
  attMap.set('fmt', 'packed');
  attMap.set('attStmt', stmt);
  attMap.set('authData', authData);
  return { att: parseAttestationObject(encodeCbor(attMap)), clientDataHash };
}

describe('DEFAULT_ATTESTATION_VERIFIERS', () => {
  it('should include none and packed', () => {
    expect(DEFAULT_ATTESTATION_VERIFIERS.has('none')).toBe(true);
    expect(DEFAULT_ATTESTATION_VERIFIERS.has('packed')).toBe(true);
  });

  it('should NOT statically include the dynamic-import formats', () => {
    expect(DEFAULT_ATTESTATION_VERIFIERS.has('apple' as never)).toBe(false);
    expect(DEFAULT_ATTESTATION_VERIFIERS.has('tpm' as never)).toBe(false);
    expect(DEFAULT_ATTESTATION_VERIFIERS.has('android-key' as never)).toBe(false);
    expect(DEFAULT_ATTESTATION_VERIFIERS.has('fido-u2f' as never)).toBe(false);
  });
});

describe('verifyNoneAttestation', () => {
  it('should always return valid:true with attestationType:none', async () => {
    const { att } = await buildPackedSelfAttestation({});
    const r = await verifyNoneAttestation(att, { clientDataHash: new Uint8Array(32) });
    expect(r).toEqual({ valid: true, attestationType: 'none' });
  });
});

describe('verifyPackedAttestation (self)', () => {
  it('should accept a valid self-attestation', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({});
    const r = await verifyPackedAttestation(att, { clientDataHash });
    expect(r.valid).toBe(true);
    expect(r.attestationType).toBe('self');
  });

  it('should reject when alg / sig fields are missing', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({ malformed: true });
    await expect(verifyPackedAttestation(att, { clientDataHash })).rejects.toThrow(
      InvalidAttestationError,
    );
  });

  it('should reject when self-attestation alg does not match the COSE key alg', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({ badAlg: true });
    await expect(verifyPackedAttestation(att, { clientDataHash })).rejects.toThrow(
      InvalidAttestationError,
    );
  });

  it('should reject self-attestation when AT flag / attestedCredentialData missing', async () => {
    // Missing AT — produces no attestedCredentialData, which the verifier then rejects.
    const { att, clientDataHash } = await buildPackedSelfAttestation({ noAcd: true });
    await expect(verifyPackedAttestation(att, { clientDataHash })).rejects.toThrow(
      InvalidAttestationError,
    );
  });
});

describe('verifyPackedAttestation (basic with x5c)', () => {
  it('should accept and forward the trustChain when x5c has at least one cert', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({ withX5c: true });
    const r = await verifyPackedAttestation(att, { clientDataHash });
    expect(r.attestationType).toBe('basic');
    expect(r.valid).toBe(true);
    expect(r.trustChain).toBeDefined();
    expect(r.trustChain!.length).toBe(1);
  });

  it('should reject malformed x5c (non-Uint8Array entries)', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({
      withX5c: true,
      invalidX5c: true,
    });
    await expect(verifyPackedAttestation(att, { clientDataHash })).rejects.toThrow(
      InvalidAttestationError,
    );
  });

  it('should fall through to self-attestation when x5c is an empty array', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({ emptyX5c: true });
    const r = await verifyPackedAttestation(att, { clientDataHash });
    expect(r.attestationType).toBe('self');
  });
});

describe('verifyAttestation dispatcher', () => {
  it('should dispatch to none and packed via the default registry', async () => {
    const { att, clientDataHash } = await buildPackedSelfAttestation({});
    const r = await verifyAttestation(att, { clientDataHash });
    expect(r.valid).toBe(true);
  });

  it('should prefer overrides over the default registry', async () => {
    const { att } = await buildPackedSelfAttestation({});
    const stub: AttestationVerifier = async () => ({
      valid: false,
      attestationType: 'unsupported',
    });
    const r = await verifyAttestation(att, { clientDataHash: new Uint8Array(32) }, new Map([['packed', stub]]));
    expect(r.valid).toBe(false);
  });

  it('should reject formats with no static or dynamic loader', async () => {
    const { att } = await buildPackedSelfAttestation({});
    const synthetic: ParsedAttestationObject = { ...att, fmt: 'unknown-format' };
    await expect(
      verifyAttestation(synthetic, { clientDataHash: new Uint8Array(32) }),
    ).rejects.toThrow(UnsupportedAttestationFormatError);
  });

  it('should dispatch dynamically-loaded formats and surface their UnsupportedAttestationFormatError', async () => {
    const { att } = await buildPackedSelfAttestation({});
    const synthetic: ParsedAttestationObject = { ...att, fmt: 'apple' };
    await expect(
      verifyAttestation(synthetic, { clientDataHash: new Uint8Array(32) }),
    ).rejects.toThrow(UnsupportedAttestationFormatError);
  });
});

describe('Roadmap formats (apple / fido-u2f / tpm / android-key)', () => {
  it.each([
    ['apple', () => import('../server/attestation/apple.js').then((m) => m.verifyAppleAttestation)],
    [
      'fido-u2f',
      () => import('../server/attestation/fido-u2f.js').then((m) => m.verifyFidoU2fAttestation),
    ],
    ['tpm', () => import('../server/attestation/tpm.js').then((m) => m.verifyTpmAttestation)],
    [
      'android-key',
      () =>
        import('../server/attestation/android-key.js').then(
          (m) => m.verifyAndroidKeyAttestation,
        ),
    ],
  ])('should reject %s attestation as unsupported (until v0.3 lands)', async (_name, load) => {
    const verifier = await load();
    const { att } = await buildPackedSelfAttestation({});
    await expect(verifier(att, { clientDataHash: new Uint8Array(32) })).rejects.toThrow(
      UnsupportedAttestationFormatError,
    );
  });
});
