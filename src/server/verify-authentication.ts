import { PasskeyVerificationError } from '../errors/verification.js';
import { fromBase64Url } from '../core/encoding/base64url.js';
import { encodeUtf8 } from '../core/encoding/utf8.js';
import { sha256 } from '../core/crypto/digest.js';
import { dummyVerify } from '../core/crypto/verify.js';
import { parseClientDataJSON, assertExpectedClientData } from '../core/ceremony/client-data.js';
import { parseAuthenticatorData } from '../core/ceremony/auth-data.js';
import { validateRpId } from '../core/ceremony/rp-id.js';
import { coseAlgToWebCrypto, isEcdsaAlg } from '../core/cose/algorithms.js';
import { derToRawEcdsa } from '../core/crypto/der.js';
import { applyPolicy, resolveSignCount, assertTransportAllowed } from './policies.js';
import type { AuthenticationResponseJSON } from '../types/webauthn-json.js';
import type { AuthenticatedCredential, CredentialRecord } from '../types/credential.js';
import type { AuthenticatorPolicy } from '../types/policy.js';

export interface VerifyAuthenticationInput {
  response: AuthenticationResponseJSON;
  expectedChallenge: Uint8Array;
  expectedOrigin: string | readonly string[];
  expectedRpId: string;
  /** Optional — when set, response.userHandle MUST equal it (mismatch is a hard failure). */
  expectedUserId?: Uint8Array;
  policy: AuthenticatorPolicy;
  /** May be `null` when the credentialId is unknown — triggers the dummy-verify path (§9.10). */
  credential: CredentialRecord | null;
}

/**
 * Internal helper. Verify an `AuthenticationResponseJSON` against a stored
 * credential record. Returns the data the caller persists (`newSignCount`,
 * `signCountStatic`, `backupState`).
 *
 * Implements the timing/error-shape collapse described in PLAN §9.10:
 * - When the credential is unknown, run a dummy verify so wall-clock time and
 *   error shape match a real failed verify.
 * - The granular reason (`unknown-credential` vs `bad-signature`) is stuffed
 *   on `error.details.reason` for server-only audit logs.
 */
export async function _verifyAuthentication(input: VerifyAuthenticationInput): Promise<{
  result: AuthenticatedCredential;
  patch: { signCount: number; signCountStatic: boolean; backupState: boolean };
}> {
  // Always parse + validate clientData before touching the credential — bad
  // challenge / bad origin should fail fast and identically regardless of credentialId.
  let clientDataBytes: Uint8Array;
  try {
    clientDataBytes = fromBase64Url(input.response.response.clientDataJSON);
  } catch (cause) {
    throw new PasskeyVerificationError('authentication-failed', 'Invalid clientDataJSON encoding.', {
      cause,
      details: { reason: 'client-data-parse-failed' },
    });
  }
  const clientData = parseClientDataJSON(clientDataBytes);
  assertExpectedClientData(clientData, 'webauthn.get', input.expectedChallenge, input.expectedOrigin);
  validateRpId(clientData.origin, input.expectedRpId);

  let authDataBytes: Uint8Array;
  try {
    authDataBytes = fromBase64Url(input.response.response.authenticatorData);
  } catch (cause) {
    throw new PasskeyVerificationError('authentication-failed', 'Invalid authenticatorData encoding.', {
      cause,
      details: { reason: 'authenticator-data-parse-failed' },
    });
  }
  const authData = parseAuthenticatorData(authDataBytes);

  const expectedRpIdHash = await sha256(encodeUtf8(input.expectedRpId));
  if (!equalBytes(authData.rpIdHash, expectedRpIdHash)) {
    throw new PasskeyVerificationError('bad-rp-id', 'authData.rpIdHash does not match expected rpId.', {
      details: { reason: 'rp-id-hash-mismatch', expectedRpId: input.expectedRpId },
    });
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64Url(input.response.response.signature);
  } catch (cause) {
    throw new PasskeyVerificationError('authentication-failed', 'Invalid signature encoding.', {
      cause,
      details: { reason: 'bad-signature' },
    });
  }

  const clientDataHash = await sha256(clientDataBytes);
  const signedData = concat(authDataBytes, clientDataHash);

  // §9.10 — unknown credential takes the dummy-verify path.
  if (!input.credential) {
    await dummyVerify(signedData);
    throw new PasskeyVerificationError('authentication-failed', 'Authentication failed.', {
      details: { reason: 'unknown-credential', credentialId: input.response.id },
    });
  }

  // Signature verify. Re-parse the SPKI back into a verify-key by importing
  // the COSE key (we kept the alg on the record); for portability the record
  // could also store COSE bytes — for now we round-trip via SPKI import.
  const algo = coseAlgToWebCrypto(input.credential.publicKeyAlgorithm);
  if (!algo) {
    throw new PasskeyVerificationError(
      'authentication-failed',
      `Algorithm ${input.credential.publicKeyAlgorithm} not supported.`,
      { details: { reason: 'unsupported-algorithm' } },
    );
  }

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey('spki', input.credential.publicKey, algo.importParams, false, ['verify']);
  } catch (cause) {
    throw new PasskeyVerificationError('authentication-failed', 'Stored public key could not be imported.', {
      cause,
      details: { reason: 'cose-key-parse-failed' },
    });
  }

  const sig = isEcdsaAlg(input.credential.publicKeyAlgorithm)
    ? derToRawEcdsa(signature, ec2ComponentLengthForAlg(input.credential.publicKeyAlgorithm))
    : signature;

  const ok = await crypto.subtle.verify(algo.verifyParams, cryptoKey, sig, signedData);
  if (!ok) {
    throw new PasskeyVerificationError('authentication-failed', 'Authentication failed.', {
      details: { reason: 'bad-signature', credentialId: input.credential.credentialId },
    });
  }

  // Backup-eligibility must NOT have flipped from true → false.
  if (input.credential.backupEligible && !authData.flags.be) {
    throw new PasskeyVerificationError(
      'authentication-failed',
      'Backup-eligible flag regressed (BE: 1 → 0 is forbidden).',
      { details: { reason: 'backup-eligibility-flipped', credentialId: input.credential.credentialId } },
    );
  }

  const aaguid = input.credential.aaguid;
  applyPolicy(input.policy, authData, aaguid);

  // Optional userHandle binding.
  let userHandle: Uint8Array | undefined;
  if (input.response.response.userHandle) {
    userHandle = fromBase64Url(input.response.response.userHandle);
    if (input.expectedUserId && !equalBytes(userHandle, input.expectedUserId)) {
      throw new PasskeyVerificationError(
        'authentication-failed',
        'response.userHandle does not match expectedUserId.',
        { details: { reason: 'unknown-credential', credentialId: input.credential.credentialId } },
      );
    }
  } else if (input.expectedUserId && !equalBytes(input.credential.userId, input.expectedUserId)) {
    throw new PasskeyVerificationError(
      'authentication-failed',
      'Stored credential does not belong to expectedUserId.',
      { details: { reason: 'unknown-credential', credentialId: input.credential.credentialId } },
    );
  }

  // Transport check (the response itself doesn't carry transports — keep this for symmetry).
  for (const t of input.credential.transports) assertTransportAllowed(input.policy, t);

  const counter = resolveSignCount(input.credential, authData.signCount);

  return {
    result: {
      credentialId: input.credential.credentialId,
      userId: input.credential.userId,
      newSignCount: counter.signCount,
      signCountStatic: counter.signCountStatic,
      aaguid,
      backupEligible: authData.flags.be,
      backupState: authData.flags.bs,
      ...(input.response.clientExtensionResults
        ? { extensionResults: input.response.clientExtensionResults }
        : {}),
    },
    patch: {
      signCount: counter.signCount,
      signCountStatic: counter.signCountStatic,
      backupState: authData.flags.bs,
    },
  };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function ec2ComponentLengthForAlg(alg: number): number {
  // -7 ES256, -35 ES384, -36 ES512.
  switch (alg) {
    case -7:
      return 32;
    case -35:
      return 48;
    case -36:
      return 66;
    default:
      return 32;
  }
}

