import { PasskeyVerificationError } from '../errors/verification.js';
import { PasskeyError } from '../errors/base.js';
import { fromBase64Url, toBase64Url } from '../core/encoding/base64url.js';
import { aaguidToUuid } from '../core/encoding/hex.js';
import { sha256 } from '../core/crypto/digest.js';
import { encodeUtf8 } from '../core/encoding/utf8.js';
import { parseClientDataJSON, assertExpectedClientData } from '../core/ceremony/client-data.js';
import { parseAttestationObject } from '../core/ceremony/attestation.js';
import { validateRpId } from '../core/ceremony/rp-id.js';
import { parseCoseKey, exportCoseKeyAsSpki } from '../core/cose/key.js';
import {
  DEFAULT_ATTESTATION_VERIFIERS,
  type AttestationVerifier,
} from '../core/attestation-formats/index.js';
import type {
  AttestationConveyancePreference,
  RegistrationResponseJSON,
} from '../types/webauthn-json.js';
import type { CredentialRecord } from '../types/credential.js';
import type { AuthenticatorTransport } from '../types/transport.js';
import type { AuthenticatorPolicy } from '../types/policy.js';
import { applyPolicy, formatAaguid, assertTransportAllowed } from './policies.js';

export interface VerifyRegistrationInput {
  response: RegistrationResponseJSON;
  expectedChallenge: Uint8Array;
  expectedOrigin: string | readonly string[];
  expectedRpId: string;
  expectedUserId: Uint8Array;
  attestation: AttestationConveyancePreference;
  policy: AuthenticatorPolicy;
  attestationVerifiers: ReadonlyMap<string, AttestationVerifier>;
}

/**
 * Internal helper. Verify a `RegistrationResponseJSON` end-to-end and produce
 * a {@link CredentialRecord} the caller persists via `CredentialStore.save`.
 *
 * On failure, throws a {@link PasskeyVerificationError} or
 * {@link PasskeyPolicyError}; the calling `RelyingParty.finishRegistration`
 * wraps these in a `Result` for the public boundary.
 */
export async function _verifyRegistration(input: VerifyRegistrationInput): Promise<CredentialRecord> {
  // 1. Decode + parse client data.
  let clientDataBytes: Uint8Array;
  try {
    clientDataBytes = fromBase64Url(input.response.response.clientDataJSON);
  } catch (cause) {
    throw new PasskeyVerificationError('registration-failed', 'Invalid clientDataJSON encoding.', {
      cause,
      details: { reason: 'client-data-parse-failed' },
    });
  }
  const clientData = parseClientDataJSON(clientDataBytes);
  assertExpectedClientData(clientData, 'webauthn.create', input.expectedChallenge, input.expectedOrigin);

  // Origin → RP-ID compatibility (covers subdomain rules + scheme).
  validateRpId(clientData.origin, input.expectedRpId);

  // 2. Parse attestation object.
  let attestationBytes: Uint8Array;
  try {
    attestationBytes = fromBase64Url(input.response.response.attestationObject);
  } catch (cause) {
    throw new PasskeyVerificationError('registration-failed', 'Invalid attestationObject encoding.', {
      cause,
      details: { reason: 'attestation-statement-invalid' },
    });
  }
  const attestation = parseAttestationObject(attestationBytes);

  // 3. RP-ID hash check.
  const expectedRpIdHash = await sha256(encodeUtf8(input.expectedRpId));
  if (!equalBytes(attestation.authData.rpIdHash, expectedRpIdHash)) {
    throw new PasskeyVerificationError('bad-rp-id', 'authData.rpIdHash does not match expected rpId.', {
      details: { reason: 'rp-id-hash-mismatch', expectedRpId: input.expectedRpId },
    });
  }

  if (!attestation.authData.attestedCredentialData) {
    throw new PasskeyVerificationError('registration-failed', 'authenticatorData.attestedCredentialData is missing.', {
      details: { reason: 'authenticator-data-parse-failed' },
    });
  }

  // 4. Format-specific attestation verification.
  const verifier = input.attestationVerifiers.get(attestation.fmt) ?? DEFAULT_ATTESTATION_VERIFIERS.get(attestation.fmt);
  if (!verifier) {
    throw new PasskeyError('unsupported-attestation-format', `Attestation format "${attestation.fmt}" is not registered.`, {
      details: { attestationFormat: attestation.fmt },
    });
  }
  const clientDataHash = await sha256(clientDataBytes);
  const result = await verifier(attestation, { clientDataHash });
  if (!result.valid) {
    throw new PasskeyVerificationError('registration-failed', `Attestation "${attestation.fmt}" failed verification.`, {
      details: { reason: 'attestation-statement-invalid', attestationFormat: attestation.fmt },
    });
  }

  // 5. Apply policy.
  const aaguid = aaguidToUuid(attestation.authData.attestedCredentialData.aaguid);
  applyPolicy(input.policy, attestation.authData, aaguid);

  // 6. Transports.
  const transports = (input.response.response.transports ?? []) as AuthenticatorTransport[];
  for (const t of transports) assertTransportAllowed(input.policy, t);

  // 7. Parse + export the credential public key.
  const coseKey = parseCoseKey(attestation.authData.attestedCredentialData.credentialPublicKey);
  const spki = await exportCoseKeyAsSpki(coseKey);

  // 8. Compose the persistent record.
  const credentialId = toBase64Url(attestation.authData.attestedCredentialData.credentialId);

  void formatAaguid; // explicit reference to silence unused-import on bundlers that mis-count
  return {
    credentialId,
    userId: input.expectedUserId,
    publicKey: spki,
    publicKeyAlgorithm: coseKey.alg,
    signCount: attestation.authData.signCount,
    signCountStatic: null, // Unknown at registration; auth flow flips this.
    transports,
    aaguid,
    backupEligible: attestation.authData.flags.be,
    backupState: attestation.authData.flags.bs,
    attestationFormat: attestation.fmt,
    createdAt: new Date(),
  };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
