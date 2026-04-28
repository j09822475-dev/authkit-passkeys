import {
  InvalidAttestationError,
  InvalidRpIdError,
} from '../errors/classes.js';
import { fromBase64Url, toBase64Url } from '../core/encoding/base64url.js';
import { aaguidToUuid } from '../core/encoding/hex.js';
import { encodeUtf8 } from '../core/encoding/utf8.js';
import { sha256 } from '../core/crypto/digest.js';
import { equalBytes } from '../core/crypto/bytes.js';
import {
  assertExpectedClientData,
  assertOriginMatchesRpId,
  parseAttestationObject,
  parseClientDataJSON,
} from '../core/ceremony/index.js';
import { parseCoseKey } from '../core/cose/key.js';
import { verifyChallengeToken } from './challenge.js';
import { verifyAttestation, type AttestationVerifier } from './attestation/index.js';
import { assertAaguidAllowed } from './policy/aaguid.js';
import { assertUserVerification } from './policy/user-verification.js';
import type {
  AuthenticatorTransport,
  ChallengeToken,
  RegistrationResponseJSON,
} from '../types/webauthn.js';
import type {
  NewCredentialRecord,
  RegistrationVerifiedEvent,
} from '../types/credential.js';
import type { AaguidPolicy, ChallengeSigningKeys } from '../types/options.js';

/** Input shape for {@link verifyRegistration}. */
export interface VerifyRegistrationInput {
  response: RegistrationResponseJSON;
  challengeToken: ChallengeToken | string;
  expectedOrigin: string | readonly string[];
  expectedRpId: string;
  signingKeys: ChallengeSigningKeys;
  /** Default `true`. Set `false` ONLY to integrate with non-https dev. */
  requireUserVerification?: boolean;
  /**
   * Hook fired after verification but before the function returns. Use for
   * logging / audit. Errors thrown inside the hook propagate.
   */
  onVerified?: (ev: RegistrationVerifiedEvent) => void | Promise<void>;
  /** Optional AAGUID allow/deny policy. */
  policy?: AaguidPolicy;
  /** Optional verifier override map — short-circuits the registry / dynamic-import path. */
  attestationVerifiers?: ReadonlyMap<string, AttestationVerifier>;
}

/**
 * Verify the attestation produced by the browser's {@link startRegistration}.
 *
 * On success returns a {@link NewCredentialRecord} ready for storage. The
 * store is NOT written automatically — call `store.create(record)` from
 * your app code so you control the transaction boundary (e.g. wrapping with
 * the user-creation row).
 *
 * @param input  Verification input — see {@link VerifyRegistrationInput}.
 * @returns      The new credential record (caller fills `userId` if it differs
 *               from the binding embedded in the challenge envelope).
 * @throws {InvalidChallengeTokenError}    Tag mismatch / expired / malformed.
 * @throws {WrongCeremonyError}            Token issued for the auth ceremony.
 * @throws {InvalidChallengeError}         clientData challenge mismatch.
 * @throws {InvalidOriginError}            Origin not allowed.
 * @throws {InvalidRpIdError}              `authData.rpIdHash` mismatch.
 * @throws {InvalidAttestationError}       Attestation statement invalid.
 * @throws {UnsupportedAttestationFormatError}  `fmt` not loaded.
 * @throws {AaguidNotAllowedError}         AAGUID rejected by policy.
 * @throws {UserVerificationRequiredError} UV required but `flags.uv` is 0.
 *
 * @example
 *   const record = await verifyRegistration({
 *     response: req.body,
 *     challengeToken: getCookie('passkey_reg')!,
 *     expectedOrigin: 'https://example.com',
 *     expectedRpId: 'example.com',
 *     signingKeys: PASSKEY_SIGNING_KEYS,
 *   });
 *   await store.create({ ...record, userId: req.user.id });
 */
export async function verifyRegistration(
  input: VerifyRegistrationInput,
): Promise<NewCredentialRecord> {
  const requireUv = input.requireUserVerification ?? true;

  const { challenge: expectedChallenge, userId: envelopeUserId } = await verifyChallengeToken(
    input.challengeToken,
    input.signingKeys,
    'reg',
  );

  // Decode + validate clientData.
  const clientDataBytes = fromBase64Url(input.response.response.clientDataJSON);
  const clientData = parseClientDataJSON(clientDataBytes);
  assertExpectedClientData(clientData, 'webauthn.create', expectedChallenge, input.expectedOrigin);
  assertOriginMatchesRpId(clientData.origin, input.expectedRpId);

  // Decode + parse attestation object.
  const attestationBytes = fromBase64Url(input.response.response.attestationObject);
  const attestation = parseAttestationObject(attestationBytes);

  // RP-ID hash check.
  const expectedRpIdHash = await sha256(encodeUtf8(input.expectedRpId));
  if (!equalBytes(attestation.authData.rpIdHash, expectedRpIdHash)) {
    throw new InvalidRpIdError(undefined, {
      details: { reason: 'rp_id_hash_mismatch', expectedRpId: input.expectedRpId },
    });
  }

  if (!attestation.authData.attestedCredentialData) {
    throw new InvalidAttestationError('authenticatorData.attestedCredentialData is missing.', {
      details: { reason: 'authenticator_data_parse_failed' },
    });
  }

  // Format-specific attestation verification.
  const clientDataHash = await sha256(clientDataBytes);
  const attResult = await verifyAttestation(
    attestation,
    { clientDataHash },
    input.attestationVerifiers,
  );
  if (!attResult.valid) {
    throw new InvalidAttestationError(
      `Attestation "${attestation.fmt}" failed verification.`,
      {
        details: {
          reason: 'attestation_statement_invalid',
          attestationFormat: attestation.fmt,
        },
      },
    );
  }

  // User verification + presence policy.
  assertUserVerification(attestation.authData.flags, requireUv);

  // AAGUID policy.
  const aaguid = aaguidToUuid(attestation.authData.attestedCredentialData.aaguid);
  assertAaguidAllowed(input.policy, aaguid);

  // Validate the credential public key once so alg / kty errors surface at
  // registration time; the raw COSE bytes are persisted opaquely on
  // `publicKey` so the SQL column stays opaque (PLAN §2.3).
  validateCredentialKey(attestation.authData.attestedCredentialData.credentialPublicKey);
  const credentialPublicKeyCose = attestation.authData.attestedCredentialData.credentialPublicKey;

  const credentialId = toBase64Url(attestation.authData.attestedCredentialData.credentialId);
  const transports = (input.response.response.transports ?? []) as ReadonlyArray<AuthenticatorTransport>;
  const flags = attestation.authData.flags;

  const record: NewCredentialRecord = {
    credentialId,
    publicKey: toBase64Url(credentialPublicKeyCose),
    aaguid,
    counter: attestation.authData.signCount,
    transports,
    backupEligible: flags.be,
    backupState: flags.bs,
    deviceType: flags.be ? 'multiDevice' : 'singleDevice',
    ...(envelopeUserId ? { userId: bytesToString(envelopeUserId) } : {}),
  };

  if (input.onVerified) {
    await input.onVerified({
      credentialId: record.credentialId,
      aaguid: record.aaguid,
      attestationFormat: attestation.fmt,
      transports: record.transports,
      flags: { up: flags.up, uv: flags.uv, be: flags.be, bs: flags.bs },
      backupEligible: record.backupEligible,
      backupState: record.backupState,
      deviceType: record.deviceType,
    });
  }

  return record;
}

function validateCredentialKey(coseBytes: Uint8Array): void {
  parseCoseKey(coseBytes);
}

function bytesToString(b: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(b);
}
