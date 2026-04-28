import { PasskeyError } from '../../errors/base.js';
import {
  InvalidChallengeError,
  InvalidOriginError,
} from '../../errors/classes.js';
import { fromBase64Url } from '../encoding/base64url.js';
import { decodeUtf8 } from '../encoding/utf8.js';
import { timingSafeEqualBytes } from '../crypto/bytes.js';
import type { ParsedClientData } from '../../types/parsed.js';

interface ClientDataJSONShape {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  tokenBinding?: { status: string; id?: string };
}

/**
 * Parse a `clientDataJSON` byte buffer into a typed {@link ParsedClientData}.
 *
 * The raw bytes are retained on `.raw` — hash THOSE, not a re-stringified
 * copy (the authenticator signed the bytes the browser produced, not our
 * normalized JSON).
 *
 * @param bytes  Raw `clientDataJSON` bytes.
 * @returns      Parsed client data.
 * @throws {PasskeyError}  Code `'invalid_attestation'` for non-UTF-8 / non-JSON / missing fields.
 *
 * @example
 *   const cd = parseClientDataJSON(fromBase64Url(response.response.clientDataJSON));
 */
export function parseClientDataJSON(bytes: Uint8Array): ParsedClientData {
  let text: string;
  try {
    text = decodeUtf8(bytes, true);
  } catch (cause) {
    throw bad('clientDataJSON is not valid UTF-8.', cause);
  }

  let parsed: ClientDataJSONShape;
  try {
    parsed = JSON.parse(text) as ClientDataJSONShape;
  } catch (cause) {
    throw bad('clientDataJSON is not valid JSON.', cause);
  }

  if (
    typeof parsed.type !== 'string' ||
    typeof parsed.challenge !== 'string' ||
    typeof parsed.origin !== 'string'
  ) {
    throw bad('clientDataJSON is missing required fields.');
  }

  return {
    type: parsed.type,
    challenge: parsed.challenge,
    origin: parsed.origin,
    crossOrigin: parsed.crossOrigin,
    tokenBinding: parsed.tokenBinding,
    raw: bytes,
  };
}

/**
 * Verify the parsed clientData against the expectations of this ceremony.
 *
 * @param data              Parsed client data.
 * @param expectedType      `'webauthn.create'` for registration, `'webauthn.get'` for authentication.
 * @param expectedChallenge The original challenge bytes the server issued.
 * @param expectedOrigins   One or more allowed origins (string or readonly array).
 * @throws {InvalidChallengeError}  When the challenge doesn't match.
 * @throws {InvalidOriginError}     When the origin is not in the allow-list.
 * @throws {PasskeyError}           Code `'invalid_attestation'` when `type` mismatches.
 *
 * @example
 *   assertExpectedClientData(cd, 'webauthn.get', challengeBytes, 'https://acme.com');
 */
export function assertExpectedClientData(
  data: ParsedClientData,
  expectedType: 'webauthn.create' | 'webauthn.get',
  expectedChallenge: Uint8Array,
  expectedOrigins: string | readonly string[],
): void {
  if (data.type !== expectedType) {
    throw new PasskeyError(
      'invalid_attestation',
      `clientData.type is "${data.type}", expected "${expectedType}".`,
      { details: { reason: 'client_data_parse_failed' } },
    );
  }

  // Always compare bytes through `timingSafeEqualBytes`. A `===` short-circuit
  // would leak nothing about a public nonce by itself, but mixing constant-time
  // and short-circuit comparisons in ceremony code invites the wrong pattern
  // to be copy-pasted into a key-comparison site later. Single-style only.
  let actual: Uint8Array | undefined;
  try {
    actual = fromBase64Url(data.challenge);
  } catch {
    // ignore — falls through to the equality check below, which fails on undefined.
  }
  if (!actual || !timingSafeEqualBytes(actual, expectedChallenge)) {
    throw new InvalidChallengeError(undefined, {
      details: { reason: 'challenge_mismatch' },
    });
  }

  const allowed = typeof expectedOrigins === 'string' ? [expectedOrigins] : expectedOrigins;
  if (!allowed.some((o) => o === data.origin)) {
    throw new InvalidOriginError(undefined, {
      details: { actualOrigin: data.origin, expectedOrigin: allowed },
    });
  }
}

function bad(msg: string, cause?: unknown): PasskeyError {
  return new PasskeyError('invalid_attestation', msg, {
    ...(cause === undefined ? {} : { cause }),
    details: { reason: 'client_data_parse_failed' },
  });
}
