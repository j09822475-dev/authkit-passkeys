import { PasskeyError } from '../../errors/base.js';
import { PasskeyVerificationError } from '../../errors/verification.js';
import { fromBase64Url, toBase64Url } from '../encoding/base64url.js';
import { decodeUtf8 } from '../encoding/utf8.js';
import type { ParsedClientData } from '../../types/ceremony.js';

interface ClientDataJSONShape {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
  tokenBinding?: { status: string; id?: string };
}

/**
 * Parse a `clientDataJSON` byte buffer into a typed {@link ParsedClientData}.
 * The raw bytes are retained on `.raw` — hash THOSE, not a re-stringified copy
 * (the authenticator signed the bytes the browser produced, not our normalized
 * JSON).
 *
 * @param bytes  Raw `clientDataJSON` bytes (NOT base64url decoded JSON of the wire format — the inner UTF-8).
 * @returns      Parsed client data with `.raw` retained.
 * @throws {PasskeyError}  Code `'malformed-response'` for non-UTF-8 / non-JSON / missing fields.
 *
 * @example
 *   const cd = parseClientDataJSON(fromBase64Url(response.clientDataJSON));
 */
export function parseClientDataJSON(bytes: Uint8Array): ParsedClientData {
  let text: string;
  try {
    text = decodeUtf8(bytes, true);
  } catch (cause) {
    throw new PasskeyError('malformed-response', 'clientDataJSON is not valid UTF-8.', {
      cause,
      details: { reason: 'client-data-parse-failed' },
    });
  }

  let parsed: ClientDataJSONShape;
  try {
    parsed = JSON.parse(text) as ClientDataJSONShape;
  } catch (cause) {
    throw new PasskeyError('malformed-response', 'clientDataJSON is not valid JSON.', {
      cause,
      details: { reason: 'client-data-parse-failed' },
    });
  }

  if (typeof parsed.type !== 'string' || typeof parsed.challenge !== 'string' || typeof parsed.origin !== 'string') {
    throw new PasskeyError('malformed-response', 'clientDataJSON is missing required fields.', {
      details: { reason: 'client-data-parse-failed' },
    });
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
 * @param data              The parsed client data.
 * @param expectedType      `'webauthn.create'` for registration, `'webauthn.get'` for authentication.
 * @param expectedChallenge The original challenge bytes the server issued.
 * @param expectedOrigins   One or more allowed origins (string or array).
 * @throws {PasskeyVerificationError}  When type/challenge/origin mismatch (typed code; details carry the reason).
 *
 * @example
 *   assertExpectedClientData(cd, 'webauthn.get', challengeBytes, ['https://acme.com']);
 */
export function assertExpectedClientData(
  data: ParsedClientData,
  expectedType: 'webauthn.create' | 'webauthn.get',
  expectedChallenge: Uint8Array,
  expectedOrigins: string | readonly string[],
): void {
  if (data.type !== expectedType) {
    throw new PasskeyVerificationError(
      expectedType === 'webauthn.create' ? 'registration-failed' : 'authentication-failed',
      `clientData.type is ${data.type}, expected ${expectedType}.`,
      { details: { reason: 'client-data-parse-failed' } },
    );
  }

  if (data.challenge !== toBase64Url(expectedChallenge)) {
    let actual: Uint8Array | undefined;
    try {
      actual = fromBase64Url(data.challenge);
    } catch {
      // ignore
    }
    if (!actual || !timingSafeEqualBytes(actual, expectedChallenge)) {
      throw new PasskeyVerificationError('bad-challenge', 'clientData challenge does not match issued challenge.', {
        details: { reason: 'challenge-mismatch' },
      });
    }
  }

  const allowed = typeof expectedOrigins === 'string' ? [expectedOrigins] : expectedOrigins;
  if (!allowed.some((o) => o === data.origin)) {
    throw new PasskeyVerificationError('bad-origin', `clientData origin "${data.origin}" is not allowed.`, {
      details: { actualOrigin: data.origin, expectedOrigin: allowed },
    });
  }
}

function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
