import { PasskeyVerificationError } from '../../errors/verification.js';

/**
 * Validate that an `origin` (URL string) is a legitimate ceremony origin for
 * the given `rpId`. Per WebAuthn:
 *
 * - `origin` must be `https:` (or `http://localhost[:port]` for development).
 * - The host must be `rpId` itself OR a subdomain of `rpId`.
 *
 * @param origin  The origin string the response carries (e.g. `https://app.acme.com`).
 * @param rpId    The configured Relying Party ID (e.g. `acme.com`).
 * @throws {PasskeyVerificationError}  Code `'bad-origin'` (scheme mismatch / not-a-URL) or `'bad-rp-id'` (host mismatch).
 *
 * @example
 *   validateRpId('https://app.acme.com', 'acme.com'); // ok
 *   validateRpId('https://evil.com', 'acme.com');     // throws 'bad-rp-id'
 */
export function validateRpId(origin: string, rpId: string): void {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new PasskeyVerificationError('bad-origin', `origin "${origin}" is not a valid URL.`, {
      details: { actualOrigin: origin },
    });
  }

  const isLocalhost = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost)) {
    throw new PasskeyVerificationError(
      'bad-origin',
      `origin scheme "${url.protocol}" is not allowed (must be https:, or http://localhost).`,
      { details: { actualOrigin: origin } },
    );
  }

  // Strip IPv6 brackets to compare against rpId.
  const host = url.hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (host !== rpId && !host.endsWith(`.${rpId}`)) {
    throw new PasskeyVerificationError('bad-rp-id', `host "${host}" is not "${rpId}" or a subdomain of it.`, {
      details: { expectedRpId: rpId, actualOrigin: origin },
    });
  }
}

/**
 * Derive the effective domain (rpId) from the first allowed origin. Used when
 * a caller omits `rpId` explicitly. Localhost is returned as-is.
 *
 * @param origin  An https URL.
 * @returns       The hostname (suitable for `rpId`).
 */
export function deriveRpIdFromOrigin(origin: string): string {
  const url = new URL(origin);
  return url.hostname.replace(/^\[/, '').replace(/\]$/, '');
}
