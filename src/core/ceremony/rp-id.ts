import { InvalidOriginError, InvalidRpIdError } from '../../errors/classes.js';

/**
 * Validate that an `origin` is a legitimate ceremony origin for the given
 * `rpId`. Per WebAuthn:
 *
 * - `origin` must be `https:` (or `http://localhost[:port]` for development).
 * - The host must be `rpId` itself OR a subdomain of `rpId`.
 *
 * @param origin  Origin string from `clientData` (e.g. `https://app.acme.com`).
 * @param rpId    The configured Relying Party ID (e.g. `acme.com`).
 * @throws {InvalidOriginError}  When `origin` is malformed or uses a disallowed scheme.
 * @throws {InvalidRpIdError}    When `origin`'s host is not `rpId` or a subdomain.
 *
 * @example
 *   assertOriginMatchesRpId('https://app.acme.com', 'acme.com'); // ok
 *   assertOriginMatchesRpId('https://evil.com', 'acme.com');     // throws InvalidRpIdError
 */
export function assertOriginMatchesRpId(origin: string, rpId: string): void {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new InvalidOriginError(`origin "${origin}" is not a valid URL.`, {
      details: { actualOrigin: origin },
    });
  }

  const isLocalhost =
    url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLocalhost)) {
    throw new InvalidOriginError(
      `origin scheme "${url.protocol}" is not allowed (must be https:, or http://localhost).`,
      { details: { actualOrigin: origin } },
    );
  }

  const host = url.hostname.replace(/^\[/, '').replace(/\]$/, '');
  if (host !== rpId && !host.endsWith(`.${rpId}`)) {
    throw new InvalidRpIdError(
      `host "${host}" is not "${rpId}" nor a subdomain of it.`,
      { details: { expectedRpId: rpId, actualOrigin: origin } },
    );
  }
}

/**
 * Derive the effective domain (rpId) from an origin. Used when a caller omits
 * `rpId` explicitly. Localhost and IPv6 hosts are returned as-is (without
 * brackets).
 *
 * @param origin  An https URL.
 * @returns       The hostname (suitable for `rpId`).
 */
export function deriveRpIdFromOrigin(origin: string): string {
  const url = new URL(origin);
  return url.hostname.replace(/^\[/, '').replace(/\]$/, '');
}
