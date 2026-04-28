import { PasskeyError } from '../../errors/base.js';
import type { ParsedAuthenticatorData } from '../../types/ceremony.js';
import { decodeFlags } from './flags.js';
import { decodeCbor } from '../cose/cbor.js';

/**
 * Parse the WebAuthn `authenticatorData` byte structure.
 *
 * Layout (WebAuthn L3 §6.1):
 *   rpIdHash (32) || flags (1) || signCount (4 BE) || [attCredData] || [extensions]
 *
 * @param bytes  Raw `authenticatorData` bytes.
 * @returns      Typed {@link ParsedAuthenticatorData} with the original byte slice retained on `.raw`.
 * @throws {PasskeyError}  Code `'malformed-response'` for truncated or otherwise invalid input.
 *
 * @example
 *   const ad = parseAuthenticatorData(authDataBytes);
 *   if (!ad.flags.up) return err(...);
 */
export function parseAuthenticatorData(bytes: Uint8Array): ParsedAuthenticatorData {
  if (bytes.length < 37) {
    throw new PasskeyError('malformed-response', `authenticatorData too short: ${bytes.length} < 37.`, {
      details: { reason: 'authenticator-data-parse-failed' },
    });
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rpIdHash = bytes.subarray(0, 32).slice();
  const flagsByte = bytes[32] as number;
  const flags = decodeFlags(flagsByte);
  const signCount = view.getUint32(33);

  let offset = 37;
  let attestedCredentialData: ParsedAuthenticatorData['attestedCredentialData'];

  if (flags.at) {
    if (bytes.length < offset + 18) {
      throw new PasskeyError('malformed-response', 'authenticatorData truncated in attested credential data header.', {
        details: { reason: 'authenticator-data-parse-failed' },
      });
    }
    const aaguid = bytes.subarray(offset, offset + 16).slice();
    offset += 16;
    const credIdLen = view.getUint16(offset);
    offset += 2;
    if (bytes.length < offset + credIdLen) {
      throw new PasskeyError('malformed-response', 'authenticatorData truncated in credentialId.', {
        details: { reason: 'authenticator-data-parse-failed' },
      });
    }
    const credentialId = bytes.subarray(offset, offset + credIdLen).slice();
    offset += credIdLen;

    // The COSE key consumes a CBOR map; decode-and-measure to advance the cursor exactly.
    const keySlice = bytes.subarray(offset);
    const { bytesRead } = decodeCbor(keySlice);
    const credentialPublicKey = bytes.subarray(offset, offset + bytesRead).slice();
    offset += bytesRead;

    attestedCredentialData = { aaguid, credentialId, credentialPublicKey };
  }

  let extensions: Uint8Array | undefined;
  if (flags.ed) {
    const extSlice = bytes.subarray(offset);
    const { bytesRead } = decodeCbor(extSlice);
    extensions = bytes.subarray(offset, offset + bytesRead).slice();
    offset += bytesRead;
  }

  const result: ParsedAuthenticatorData = {
    rpIdHash,
    flags,
    signCount,
    raw: bytes,
    ...(attestedCredentialData ? { attestedCredentialData } : {}),
    ...(extensions ? { extensions } : {}),
  };
  return result;
}
