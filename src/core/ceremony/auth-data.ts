import { PasskeyError } from '../../errors/base.js';
import type { ParsedAuthenticatorData } from '../../types/parsed.js';
import { decodeFlags } from './flags.js';
import { decodeCbor } from '../cose/cbor.js';

/**
 * Parse the WebAuthn `authenticatorData` byte structure.
 *
 * Layout (WebAuthn L3 §6.1):
 *   `rpIdHash (32) || flags (1) || signCount (4 BE) || [attCredData] || [extensions]`
 *
 * The COSE-key map at the tail of attested credential data is decoded only
 * to advance the cursor — the raw bytes are returned on
 * `attestedCredentialData.credentialPublicKey` for downstream parsing /
 * SPKI export.
 *
 * @param bytes  Raw `authenticatorData` bytes.
 * @returns      {@link ParsedAuthenticatorData} with `.raw` retained for signature verification.
 * @throws {PasskeyError}  Code `'invalid_attestation'` for truncated / malformed input.
 *
 * @example
 *   const ad = parseAuthenticatorData(authDataBytes);
 *   if (!ad.flags.up) throw new AuthenticationFailedError();
 */
export function parseAuthenticatorData(bytes: Uint8Array): ParsedAuthenticatorData {
  if (bytes.length < 37) {
    throw bad(`authenticatorData too short: ${bytes.length} < 37.`);
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
      throw bad('authenticatorData truncated in attested credential data header.');
    }
    const aaguid = bytes.subarray(offset, offset + 16).slice();
    offset += 16;
    const credIdLen = view.getUint16(offset);
    offset += 2;
    if (bytes.length < offset + credIdLen) {
      throw bad('authenticatorData truncated in credentialId.');
    }
    const credentialId = bytes.subarray(offset, offset + credIdLen).slice();
    offset += credIdLen;

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

  return {
    rpIdHash,
    flags,
    signCount,
    raw: bytes,
    ...(attestedCredentialData ? { attestedCredentialData } : {}),
    ...(extensions ? { extensions } : {}),
  };
}

function bad(msg: string): PasskeyError {
  return new PasskeyError('invalid_attestation', msg, {
    details: { reason: 'authenticator_data_parse_failed' },
  });
}
