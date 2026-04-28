import type { COSEAlgorithmIdentifier } from '../../types/webauthn-json.js';

/**
 * COSE algorithm identifiers we support out of the box.
 * @see https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export const COSE_ALG = {
  /** ECDSA w/ SHA-256 (P-256). Required for FIDO2 / passkeys. */
  ES256: -7,
  /** EdDSA (Ed25519). */
  EdDSA: -8,
  /** ECDSA w/ SHA-384 (P-384). */
  ES384: -35,
  /** ECDSA w/ SHA-512 (P-521). */
  ES512: -36,
  /** RSASSA-PKCS1-v1_5 w/ SHA-256. */
  RS256: -257,
  /** RSASSA-PKCS1-v1_5 w/ SHA-384. */
  RS384: -258,
  /** RSASSA-PKCS1-v1_5 w/ SHA-512. */
  RS512: -259,
  /** RSASSA-PSS w/ SHA-256. */
  PS256: -37,
  /** RSASSA-PSS w/ SHA-384. */
  PS384: -38,
  /** RSASSA-PSS w/ SHA-512. */
  PS512: -39,
} as const satisfies Record<string, COSEAlgorithmIdentifier>;

/** Default algorithm preference offered to the authenticator at registration. */
export const DEFAULT_PUB_KEY_CRED_PARAMS: ReadonlyArray<{
  alg: COSEAlgorithmIdentifier;
  type: 'public-key';
}> = [
  { alg: COSE_ALG.ES256, type: 'public-key' },
  { alg: COSE_ALG.EdDSA, type: 'public-key' },
  { alg: COSE_ALG.RS256, type: 'public-key' },
];

/** COSE EC2 curve identifiers. */
export const COSE_CURVE = {
  P_256: 1,
  P_384: 2,
  P_521: 3,
  ED25519: 6,
} as const;

/**
 * Mapping from COSE algorithm to the parameters required by `crypto.subtle.verify`.
 * Returns `null` if the algorithm is not supported by this build.
 */
export function coseAlgToWebCrypto(alg: COSEAlgorithmIdentifier): {
  importParams: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams;
  verifyParams: AlgorithmIdentifier | EcdsaParams | RsaPssParams;
} | null {
  switch (alg) {
    case COSE_ALG.ES256:
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
      };
    case COSE_ALG.ES384:
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-384' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-384' },
      };
    case COSE_ALG.ES512:
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-521' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-512' },
      };
    case COSE_ALG.EdDSA:
      return {
        importParams: { name: 'Ed25519' },
        verifyParams: { name: 'Ed25519' },
      };
    case COSE_ALG.RS256:
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
      };
    case COSE_ALG.RS384:
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
      };
    case COSE_ALG.RS512:
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
      };
    case COSE_ALG.PS256:
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-256' },
        verifyParams: { name: 'RSA-PSS', saltLength: 32 },
      };
    case COSE_ALG.PS384:
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-384' },
        verifyParams: { name: 'RSA-PSS', saltLength: 48 },
      };
    case COSE_ALG.PS512:
      return {
        importParams: { name: 'RSA-PSS', hash: 'SHA-512' },
        verifyParams: { name: 'RSA-PSS', saltLength: 64 },
      };
    default:
      return null;
  }
}

/** Algorithms that use raw `r||s` ECDSA signatures (need DER conversion before WebCrypto). */
export function isEcdsaAlg(alg: COSEAlgorithmIdentifier): boolean {
  return alg === COSE_ALG.ES256 || alg === COSE_ALG.ES384 || alg === COSE_ALG.ES512;
}
