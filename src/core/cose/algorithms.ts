import type { CoseAlgId, CoseAlgName } from '../../types/webauthn.js';

/**
 * COSE algorithm identifiers.
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
} as const satisfies Record<CoseAlgName, CoseAlgId>;

/**
 * Default algorithm preference offered to the authenticator at registration.
 *
 * EdDSA precedes RS256 because Ed25519 keys are ~32 B vs RSA ≥256 B; RS256 is
 * kept for Windows Hello compatibility (PLAN Appendix C).
 */
export const DEFAULT_PUB_KEY_CRED_ALGS: ReadonlyArray<CoseAlgName> = ['ES256', 'EdDSA', 'RS256'];

/** COSE EC2 / OKP curve identifiers. */
export const COSE_CURVE = {
  P_256: 1,
  P_384: 2,
  P_521: 3,
  ED25519: 6,
} as const;

/**
 * Resolve the COSE algorithm identifier for a name.
 *
 * @param name  Algorithm name (e.g. `'ES256'`).
 * @returns     The signed COSE algorithm integer.
 */
export function coseAlgId(name: CoseAlgName): CoseAlgId {
  return COSE_ALG[name];
}

/**
 * Map a COSE algorithm identifier to the parameters required by
 * `crypto.subtle.importKey` and `crypto.subtle.verify`. Returns `null` if the
 * algorithm is not supported by this build.
 *
 * @param alg  COSE algorithm identifier.
 * @returns    `{ importParams, verifyParams }` or `null`.
 */
export function coseAlgToWebCrypto(alg: CoseAlgId): {
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
    default:
      return null;
  }
}

/** True iff `alg` is an ECDSA variant (raw r||s ↔ DER conversion required). */
export function isEcdsaAlg(alg: CoseAlgId): boolean {
  return alg === COSE_ALG.ES256 || alg === COSE_ALG.ES384 || alg === COSE_ALG.ES512;
}
