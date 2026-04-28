/**
 * Shared helpers for stubbing the browser globals (`navigator`,
 * `PublicKeyCredential`) inside Node-based vitest runs. Node ≥18 exposes
 * `globalThis.navigator` as a getter-only descriptor; assignment fails with
 * "has only a getter", so every browser test goes through these helpers.
 */

const g = globalThis as unknown as Record<string, unknown>;

let navigatorBackup: PropertyDescriptor | undefined;
let publicKeyCredentialBackup: PropertyDescriptor | undefined;

export function setNavigator(value: unknown): void {
  if (navigatorBackup === undefined) {
    navigatorBackup = Object.getOwnPropertyDescriptor(g, 'navigator');
  }
  Object.defineProperty(g, 'navigator', {
    value,
    writable: true,
    configurable: true,
    enumerable: true,
  });
}

export function deleteNavigator(): void {
  if (navigatorBackup === undefined) {
    navigatorBackup = Object.getOwnPropertyDescriptor(g, 'navigator');
  }
  delete g['navigator'];
}

export function setPublicKeyCredential(value: unknown): void {
  if (publicKeyCredentialBackup === undefined) {
    publicKeyCredentialBackup = Object.getOwnPropertyDescriptor(g, 'PublicKeyCredential');
  }
  Object.defineProperty(g, 'PublicKeyCredential', {
    value,
    writable: true,
    configurable: true,
    enumerable: true,
  });
}

export function deletePublicKeyCredential(): void {
  if (publicKeyCredentialBackup === undefined) {
    publicKeyCredentialBackup = Object.getOwnPropertyDescriptor(g, 'PublicKeyCredential');
  }
  delete g['PublicKeyCredential'];
}

export function restoreGlobals(): void {
  if (navigatorBackup !== undefined) {
    delete g['navigator'];
    Object.defineProperty(g, 'navigator', navigatorBackup);
    navigatorBackup = undefined;
  }
  if (publicKeyCredentialBackup !== undefined) {
    delete g['PublicKeyCredential'];
    Object.defineProperty(g, 'PublicKeyCredential', publicKeyCredentialBackup);
    publicKeyCredentialBackup = undefined;
  }
}
