/**
 * Library version. Replaced at build time by tsup's `define` plugin with the
 * value from `package.json#version`. The fallback keeps the literal in source
 * so the import works even if the build define is skipped.
 */
declare const __PACKAGE_VERSION__: string | undefined;

/**
 * Current `@authkit/passkeys` version string.
 *
 * @returns The semver string from `package.json#version` at build time.
 */
export function version(): string {
  return typeof __PACKAGE_VERSION__ === 'string' ? __PACKAGE_VERSION__ : '0.1.0';
}
