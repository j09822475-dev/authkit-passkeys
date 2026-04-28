/**
 * Library version. Replaced at build time by tsup's `define` plugin with the
 * value from `package.json#version`. The fallback is the source-of-truth so
 * the literal isn't lost if the build define is ever skipped.
 */
declare const __PACKAGE_VERSION__: string | undefined;

export const VERSION: string =
  typeof __PACKAGE_VERSION__ === 'string' ? __PACKAGE_VERSION__ : '0.1.0';
