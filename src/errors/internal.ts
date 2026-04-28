import { PasskeyError, type PasskeyErrorDetails } from './base.js';

/**
 * Thrown synchronously when the library detects a logic bug or programmer
 * error (missing config, invalid types, unreachable code path). Should never
 * reach the user; if you catch one in production, file a bug.
 *
 * @example
 *   throw new PasskeyInternalError('expected RelyingParty.rpId to be set');
 */
export class PasskeyInternalError extends PasskeyError {
  constructor(message: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('unknown', message, options);
    this.name = 'PasskeyInternalError';
  }
}
