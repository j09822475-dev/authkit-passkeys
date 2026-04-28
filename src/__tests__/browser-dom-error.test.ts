import { describe, expect, it } from 'vitest';
import { mapDomException } from '../browser/dom-error.js';
import {
  InternalError,
  InvalidStateError,
  NotSupportedError,
  PasskeyError,
  SecurityError,
  TimeoutError,
  UserCancelledError,
} from '../errors/index.js';

function makeDomError(name: string, message = 'm'): Error {
  const e = new Error(message);
  e.name = name;
  return e;
}

describe('mapDomException', () => {
  it('should pass through PasskeyError unchanged', () => {
    const original = new TimeoutError('already mapped');
    expect(mapDomException(original)).toBe(original);
  });

  it('should map NotSupportedError', () => {
    expect(mapDomException(makeDomError('NotSupportedError'))).toBeInstanceOf(NotSupportedError);
  });

  it('should map a short NotAllowedError to UserCancelledError', () => {
    const e = mapDomException(makeDomError('NotAllowedError'), 1000);
    expect(e).toBeInstanceOf(UserCancelledError);
  });

  it('should map a long NotAllowedError (>= 30s) to TimeoutError', () => {
    const e = mapDomException(makeDomError('NotAllowedError'), 30_000);
    expect(e).toBeInstanceOf(TimeoutError);
  });

  it('should default NotAllowedError without elapsedMs to UserCancelledError', () => {
    expect(mapDomException(makeDomError('NotAllowedError'))).toBeInstanceOf(UserCancelledError);
  });

  it('should map AbortError to UserCancelledError', () => {
    expect(mapDomException(makeDomError('AbortError'))).toBeInstanceOf(UserCancelledError);
  });

  it('should map InvalidStateError', () => {
    expect(mapDomException(makeDomError('InvalidStateError'))).toBeInstanceOf(InvalidStateError);
  });

  it('should map SecurityError', () => {
    expect(mapDomException(makeDomError('SecurityError'))).toBeInstanceOf(SecurityError);
  });

  it('should map TimeoutError', () => {
    expect(mapDomException(makeDomError('TimeoutError'))).toBeInstanceOf(TimeoutError);
  });

  it('should map any unknown DOMException to InternalError (not NotSupportedError)', () => {
    expect(mapDomException(makeDomError('SomethingWeird'))).toBeInstanceOf(InternalError);
  });

  it('should preserve the original error as cause', () => {
    const cause = makeDomError('SecurityError', 'rp mismatch');
    const mapped = mapDomException(cause);
    expect((mapped as PasskeyError).cause).toBe(cause);
  });

  it('should accept non-Error values', () => {
    const mapped = mapDomException('plain string');
    expect(mapped).toBeInstanceOf(InternalError);
    expect(mapped.message).toBe('plain string');
  });
});
