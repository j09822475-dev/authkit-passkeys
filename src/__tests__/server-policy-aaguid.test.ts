import { describe, expect, it } from 'vitest';
import { assertAaguidAllowed } from '../server/policy/aaguid.js';
import { ANONYMOUS_AAGUID } from '../core/encoding/hex.js';
import { AaguidNotAllowedError } from '../errors/index.js';
import type { AaguidString } from '../types/webauthn.js';

const A1 = '00000000-0000-0000-0000-000000000001' as AaguidString;
const A2 = '00000000-0000-0000-0000-000000000002' as AaguidString;
const A3 = '00000000-0000-0000-0000-000000000003' as AaguidString;

describe('assertAaguidAllowed', () => {
  it('should accept any AAGUID when no policy is provided', () => {
    expect(() => assertAaguidAllowed(undefined, A1)).not.toThrow();
  });

  it('should accept an AAGUID on the allow-list', () => {
    expect(() => assertAaguidAllowed({ allow: [A1, A2] }, A1)).not.toThrow();
  });

  it('should reject an AAGUID NOT on the allow-list', () => {
    expect(() => assertAaguidAllowed({ allow: [A1, A2] }, A3)).toThrow(AaguidNotAllowedError);
  });

  it('should reject the anonymous AAGUID under allowlist mode by default', () => {
    expect(() => assertAaguidAllowed({ allow: [A1] }, ANONYMOUS_AAGUID)).toThrow(
      AaguidNotAllowedError,
    );
  });

  it('should accept the anonymous AAGUID when allowAnonymous is true', () => {
    expect(() =>
      assertAaguidAllowed({ allow: [A1], allowAnonymous: true }, ANONYMOUS_AAGUID),
    ).not.toThrow();
  });

  it('should reject an AAGUID on the deny-list (deny-wins precedence)', () => {
    expect(() => assertAaguidAllowed({ deny: [A1] }, A1)).toThrow(AaguidNotAllowedError);
  });

  it('should let deny override allow when both list the same AAGUID', () => {
    expect(() => assertAaguidAllowed({ allow: [A1], deny: [A1] }, A1)).toThrow(
      AaguidNotAllowedError,
    );
  });

  it('should accept an AAGUID under denylist mode when not denied', () => {
    expect(() => assertAaguidAllowed({ mode: 'denylist', deny: [A2] }, A1)).not.toThrow();
  });

  it('should default mode to allowlist when only allow is provided', () => {
    expect(() => assertAaguidAllowed({ allow: [A1] }, A2)).toThrow(AaguidNotAllowedError);
  });

  it('should default mode to denylist when only deny is provided', () => {
    expect(() => assertAaguidAllowed({ deny: [A2] }, A1)).not.toThrow();
  });
});
