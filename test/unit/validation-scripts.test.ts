import { describe, expect, it } from 'vitest';
import { isValidScriptName, selectValidationScripts } from '../../src/core/apply/validation';

describe('validation scripts', () => {
  it('validates names accepted by npm run', () => {
    expect(isValidScriptName('test:unit')).toBe(true);
    expect(isValidScriptName('build.prod-1')).toBe(true);
    expect(isValidScriptName('-bad')).toBe(false);
    expect(isValidScriptName('bad name')).toBe(false);
  });

  it('selects configured scripts in order and marks missing ones', () => {
    expect(selectValidationScripts(['test', 'missing', '../bad'], '{"scripts":{"test":"vitest"}}')).toEqual([
      { name: 'test', exists: true },
      { name: 'missing', exists: false },
    ]);
  });
});
