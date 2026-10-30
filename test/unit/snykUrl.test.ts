import { describe, expect, it } from 'vitest';
import { snykUrl } from '../../src/core/reference/snykUrl';

describe('snykUrl', () => {
  it('apunta a la versión indicada', () => {
    expect(snykUrl('axios', '1.15.0')).toBe('https://security.snyk.io/package/npm/axios/1.15.0');
  });

  it('codifica los paquetes con scope', () => {
    expect(snykUrl('@babel/core', '7.24.0')).toBe('https://security.snyk.io/package/npm/%40babel%2Fcore/7.24.0');
  });

  it('sin versión apunta a la página del paquete', () => {
    expect(snykUrl('axios')).toBe('https://security.snyk.io/package/npm/axios');
  });
});
