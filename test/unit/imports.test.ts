import { describe, expect, it } from 'vitest';
import { findUsages } from '../../src/core/impact/imports';
import { fixtureText } from './helpers';

describe('findUsages', () => {
  it('encuentra default import y sus métodos, sin comentarios ni nombres parecidos', () => {
    expect(findUsages(fixtureText('imports/jwt.ts'), 'jsonwebtoken')).toEqual([
      { line: 3, kind: 'import', symbol: 'jwt.verify' },
      { line: 4, kind: 'import', symbol: 'jwt.sign' },
    ]);
  });

  it('encuentra require destructurado con alias', () => {
    expect(findUsages(fixtureText('imports/common.js'), 'jsonwebtoken')).toEqual([{ line: 3, kind: 'require', symbol: 'sign' }]);
  });

  it('encuentra subrutas, namespace, named multilínea y dynamic import en Vue', () => {
    expect(findUsages(fixtureText('imports/mixed.vue'), 'axios')).toEqual([
      { line: 7, kind: 'import', symbol: 'http.get' },
      { line: 8, kind: 'import', symbol: 'AxiosError' },
      { line: 9, kind: 'dynamic-import', symbol: 'lazy.post' },
    ]);
  });

  it('devuelve la línea del import si no se usa', () => {
    expect(findUsages(fixtureText('imports/unused.ts'), 'axios')).toEqual([{ line: 1, kind: 'import', symbol: 'axios' }]);
  });
});
