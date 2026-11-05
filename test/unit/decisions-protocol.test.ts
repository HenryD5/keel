import { describe, expect, it } from 'vitest';
import { KeelFileError, keepDecisions, normalizeReason, parseKeelFile, serializeKeelFile, withKeep } from '../../src/core/decisions';
import { parseWebviewMessage } from '../../src/webview/protocol';

describe('decisiones', () => {
  it('parsea vacío y rechaza JSON o keep inválidos', () => {
    expect(parseKeelFile('')).toEqual({});
    expect(() => parseKeelFile('{')).toThrow(KeelFileError);
    expect(() => parseKeelFile('{"keep":[]}')).toThrow(KeelFileError);
  });

  it('filtra decisiones mal formadas y conserva claves desconocidas', () => {
    const file = parseKeelFile('{"future":true,"keep":{"axios":{"version":"1","reason":"x","date":"d"},"bad":{"version":2}}}');
    expect(keepDecisions(file)).toEqual({ axios: { version: '1', reason: 'x', date: 'd' } });
    expect(withKeep(file, 'vite', { version: '2', reason: '  esperar\n ahora ', date: 'd' })).toMatchObject({ future: true, keep: { vite: { reason: 'esperar ahora' } } });
  });

  it('normaliza, limita y serializa con salto final', () => {
    expect(normalizeReason(` a\n${'b'.repeat(600)}`)).toHaveLength(500);
    expect(serializeKeelFile({ keep: {} })).toBe('{\n  "keep": {}\n}\n');
  });
});

describe('parseWebviewMessage', () => {
  it('rechaza tipo desconocido, lang y choice inválidos', () => {
    expect(parseWebviewMessage({ type: 'wat' })).toBeUndefined();
    expect(parseWebviewMessage({ type: 'setLang', lang: 'fr' })).toBeUndefined();
    expect(parseWebviewMessage({ type: 'saveDecision', name: 'axios', choice: 'other' })).toBeUndefined();
  });

  it('rechaza líneas no enteras', () => {
    expect(parseWebviewMessage({ type: 'openFile', path: 'a.ts', line: 1.5 })).toBeUndefined();
    expect(parseWebviewMessage({ type: 'openFile', path: 'a.ts', line: '1' })).toBeUndefined();
  });

  it('valida los mensajes de plan y aplicación', () => {
    expect(parseWebviewMessage({ type: 'requestPlan', selected: ['axios'], exact: false })).toEqual({
      type: 'requestPlan', selected: ['axios'], exact: false, companions: [],
    });
    expect(parseWebviewMessage({ type: 'apply', method: 'exact', selected: ['axios'], exact: true, validate: true })).toEqual({
      type: 'apply', method: 'exact', selected: ['axios'], exact: true, validate: true, companions: [],
    });
    expect(parseWebviewMessage({ type: 'apply', method: 'force', selected: [], exact: false })).toBeUndefined();
    expect(parseWebviewMessage({ type: 'requestPlan', selected: ['axios'], exact: 'false' })).toBeUndefined();
    expect(parseWebviewMessage({ type: 'requestPlan', selected: [1], exact: false })).toBeUndefined();
    expect(parseWebviewMessage({ type: 'requestPlan', selected: ['x'.repeat(215)], exact: false })).toBeUndefined();
  });

  it('parses rollback decisions and validates the apply checkbox', () => {
    expect(parseWebviewMessage({ type: 'revert' })).toEqual({ type: 'revert' });
    expect(parseWebviewMessage({ type: 'keepChanges' })).toEqual({ type: 'keepChanges' });
    expect(parseWebviewMessage({ type: 'apply', method: 'exact', selected: [], exact: false })).toBeUndefined();
  });

  it('acepta mensajes válidos', () => {
    expect(parseWebviewMessage({ type: 'setLang', lang: 'es' })).toEqual({ type: 'setLang', lang: 'es' });
    expect(parseWebviewMessage({ type: 'openFile', path: 'a.ts', line: 1 })).toEqual({ type: 'openFile', path: 'a.ts', line: 1 });
  });
});
