import { describe, expect, it } from 'vitest';
import { parseAudit } from '../../src/core/audit/parseAudit';
import { combinePredictions, predictAuditFix } from '../../src/core/resolver/auditFix';
import { advisory, fixtureText, makePackument, packumentFixture } from './helpers';

const audit = parseAudit(fixtureText('audit/sample.json'));
const predict = (name: string, ranges: string[]) => predictAuditFix(packumentFixture(name), ranges, audit.entries.get(name)!.advisories);

describe('predictAuditFix', () => {
  it('axios ^1.18.0: npm elegiría la última, 1.21.0 (aunque Keel recomiende 1.20.0)', () => {
    expect(predict('axios', ['^1.18.0'])).toEqual({ kind: 'audit-fix', version: '1.21.0' });
  });

  it('jsonwebtoken ^8.5.1: no hay 8.x segura, npm pediría --force', () => {
    expect(predict('jsonwebtoken', ['^8.5.1'])).toEqual({ kind: 'force' });
  });

  it('braces transitiva: chokidar acepta ~3.0.2, así que audit fix llega a 3.0.3', () => {
    expect(predict('braces', ['~3.0.2'])).toEqual({ kind: 'audit-fix', version: '3.0.3' });
  });

  it('esbuild transitiva: vite 5 pide ^0.21.3 y la corrección es 0.25, así que pediría --force', () => {
    expect(predict('esbuild', ['^0.21.3'])).toEqual({ kind: 'force' });
  });

  it('con varios rangos, la versión debe cumplirlos todos', () => {
    const packument = makePackument({ '1.0.0': {}, '1.1.0': {}, '1.2.0': {} }, '1.2.0');
    expect(predictAuditFix(packument, ['^1.0.0', '<1.2.0'], [advisory('<1.1.0')])).toEqual({ kind: 'audit-fix', version: '1.1.0' });
  });

  it('evita deprecated si hay alternativa', () => {
    const packument = makePackument({ '1.0.0': {}, '1.1.0': {}, '1.2.0': { deprecated: 'x' } }, '1.0.0');
    expect(predictAuditFix(packument, ['^1.0.0'], [advisory('<1.1.0')])).toEqual({ kind: 'audit-fix', version: '1.1.0' });
  });

  it('no predice con rangos que no son semver', () => {
    const packument = makePackument({ '1.0.0': {} });
    expect(predictAuditFix(packument, ['github:user/repo'], [])).toEqual({ kind: 'unknown' });
  });
});

describe('combinePredictions', () => {
  it('basta una copia que pida --force para que todo lo pida', () => {
    expect(combinePredictions([{ kind: 'audit-fix', version: '1.0.1' }, { kind: 'force' }])).toEqual({ kind: 'force' });
    expect(combinePredictions([{ kind: 'audit-fix', version: '1.0.1' }, { kind: 'audit-fix', version: '1.2.0' }])).toEqual({
      kind: 'audit-fix',
      version: '1.2.0',
    });
    expect(combinePredictions([])).toEqual({ kind: 'unknown' });
  });
});
