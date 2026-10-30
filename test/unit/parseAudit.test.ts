import { describe, expect, it } from 'vitest';
import { AuditError, countBySeverity, maxSeverity, parseAudit } from '../../src/core/audit/parseAudit';
import { fixtureText } from './helpers';

describe('parseAudit', () => {
  const result = parseAudit(fixtureText('audit/sample.json'));

  it('lee el formato v2 real de npm audit', () => {
    expect([...result.entries.keys()].sort()).toEqual(['axios', 'braces', 'esbuild', 'jsonwebtoken', 'vite']);
    expect(result.totals.total).toBe(5);
  });

  it('separa advisories propios de dependencias vulnerables en via', () => {
    const vite = result.entries.get('vite')!;
    expect(vite.isDirect).toBe(true);
    expect(vite.advisories).toHaveLength(20);
    expect(vite.viaPackages).toEqual(['esbuild']);
    expect(result.entries.get('esbuild')!.effects).toEqual(['vite']);
  });

  it('conserva rango, severidad y fixAvailable', () => {
    const jwt = result.entries.get('jsonwebtoken')!;
    expect(jwt.fixAvailable).toEqual({ name: 'jsonwebtoken', version: '9.0.3', isSemVerMajor: true });
    expect(jwt.advisories.map((a) => a.range)).toEqual(['<=8.5.1', '<=8.5.1', '<9.0.0']);
    expect(jwt.nodes).toEqual(['node_modules/jsonwebtoken']);
  });

  it('elimina advisories repetidos en via', () => {
    const raw = JSON.parse(fixtureText('audit/sample.json'));
    const via = raw.vulnerabilities.braces.via[0];
    raw.vulnerabilities.braces.via.push(via);
    expect(parseAudit(JSON.stringify(raw)).entries.get('braces')!.advisories).toHaveLength(1);
  });

  it('convierte el error de npm (sin lockfile) en AuditError', () => {
    expect(() => parseAudit(fixtureText('audit/error-enolock.json'))).toThrowError(AuditError);
    try {
      parseAudit(fixtureText('audit/error-enolock.json'));
    } catch (err) {
      expect((err as AuditError).code).toBe('ENOLOCK');
    }
  });

  it('rechaza JSON inválido y formatos que no son v2', () => {
    expect(() => parseAudit('npm ERR! something')).toThrowError(/valid JSON/);
    expect(() => parseAudit(JSON.stringify({ auditReportVersion: 1, advisories: {} }))).toThrowError(/auditReportVersion 2/);
  });
});

describe('maxSeverity / countBySeverity', () => {
  it('calcula la severidad máxima y el conteo', () => {
    const list = [{ severity: 'moderate' as const }, { severity: 'critical' as const }, { severity: 'moderate' as const }];
    expect(maxSeverity(list)).toBe('critical');
    expect(maxSeverity([])).toBeUndefined();
    expect(countBySeverity(list)).toEqual({ info: 0, low: 0, moderate: 2, high: 0, critical: 1 });
  });
});
