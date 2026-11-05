import { describe, expect, it } from 'vitest';
import { parseAudit } from '../../src/core/audit/parseAudit';
import { resolveMinSafeVersion, type ResolveInput } from '../../src/core/resolver/minSafeVersion';
import { buildVersionTable } from '../../src/core/resolver/versionTable';
import { advisory, FIXTURE_NOW, fixtureText, makePackument, packumentFixture } from './helpers';

const audit = parseAudit(fixtureText('audit/sample.json'));

function realCase(name: string, installed: string, overrides: Partial<ResolveInput> = {}) {
  const entry = audit.entries.get(name)!;
  return resolveMinSafeVersion({
    packument: packumentFixture(name),
    installed,
    advisories: entry.advisories,
    severity: entry.severity,
    quarantineDays: 7,
    now: FIXTURE_NOW,
    ...overrides,
  });
}

describe('resolveMinSafeVersion · casos reales', () => {
  it('explica por qué no sirve la última de la línea instalada (caso vitest 3.2.7)', () => {
    const packument = makePackument({ '3.2.6': { ageDays: 200 }, '3.2.7': { ageDays: 120 }, '4.1.11': { ageDays: 80 } });
    const advisories = [advisory('>=2.1.0 <4.1.11', 'high', 82)];
    const r = resolveMinSafeVersion({ packument, installed: '3.2.6', advisories, severity: 'high', quarantineDays: 7, now: FIXTURE_NOW });
    expect(r.recommended?.version).toBe('4.1.11');
    expect(r.lineBlocker).toEqual({ version: '3.2.7', reason: 'vulnerable', advisoryIds: [82] });
  });

  it('ofrece la mejor versión sin salto major cuando corrige una parte', () => {
    const packument = makePackument({ '3.2.6': { ageDays: 200 }, '3.2.7': { ageDays: 120 }, '3.2.8': { ageDays: 1 }, '4.1.11': { ageDays: 80 } });
    const advisories = [advisory('>=2.1.0 <4.1.11', 'high', 1), advisory('<3.2.7', 'critical', 2)];
    const r = resolveMinSafeVersion({ packument, installed: '3.2.6', advisories, severity: 'critical', quarantineDays: 7, now: FIXTURE_NOW });
    expect(r.recommended?.version).toBe('4.1.11');
    expect(r.bestInLine).toMatchObject({ version: '3.2.7', bump: 'patch', fixedIds: [2], remainingIds: [1] });
  });

  it('no ofrece versión sin salto major si no reduce nada (vitest 3.2.7 = 3.2.6)', () => {
    const packument = makePackument({ '3.2.6': { ageDays: 200 }, '3.2.7': { ageDays: 120 }, '4.1.11': { ageDays: 80 } });
    const r = resolveMinSafeVersion({ packument, installed: '3.2.6', advisories: [advisory('>=2.1.0 <4.1.11', 'high', 1)], severity: 'high', quarantineDays: 7, now: FIXTURE_NOW });
    expect(r.bestInLine).toBeUndefined();
    expect(r.lineBlocker?.version).toBe('3.2.7');
  });

  it('la tabla incluye la versión siguiente y la última de la línea instalada (vitest 3.2.7)', () => {
    const packument = makePackument({ '3.2.5': { ageDays: 300 }, '3.2.6': { ageDays: 200 }, '3.2.7': { ageDays: 120 }, '4.1.9': { ageDays: 100 }, '4.1.10': { ageDays: 90 }, '4.1.11': { ageDays: 80 } });
    const advisories = [advisory('>=2.1.0 <4.1.11', 'high', 1)];
    const resolution = resolveMinSafeVersion({ packument, installed: '3.2.6', advisories, severity: 'high', quarantineDays: 7, now: FIXTURE_NOW });
    const rows = buildVersionTable({ packument, installed: '3.2.6', advisories, resolution, excluded: new Set(), now: FIXTURE_NOW, quarantineDays: 7 });
    expect(rows.map((r) => r.version)).toContain('3.2.7');
    expect(rows.find((r) => r.version === '3.2.7')!.roles).toContain('line');
  });

  it('sin salto major obligatorio no hay bloqueo de línea', () => {
    expect(realCase('axios', '1.18.0').lineBlocker).toBeUndefined();
  });

  it('axios 1.18.0 → 1.20.0; la última 1.21.0 está en cuarentena', () => {
    const r = realCase('axios', '1.18.0');
    expect(r.status).toBe('ok');
    expect(r.recommended).toMatchObject({ version: '1.20.0', bump: 'minor', inQuarantine: false });
    expect(r.latest).toMatchObject({ version: '1.21.0', reason: 'quarantine', inQuarantine: true });
    expect(Math.floor(r.latest!.ageDays!)).toBe(3);
    expect(r.safeVersions).toEqual(['1.20.0', '1.21.0']);
  });

  it('axios sin cuarentena sigue recomendando 1.20.0 y no la última', () => {
    const r = realCase('axios', '1.18.0', { quarantineDays: 0 });
    expect(r.recommended!.version).toBe('1.20.0');
    expect(r.latest!.reason).toBe('not-needed');
  });

  it('jsonwebtoken 8.5.1 → 9.0.0 (major, no hay 8.x segura); la última 9.0.3 no hace falta', () => {
    const r = realCase('jsonwebtoken', '8.5.1');
    expect(r.recommended).toMatchObject({ version: '9.0.0', bump: 'major' });
    expect(r.safeWithoutMajor).toBe(false);
    expect(r.latest).toMatchObject({ version: '9.0.3', reason: 'not-needed' });
  });

  it('vite 5.4.2 → 6.4.4: ninguna 5.x es segura y la última 8.x se evita por major', () => {
    const r = realCase('vite', '5.4.2');
    expect(r.recommended).toMatchObject({ version: '6.4.4', bump: 'major' });
    expect(r.safeWithoutMajor).toBe(false);
    expect(r.latest).toMatchObject({ version: '8.3.5', reason: 'major-avoided' });
  });

  it('braces 3.0.2 → 3.0.3 (patch), que además es la última', () => {
    const r = realCase('braces', '3.0.2');
    expect(r.recommended).toMatchObject({ version: '3.0.3', bump: 'patch' });
    expect(r.latest!.reason).toBe('recommended');
  });

  it('esbuild 0.21.5 → 0.25.0 cuenta como major por estar en 0.x', () => {
    const r = realCase('esbuild', '0.21.5');
    expect(r.recommended).toMatchObject({ version: '0.25.0', bump: 'major' });
  });
});

describe('resolveMinSafeVersion · reglas', () => {
  const base = { installed: '1.0.0', severity: 'high' as const, quarantineDays: 7, now: FIXTURE_NOW };

  it('prefiere patch sobre minor y minor sobre major', () => {
    const packument = makePackument({
      '1.0.0': { ageDays: 300 },
      '1.0.1': { ageDays: 200 },
      '1.1.0': { ageDays: 100 },
      '2.0.0': { ageDays: 50 },
    });
    expect(resolveMinSafeVersion({ ...base, packument, advisories: [advisory('<1.0.1')] }).recommended).toMatchObject({ version: '1.0.1', bump: 'patch' });
    expect(resolveMinSafeVersion({ ...base, packument, advisories: [advisory('<1.1.0')] }).recommended).toMatchObject({ version: '1.1.0', bump: 'minor' });
    expect(resolveMinSafeVersion({ ...base, packument, advisories: [advisory('<2.0.0')] }).recommended).toMatchObject({ version: '2.0.0', bump: 'major' });
  });

  it('descarta prereleases, deprecated y versiones en cualquier rango vulnerable', () => {
    const packument = makePackument(
      {
        '1.0.0': { ageDays: 300 },
        '1.0.1-beta.1': { ageDays: 250 },
        '1.0.1': { ageDays: 200, deprecated: 'broken release' },
        '1.0.2': { ageDays: 150 },
        '1.0.3': { ageDays: 100 },
      },
      '1.0.3',
    );
    const r = resolveMinSafeVersion({ ...base, packument, advisories: [advisory('<1.0.1'), advisory('>=1.0.2 <1.0.3', 'moderate')] });
    expect(r.recommended!.version).toBe('1.0.3');
    expect(r.safeVersions).toEqual(['1.0.3']);
  });

  it('descarta las versiones excluidas por otra fuente (malware)', () => {
    const packument = makePackument({ '1.0.0': { ageDays: 300 }, '1.0.1': { ageDays: 200 }, '1.0.2': { ageDays: 100 } });
    const r = resolveMinSafeVersion({ ...base, packument, advisories: [advisory('<1.0.1')], excluded: new Set(['1.0.1']) });
    expect(r.recommended!.version).toBe('1.0.2');
  });

  it('si solo hay versiones seguras en cuarentena, espera y dice hasta cuándo', () => {
    const packument = makePackument({ '1.0.0': { ageDays: 300 }, '1.0.1': { ageDays: 2 } });
    const r = resolveMinSafeVersion({ ...base, packument, advisories: [advisory('<1.0.1')] });
    expect(r.status).toBe('quarantine-only');
    expect(r.recommended).toBeUndefined();
    // Publicada hace 2 días: le quedan 5 de cuarentena.
    expect(r.waitingFor).toMatchObject({ version: '1.0.1', waitUntil: '2026-11-04T12:00:00.000Z' });
    expect(r.latest!.reason).toBe('quarantine');
  });

  it('con una vulnerabilidad crítica, recomienda aunque esté en cuarentena', () => {
    const packument = makePackument({ '1.0.0': { ageDays: 300 }, '1.0.1': { ageDays: 2 } });
    const r = resolveMinSafeVersion({ ...base, severity: 'critical', packument, advisories: [advisory('<1.0.1', 'critical')] });
    expect(r.status).toBe('ok');
    expect(r.recommended).toMatchObject({ version: '1.0.1', inQuarantine: true });
    expect(r.quarantineBypassed).toBe(true);
  });

  it('con crítica, si hay una segura fuera de cuarentena, sigue eligiendo la mínima', () => {
    const packument = makePackument({ '1.0.0': { ageDays: 300 }, '1.0.1': { ageDays: 30 }, '1.0.2': { ageDays: 1 } });
    const r = resolveMinSafeVersion({ ...base, severity: 'critical', packument, advisories: [advisory('<1.0.1', 'critical')] });
    expect(r.recommended!.version).toBe('1.0.1');
    expect(r.quarantineBypassed).toBe(false);
  });

  it('informa cuando no hay ninguna versión segura publicada', () => {
    const packument = makePackument({ '1.0.0': { ageDays: 300 }, '1.0.1': { ageDays: 200 } });
    const r = resolveMinSafeVersion({ ...base, packument, advisories: [advisory('*')] });
    expect(r.status).toBe('no-safe-version');
    expect(r.recommended).toBeUndefined();
    expect(r.latest!.reason).toBe('vulnerable');
  });

  it('nunca recomienda una versión igual o menor a la instalada', () => {
    const packument = makePackument({ '0.9.0': { ageDays: 400 }, '1.0.0': { ageDays: 300 } }, '1.0.0');
    const r = resolveMinSafeVersion({ ...base, packument, advisories: [advisory('>=1.0.0 <1.0.1')] });
    expect(r.status).toBe('no-safe-version');
    expect(r.latest!.reason).toBe('not-newer');
  });
});
