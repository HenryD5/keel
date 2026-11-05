import { describe, expect, it } from 'vitest';
import { buildInstallPlan, lineDiff } from '../../src/core/apply/plan';
import { scan, type ScanDeps, type ScanResult } from '../../src/core/scan';
import { FIXTURE_NOW, fixtureText, packumentFixture } from './helpers';

function deps(): ScanDeps {
  return {
    runAudit: async () => fixtureText('audit/sample.json'),
    readLockfile: async () => fixtureText('lockfile/sample-v3.json'),
    readManifest: async () => fixtureText('lockfile/sample-package.json'),
    getPackument: async (name) => packumentFixture(name),
    now: FIXTURE_NOW,
    quarantineDays: 7,
    nodeVersion: 'v20.18.0',
  };
}

describe('plan de instalación', () => {
  it('edita directas y crea overrides con el escaneo real', async () => {
    const result = await scan(deps());
    const manifestText = fixtureText('lockfile/sample-package.json');
    const plan = buildInstallPlan({
      result,
      manifestText,
      selected: ['axios', 'jsonwebtoken', 'vite', 'braces', 'esbuild'],
      choices: {},
      exact: false,
    });

    expect(plan.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'axios', from: '1.18.0', to: '1.20.0', newSpec: '^1.20.0', kind: 'direct' }),
        expect.objectContaining({ name: 'jsonwebtoken', to: '9.0.0', bump: 'major', newSpec: '^9.0.0' }),
        expect.objectContaining({ name: 'vite', to: '6.4.4', newSpec: '~6.4.4' }),
        expect.objectContaining({ name: 'braces', to: '3.0.3', newSpec: '3.0.3', kind: 'override' }),
        expect.objectContaining({ name: 'esbuild', newSpec: expect.stringMatching(/^\d+\.\d+\.\d+$/), kind: 'override' }),
      ]),
    );
    const parsed = JSON.parse(plan.newManifestText);
    expect(parsed.overrides).toMatchObject({ braces: '3.0.3', esbuild: expect.any(String) });
    expect(plan.newManifestText.endsWith('\n')).toBe(true);
  });

  it('quita operadores al fijar versiones exactas', async () => {
    const result = await scan(deps());
    const plan = buildInstallPlan({
      result,
      manifestText: fixtureText('lockfile/sample-package.json'),
      selected: ['axios', 'vite'],
      choices: {},
      exact: true,
    });
    expect(JSON.parse(plan.newManifestText)).toMatchObject({ dependencies: { axios: '1.20.0' }, devDependencies: { vite: '6.4.4' } });
  });

  it('permite elegir latest cuando es segura', async () => {
    const result = await scan(deps());
    const vite = result.packages.find((pkg) => pkg.name === 'vite')!;
    expect(['not-needed', 'major-avoided']).toContain(vite.resolution!.latest!.reason);
    const plan = buildInstallPlan({
      result,
      manifestText: fixtureText('lockfile/sample-package.json'),
      selected: ['vite'],
      choices: { vite: 'latest' },
      exact: false,
    });
    expect(plan.changes[0]!.to).toBe(vite.resolution!.latest!.version);
  });

  it('con la elección line instala la mejor versión sin salto major', async () => {
    const result = await scan(deps());
    const vite = result.packages.find((pkg) => pkg.name === 'vite')!;
    expect(vite.resolution!.recommended!.bump).toBe('major');
    const best = vite.resolution!.bestInLine!;
    expect(best.remainingIds.length).toBeLessThan(vite.advisories.length);
    const plan = buildInstallPlan({ result, manifestText: fixtureText('lockfile/sample-package.json'), selected: ['vite'], choices: { vite: 'line' }, exact: true });
    expect(plan.changes[0]).toMatchObject({ name: 'vite', to: best.version });
    expect(plan.changes[0]!.bump).not.toBe('major');
  });

  it('omite paquetes sin recomendación y no cambia una selección vacía', async () => {
    const result = await scan(deps());
    result.packages[0] = { ...result.packages[0]!, resolution: undefined, error: 'timeout' };
    const manifestText = fixtureText('lockfile/sample-package.json');
    expect(
      buildInstallPlan({ result, manifestText, selected: [result.packages[0]!.name], choices: {}, exact: false }).skipped,
    ).toEqual([{ name: result.packages[0]!.name, reason: 'error' }]);
    expect(buildInstallPlan({ result, manifestText, selected: [], choices: {}, exact: false })).toMatchObject({
      changes: [],
      newManifestText: manifestText,
      diff: [],
      skipped: [],
    });
  });
});

describe('formato del manifiesto', () => {
  const resultFor = (name: string, direct = true): ScanResult => ({
    scannedAt: FIXTURE_NOW.toISOString(),
    totals: { total: 1, info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
    inheritedOnly: [],
    packages: [
      {
        name,
        installed: '1.0.0',
        installedVersions: ['1.0.0'],
        direct,
        depType: direct ? 'prod' : undefined,
        declaredRange: direct ? '^1.0.0' : undefined,
        parents: [],
        viaTopLevel: [],
        severity: 'high',
        advisories: [],
        counts: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
        auditFix: { kind: 'force' },
        resolution: {
          status: 'ok',
          recommended: { version: '1.2.0', bump: 'minor', inQuarantine: false },
          quarantineBypassed: false,
          safeWithoutMajor: true,
          safeVersions: ['1.2.0'],
        },
      },
    ],
  });

  it.each([
    ['tabs', '{\n\t"dependencies": {\n\t\t"pkg": "^1.0.0"\n\t}\n}', '{\n\t"dependencies": {\n\t\t"pkg": "^1.2.0"\n\t}\n}'],
    ['cuatro espacios', '{\n    "dependencies": {\n        "pkg": "^1.0.0"\n    }\n}\n', '{\n    "dependencies": {\n        "pkg": "^1.2.0"\n    }\n}\n'],
    ['CRLF', '{\r\n  "dependencies": {\r\n    "pkg": "^1.0.0"\r\n  }\r\n}\r\n', '{\r\n  "dependencies": {\r\n    "pkg": "^1.2.0"\r\n  }\r\n}\r\n'],
  ])('conserva %s y el salto final', (_label, before, expected) => {
    const plan = buildInstallPlan({ result: resultFor('pkg'), manifestText: before, selected: ['pkg'], choices: {}, exact: false });
    expect(plan.newManifestText).toBe(expected);
  });

  it('actualiza un override existente sin mover claves', () => {
    const before = '{\n  "name": "demo",\n  "overrides": {\n    "pkg": "1.1.0",\n    "other": "2.0.0"\n  },\n  "private": true\n}';
    const expected = '{\n  "name": "demo",\n  "overrides": {\n    "pkg": "1.2.0",\n    "other": "2.0.0"\n  },\n  "private": true\n}';
    const plan = buildInstallPlan({ result: resultFor('pkg', false), manifestText: before, selected: ['pkg'], choices: {}, exact: false });
    expect(plan.newManifestText).toBe(expected);
    expect(plan.changes[0]!.oldSpec).toBe('1.1.0');
  });
});

describe('diff por líneas', () => {
  it('incluye altas, bajas, contexto y separador', () => {
    const diff = lineDiff('a\nb\nc\nd\ne\nf\ng\n', 'a\nB\nc\nd\ne\nF\ng\n');
    expect(diff).toContainEqual({ kind: 'del', text: 'b' });
    expect(diff).toContainEqual({ kind: 'add', text: 'B' });
    expect(diff).toContainEqual({ kind: 'context', text: 'a' });
    expect(diff).toContainEqual({ kind: 'context', text: '…' });
  });
});
