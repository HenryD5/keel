import { describe, expect, it } from 'vitest';
import { AuditError } from '../../src/core/audit/parseAudit';
import { formatScanReport } from '../../src/core/report';
import { scan, type ScanDeps } from '../../src/core/scan';
import { FIXTURE_NOW, fixtureText, packumentFixture } from './helpers';

function deps(overrides: Partial<ScanDeps> = {}): ScanDeps {
  return {
    runAudit: async () => fixtureText('audit/sample.json'),
    readLockfile: async () => fixtureText('lockfile/sample-v3.json'),
    readManifest: async () => fixtureText('lockfile/sample-package.json'),
    getPackument: async (name) => packumentFixture(name),
    now: FIXTURE_NOW,
    quarantineDays: 7,
    nodeVersion: 'v20.18.0',
    ...overrides,
  };
}

describe('scan (fixtures reales)', () => {
  it('arma un reporte por paquete con advisories propios', async () => {
    const result = await scan(deps());
    expect(result.projectName).toBe('keel-sample');
    expect(result.packages.map((p) => p.name)).toEqual(['axios', 'braces', 'jsonwebtoken', 'vite', 'esbuild']);
    expect(result.inheritedOnly).toEqual([]);
  });

  it('axios: directa, 1.18.0 → 1.20.0, audit fix ✓ pero npm elegiría 1.21.0 en cuarentena', async () => {
    const axios = (await scan(deps())).packages.find((p) => p.name === 'axios')!;
    expect(axios).toMatchObject({ installed: '1.18.0', direct: true, depType: 'prod', declaredRange: '^1.18.0' });
    expect(axios.resolution!.recommended!.version).toBe('1.20.0');
    expect(axios.auditFix).toEqual({ kind: 'audit-fix', version: '1.21.0' });
    expect(axios.checks!.newInstallScripts).toEqual([]);
  });

  it('jsonwebtoken: major 9.0.0 y npm pediría --force', async () => {
    const jwt = (await scan(deps())).packages.find((p) => p.name === 'jsonwebtoken')!;
    expect(jwt.resolution!.recommended).toMatchObject({ version: '9.0.0', bump: 'major' });
    expect(jwt.auditFix.kind).toBe('force');
    expect(jwt.checks!.engines).toMatchObject({ to: '>=12', satisfiesProjectNode: true });
  });

  it('transitivas: braces vía chokidar (audit fix ✓) y esbuild vía vite (--force)', async () => {
    const result = await scan(deps());
    const braces = result.packages.find((p) => p.name === 'braces')!;
    expect(braces).toMatchObject({ direct: false, viaTopLevel: ['chokidar'] });
    expect(braces.parents.map((p) => [p.name, p.range])).toEqual([['chokidar', '~3.0.2']]);
    expect(braces.auditFix).toEqual({ kind: 'audit-fix', version: '3.0.3' });

    const esbuild = result.packages.find((p) => p.name === 'esbuild')!;
    expect(esbuild).toMatchObject({ direct: false, viaTopLevel: ['vite'] });
    expect(esbuild.auditFix.kind).toBe('force');
  });

  it('un fallo del registro afecta solo a ese paquete', async () => {
    const result = await scan(
      deps({
        getPackument: async (name) => {
          if (name === 'vite') throw new Error('timeout');
          return packumentFixture(name);
        },
      }),
    );
    const vite = result.packages.find((p) => p.name === 'vite')!;
    expect(vite.error).toMatch(/timeout/);
    expect(vite.resolution).toBeUndefined();
    expect(result.packages.find((p) => p.name === 'axios')!.resolution).toBeDefined();
  });

  it('propaga el error de npm audit', async () => {
    await expect(scan(deps({ runAudit: async () => fixtureText('audit/error-enolock.json') }))).rejects.toBeInstanceOf(AuditError);
  });

  it('el resumen de texto incluye recomendación, cuarentena y --force', async () => {
    const text = formatScanReport(await scan(deps()), 7);
    expect(text).toContain('1.18.0 → 1.20.0  [Minor · Revisar]');
    expect(text).toContain('Última: 1.21.0, publicada hace 3 días · en cuarentena');
    expect(text).toContain('8.5.1 → 9.0.0  [Major · Puede romper]');
    expect(text).toContain('npm pediría --force');
    expect(text).toContain('transitiva · vía chokidar');
  });
});
