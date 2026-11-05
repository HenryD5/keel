import { describe, expect, it } from 'vitest';
import { OsvReference, type OsvVuln } from '../../src/core/reference/osv';
import type { SecondReference } from '../../src/core/reference/types';
import { scan, type ScanDeps } from '../../src/core/scan';
import { FIXTURE_NOW, fixtureText, packumentFixture } from './helpers';

const osv = (name: string) => JSON.parse(fixtureText(`osv/${name}.json`)) as { vulns: OsvVuln[] };

function base(overrides: Partial<ScanDeps> = {}): ScanDeps {
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

function realOsv(): OsvReference {
  return new OsvReference(async (_url, body) => osv((body as { package: { name: string } }).package.name), async (name) => Object.keys(packumentFixture(name).versions));
}

describe('scan con referencia', () => {
  it('añade a cada aviso su CVE según los alias de OSV', async () => {
    const braces = (await scan(base({ reference: realOsv() }))).packages.find((p) => p.name === 'braces')!;
    expect(braces.advisories[0]).toMatchObject({ url: expect.stringContaining('GHSA-grv7-fg5c-xmjg'), cves: ['CVE-2024-4068'] });
  });

  it('OSV concuerda con axios 1.20.0', async () => {
    const axios = (await scan(base({ reference: realOsv() }))).packages.find((p) => p.name === 'axios')!;
    expect(axios.reference).toMatchObject({ source: 'osv', version: '1.20.0', agrees: true, issues: [] });
  });

  it('detecta el desacuerdo real de Vite 6.4.4', async () => {
    const vite = (await scan(base({ reference: realOsv() }))).packages.find((p) => p.name === 'vite')!;
    expect(vite.resolution?.recommended?.version).toBe('6.4.4');
    expect(vite.reference).toMatchObject({ version: '6.4.4', agrees: false });
    expect(vite.reference?.issues).toContainEqual(expect.objectContaining({ id: 'GHSA-8g5g-mxqh-grgj', severity: 'moderate' }));
  });

  it('un fallo de OSV queda en reference.error sin romper la recomendación', async () => {
    const ref = new OsvReference(async () => { throw new Error('OSV timeout'); }, async () => []);
    const axios = (await scan(base({ reference: ref }))).packages.find((p) => p.name === 'axios')!;
    expect(axios.resolution?.recommended?.version).toBe('1.20.0');
    expect(axios.reference?.error).toBe('OSV timeout');
  });

  it('descarta una candidata maliciosa y recalcula', async () => {
    const ref: SecondReference = {
      source: 'osv',
      excludedVersions: async () => new Set(),
      issuesFor: async (name, version) => name === 'jsonwebtoken' && version === '9.0.0' ? [{ id: 'MAL-X', title: 'malware', malicious: true }] : [],
    };
    const jwt = (await scan(base({ reference: ref }))).packages.find((p) => p.name === 'jsonwebtoken')!;
    expect(jwt.resolution?.recommended?.version).not.toBe('9.0.0');
    expect(jwt.reference?.maliciousVersions).toContain('9.0.0');
    expect(jwt.reference?.agrees).toBe(true);
  });

  it('arma la tabla de versiones de jsonwebtoken', async () => {
    const jwt = (await scan(base({ reference: realOsv() }))).packages.find((p) => p.name === 'jsonwebtoken')!;
    const byVersion = Object.fromEntries(jwt.versionTable!.map((row) => [row.version, row]));
    expect(byVersion['9.0.3']).toMatchObject({ roles: expect.arrayContaining(['latest']) });
    expect(byVersion['9.0.0']).toMatchObject({ roles: expect.arrayContaining(['recommended']) });
    expect(byVersion['8.5.1']).toMatchObject({ roles: expect.arrayContaining(['installed']) });
    expect(byVersion['8.5.1']!.counts.high).toBeGreaterThan(0);
  });
});
