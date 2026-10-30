import { beforeAll, describe, expect, it } from 'vitest';
import { manifestFindings } from '../../src/core/editor/manifestFindings';
import { scan, type ScanResult } from '../../src/core/scan';
import { FIXTURE_NOW, fixtureText, packumentFixture } from './helpers';

let result: ScanResult;
const manifest = fixtureText('lockfile/sample-package.json');

beforeAll(async () => {
  result = await scan({
    runAudit: async () => fixtureText('audit/sample.json'),
    readLockfile: async () => fixtureText('lockfile/sample-v3.json'),
    readManifest: async () => manifest,
    getPackument: async (name) => packumentFixture(name),
    now: FIXTURE_NOW,
    quarantineDays: 7,
    nodeVersion: 'v20.18.0',
  });
});

describe('manifestFindings', () => {
  it('localiza exactamente dependencias y devDependencies', () => {
    const findings = manifestFindings(manifest, result);
    expect(findings.map(({ name, line, startCharacter, endCharacter, offset, length }) => ({ name, line, startCharacter, endCharacter, offset, length }))).toEqual([
      { name: 'axios', line: 5, startCharacter: 5, endCharacter: 10, offset: 93, length: 5 },
      { name: 'jsonwebtoken', line: 6, startCharacter: 5, endCharacter: 17, offset: 117, length: 12 },
      { name: 'chokidar', line: 7, startCharacter: 5, endCharacter: 13, offset: 147, length: 8 },
      { name: 'vite', line: 10, startCharacter: 5, endCharacter: 9, offset: 200, length: 4 },
    ]);
    expect(findings.find((item) => item.name === 'vite')!.pkg.map((pkg) => pkg.name)).toEqual(['vite', 'esbuild']);
  });

  it('asocia transitivas a la dependencia directa y conserva via', () => {
    const findings = manifestFindings(manifest, result);
    expect(findings.find((item) => item.name === 'chokidar')).toMatchObject({ severity: 'high', via: ['braces'] });
    expect(findings.find((item) => item.name === 'vite')).toMatchObject({ severity: 'high', via: ['esbuild'] });
  });

  it('agrupa por clave y usa la severidad máxima', () => {
    const vite = result.packages.find((pkg) => pkg.name === 'vite')!;
    const esbuild = result.packages.find((pkg) => pkg.name === 'esbuild')!;
    const findings = manifestFindings(manifest, {
      ...result,
      packages: [{ ...vite, severity: 'moderate' }, { ...esbuild, severity: 'critical' }],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ name: 'vite', severity: 'critical', via: ['esbuild'] });
    expect(findings[0]!.pkg.map((pkg) => pkg.name)).toEqual(['vite', 'esbuild']);
  });

  it('omite una dependencia que no está en el manifiesto', () => {
    const axios = result.packages.find((pkg) => pkg.name === 'axios')!;
    expect(manifestFindings(manifest, { ...result, packages: [{ ...axios, name: 'missing' }] })).toEqual([]);
  });
});
