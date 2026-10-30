import { describe, expect, it } from 'vitest';
import { compareManifests } from '../../src/core/resolver/manifestDiff';
import { packumentFixture } from './helpers';

describe('compareManifests', () => {
  it('marca scripts de instalación nuevos', () => {
    const r = compareManifests(
      { name: 'x', version: '1.0.0', scripts: { test: 'vitest' } },
      { name: 'x', version: '1.0.1', scripts: { postinstall: 'node setup.js', preinstall: 'node pre.js' } },
      () => undefined,
    );
    expect(r.newInstallScripts).toEqual(['preinstall', 'postinstall']);
  });

  it('no marca scripts que la versión actual ya tenía (esbuild postinstall)', () => {
    const esbuild = packumentFixture('esbuild');
    const r = compareManifests(esbuild.versions['0.21.5'], esbuild.versions['0.25.0']!, () => undefined);
    expect(r.newInstallScripts).toEqual([]);
  });

  it('sin manifiesto de la versión actual, todo script de instalación cuenta como nuevo', () => {
    const r = compareManifests(undefined, { name: 'x', version: '2.0.0', scripts: { install: 'node-gyp rebuild' } }, () => undefined);
    expect(r.newInstallScripts).toEqual(['install']);
  });

  it('jsonwebtoken 9.0.0 sube engines.node de >=4 a >=12, y Node 20 lo cumple', () => {
    const jwt = packumentFixture('jsonwebtoken');
    const r = compareManifests(jwt.versions['8.5.1'], jwt.versions['9.0.0']!, () => undefined, 'v20.18.0');
    expect(r.engines).toEqual({ from: '>=4', to: '>=12', satisfiesProjectNode: true });
    expect(r.peerChanges).toEqual([]);
  });

  it('vite 6.4.4: detecta peers nuevos y comprueba los instalados', () => {
    const vite = packumentFixture('vite');
    const installed: Record<string, string> = { terser: '5.10.0', '@types/node': '20.11.0' };
    const r = compareManifests(vite.versions['5.4.2'], vite.versions['6.4.4']!, (n) => installed[n], 'v16.20.0');
    expect(r.peerChanges.map((p) => p.name)).toEqual(expect.arrayContaining(['jiti', 'tsx', 'yaml', 'terser', '@types/node']));
    expect(r.peers.find((p) => p.name === 'terser')).toMatchObject({ range: '^5.16.0', installed: '5.10.0', satisfied: false });
    expect(r.peers.find((p) => p.name === '@types/node')).toMatchObject({ satisfied: true });
    expect(r.peers.find((p) => p.name === 'less')).toMatchObject({ installed: undefined, satisfied: undefined });
    expect(r.engines.satisfiesProjectNode).toBe(false);
  });
});
